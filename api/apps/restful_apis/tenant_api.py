#
#  Copyright 2026 The InfiniFlow Authors. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
import asyncio
import logging
from typing import Set

from api.apps import current_user, login_required
from api.db import UserTenantRole
from api.db.db_models import UserTenant, Tenant
from api.db.services.user_service import UserService, UserTenantService, TenantService
from api.utils.api_utils import (
    get_data_error_result,
    get_json_result,
    get_request_json,
    server_error_response,
    validate_request,
)
from api.utils.permission import is_superadmin, is_team_admin
from api.utils.web_utils import send_invite_email
from common import settings
from common.constants import RetCode, StatusEnum
from common.misc_utils import get_uuid
from common.time_utils import delta_seconds

# Keeps strong references to fire-and-forget tasks so they are not GC'd before completion.
_background_tasks: Set[asyncio.Task] = set()


# ---------------------------------------------------------------------------
# Team (Tenant) CRUD – superadmin only for create/delete, teamadmin for update
# ---------------------------------------------------------------------------


@manager.route("/tenants", methods=["POST"])  # noqa: F821
@login_required
async def create_tenant():
    """Create a new team (tenant).  Only superadmin can create teams."""
    if not is_superadmin(current_user.id):
        return get_json_result(
            data=False,
            message="Only superadmin can create teams.",
            code=RetCode.PERMISSION_ERROR,
        )

    req = await get_request_json()
    name = (req.get("name") or "").strip()
    if not name:
        return get_data_error_result(message="Team name is required.")

    tenant_id = get_uuid()
    TenantService.insert(
        id=tenant_id,
        name=name,
        llm_id=settings.CHAT_MDL,
        embd_id=settings.EMBEDDING_MDL,
        asr_id=settings.ASR_MDL,
        parser_ids=settings.PARSERS,
        img2txt_id=settings.IMAGE2TEXT_MDL,
        rerank_id=settings.RERANK_MDL,
    )

    # If a teamadmin email is provided, assign the ADMIN role immediately
    admin_email = (req.get("admin_email") or "").strip()
    if admin_email:
        admin_users = UserService.query(email=admin_email)
        if not admin_users:
            return get_data_error_result(message=f"Admin user {admin_email} not found.")
        admin_user_id = admin_users[0].id
        UserTenantService.save(
            id=get_uuid(),
            user_id=admin_user_id,
            tenant_id=tenant_id,
            invited_by=current_user.id,
            role=UserTenantRole.ADMIN,
            status=StatusEnum.VALID.value,
        )

    # Superadmin is also added as OWNER so they appear in the team member list
    UserTenantService.save(
        id=get_uuid(),
        user_id=current_user.id,
        tenant_id=tenant_id,
        invited_by=current_user.id,
        role=UserTenantRole.OWNER,
        status=StatusEnum.VALID.value,
    )

    ok, tenant = TenantService.get_by_id(tenant_id)
    if not ok:
        return get_data_error_result(message="Failed to retrieve created team.")
    return get_json_result(data=tenant.to_dict())


@manager.route("/tenants", methods=["GET"])  # noqa: F821
@login_required
def tenant_list():
    """List teams visible to the current user.

    - superadmin sees ALL teams
    - other users see only teams they belong to
    """
    try:
        if is_superadmin(current_user.id):
            tenants = list(Tenant.select().where(Tenant.status == StatusEnum.VALID.value).dicts())
            for t in tenants:
                t["tenant_id"] = t.pop("id")
                t["delta_seconds"] = delta_seconds(str(t.get("update_date", "")))
                # Enrich with the user's role in this team
                ut = UserTenantService.filter_by_tenant_and_user_id(t["tenant_id"], current_user.id)
                t["role"] = ut.role if ut else "superadmin"
            return get_json_result(data=tenants)

        users = UserTenantService.get_tenants_by_user_id(current_user.id)
        for user in users:
            user["delta_seconds"] = delta_seconds(str(user["update_date"]))
        return get_json_result(data=users)
    except Exception as exc:
        return server_error_response(exc)


@manager.route("/tenants/<tenant_id>", methods=["GET"])  # noqa: F821
@login_required
def get_tenant(tenant_id):
    """Get a single team's detail.  Any team member can view."""
    try:
        ok, tenant = TenantService.get_by_id(tenant_id)
        if not ok:
            return get_data_error_result(message="Team not found.")
        data = tenant.to_dict()
        ut = UserTenantService.filter_by_tenant_and_user_id(tenant_id, current_user.id)
        data["role"] = ut.role if ut else ("superadmin" if is_superadmin(current_user.id) else None)
        return get_json_result(data=data)
    except Exception as exc:
        return server_error_response(exc)


@manager.route("/tenants/<tenant_id>", methods=["PATCH"])  # noqa: F821
@login_required
async def agree(tenant_id):
    """Accept an invitation – upgrades INVITE role to NORMAL (teammember)."""
    try:
        UserTenantService.filter_update(
            [UserTenant.tenant_id == tenant_id, UserTenant.user_id == current_user.id],
            {"role": UserTenantRole.NORMAL},
        )
        return get_json_result(data=True)
    except Exception as exc:
        return server_error_response(exc)


@manager.route("/tenants/<tenant_id>", methods=["PUT"])  # noqa: F821
@login_required
async def update_tenant(tenant_id):
    """Update team info (name, etc.).  Requires teamadmin+."""
    if not is_team_admin(current_user.id, tenant_id):
        return get_json_result(
            data=False,
            message="Team admin or higher role required.",
            code=RetCode.PERMISSION_ERROR,
        )

    req = await get_request_json()
    allowed_fields = {"name"}
    update_dict = {k: v for k, v in req.items() if k in allowed_fields}
    if not update_dict:
        return get_data_error_result(message="No valid fields to update.")

    try:
        TenantService.update_by_id(tenant_id, update_dict)
        ok, tenant = TenantService.get_by_id(tenant_id)
        if not ok:
            return get_data_error_result(message="Team not found.")
        return get_json_result(data=tenant.to_dict())
    except Exception as exc:
        return server_error_response(exc)


@manager.route("/tenants/<tenant_id>", methods=["DELETE"])  # noqa: F821
@login_required
async def delete_tenant(tenant_id):
    """Delete a team.  Only superadmin can delete teams."""
    if not is_superadmin(current_user.id):
        return get_json_result(
            data=False,
            message="Only superadmin can delete teams.",
            code=RetCode.PERMISSION_ERROR,
        )

    try:
        TenantService.update_by_id(tenant_id, {"status": StatusEnum.INVALID.value})
        return get_json_result(data=True)
    except Exception as exc:
        return server_error_response(exc)


# ---------------------------------------------------------------------------
# Team member management
# ---------------------------------------------------------------------------


@manager.route("/tenants/<tenant_id>/users", methods=["GET"])  # noqa: F821
@login_required
def user_list(tenant_id):
    """List members of a team.  Any team member can view."""
    from api.utils.permission import is_team_member
    if not is_team_member(current_user.id, tenant_id):
        return get_json_result(
            data=False,
            message="No authorization.",
            code=RetCode.AUTHENTICATION_ERROR,
        )

    try:
        users = UserTenantService.get_by_tenant_id(tenant_id)
        for user in users:
            user["delta_seconds"] = delta_seconds(str(user["update_date"]))
        return get_json_result(data=users)
    except Exception as exc:
        return server_error_response(exc)


@manager.route("/tenants/<tenant_id>/users", methods=["POST"])  # noqa: F821
@login_required
@validate_request("email")
async def create(tenant_id):
    """Invite a user to the team.  Requires teamadmin+."""
    if not is_team_admin(current_user.id, tenant_id):
        return get_json_result(
            data=False,
            message="Team admin or higher role required to invite users.",
            code=RetCode.PERMISSION_ERROR,
        )

    req = await get_request_json()
    invite_user_email = req["email"]
    invite_users = UserService.query(email=invite_user_email)
    if not invite_users:
        return get_data_error_result(message="User not found.")

    user_id_to_invite = invite_users[0].id
    user_tenants = UserTenantService.query(user_id=user_id_to_invite, tenant_id=tenant_id)
    if user_tenants:
        user_tenant_role = user_tenants[0].role
        if user_tenant_role == UserTenantRole.NORMAL:
            return get_data_error_result(message=f"{invite_user_email} is already in the team.")
        if user_tenant_role == UserTenantRole.OWNER:
            return get_data_error_result(message=f"{invite_user_email} is the owner of the team.")
        if user_tenant_role == UserTenantRole.ADMIN:
            return get_data_error_result(message=f"{invite_user_email} is already a team admin.")
        return get_data_error_result(
            message=f"{invite_user_email} is in the team, but the role: {user_tenant_role} is invalid."
        )

    UserTenantService.save(
        id=get_uuid(),
        user_id=user_id_to_invite,
        tenant_id=tenant_id,
        invited_by=current_user.id,
        role=UserTenantRole.NORMAL,  # Directly add as teammember (skip invite flow)
        status=StatusEnum.VALID.value,
    )

    try:
        user_name = ""
        _, user = UserService.get_by_id(current_user.id)
        if user:
            user_name = user.nickname

        def _on_invite_email_done(done_task: asyncio.Task) -> None:
            _background_tasks.discard(done_task)
            try:
                done_task.result()
            except asyncio.CancelledError:
                logging.warning("Invite email task cancelled: tenant_id=%s to=%s", tenant_id, invite_user_email)
            except Exception:
                logging.exception("Invite email task failed: tenant_id=%s to=%s", tenant_id, invite_user_email)

        task = asyncio.create_task(
            send_invite_email(
                to_email=invite_user_email,
                invite_url=settings.MAIL_FRONTEND_URL,
                tenant_id=tenant_id,
                inviter=user_name or current_user.email,
            )
        )
        if isinstance(task, asyncio.Task):
            _background_tasks.add(task)
            task.add_done_callback(_on_invite_email_done)
    except Exception as exc:
        logging.exception(f"Failed to send invite email to {invite_user_email}: {exc}")
        return get_json_result(
            data=False,
            message="Failed to send invite email.",
            code=RetCode.SERVER_ERROR,
        )

    user = invite_users[0].to_dict()
    user = {k: v for k, v in user.items() if k in ["id", "avatar", "email", "nickname"]}
    return get_json_result(data=user)


@manager.route("/tenants/<tenant_id>/users", methods=["DELETE"])  # noqa: F821
@login_required
@validate_request("user_id")
async def rm(tenant_id):
    """Remove a user from the team.  Requires teamadmin+ (or self-removal)."""
    req = await get_request_json()
    user_id = req["user_id"]

    # Allow users to remove themselves, otherwise require team admin
    if current_user.id != user_id and not is_team_admin(current_user.id, tenant_id):
        return get_json_result(
            data=False,
            message="No authorization.",
            code=RetCode.AUTHENTICATION_ERROR,
        )

    # Cannot remove the OWNER
    ut = UserTenantService.filter_by_tenant_and_user_id(tenant_id, user_id)
    if ut and ut.role == UserTenantRole.OWNER:
        return get_json_result(
            data=False,
            message="Cannot remove the team owner.",
            code=RetCode.PERMISSION_ERROR,
        )

    try:
        UserTenantService.filter_delete([UserTenant.tenant_id == tenant_id, UserTenant.user_id == user_id])
        return get_json_result(data=True)
    except Exception as exc:
        return server_error_response(exc)


# ---------------------------------------------------------------------------
# Team admin management – superadmin assigns / revokes teamadmin role
# ---------------------------------------------------------------------------


@manager.route("/tenants/<tenant_id>/admins", methods=["POST"])  # noqa: F821
@login_required
@validate_request("user_id")
async def assign_team_admin(tenant_id):
    """Promote a team member to teamadmin.  Only superadmin can do this."""
    if not is_superadmin(current_user.id):
        return get_json_result(
            data=False,
            message="Only superadmin can assign team admin.",
            code=RetCode.PERMISSION_ERROR,
        )

    req = await get_request_json()
    target_user_id = req["user_id"]

    ut = UserTenantService.filter_by_tenant_and_user_id(tenant_id, target_user_id)
    if ut is None:
        return get_data_error_result(message="User is not a member of this team.")
    if ut.role == UserTenantRole.INVITE:
        return get_data_error_result(message="User has not accepted the invitation yet.")
    if ut.role == UserTenantRole.OWNER:
        return get_data_error_result(message="Cannot change the role of the team owner.")
    if ut.role == UserTenantRole.ADMIN:
        return get_data_error_result(message="User is already a team admin.")

    try:
        UserTenantService.filter_update(
            [UserTenant.tenant_id == tenant_id, UserTenant.user_id == target_user_id],
            {"role": UserTenantRole.ADMIN},
        )
        return get_json_result(data=True)
    except Exception as exc:
        return server_error_response(exc)


@manager.route("/tenants/<tenant_id>/admins", methods=["DELETE"])  # noqa: F821
@login_required
@validate_request("user_id")
async def revoke_team_admin(tenant_id):
    """Demote a teamadmin to regular teammember.  Only superadmin can do this."""
    if not is_superadmin(current_user.id):
        return get_json_result(
            data=False,
            message="Only superadmin can revoke team admin.",
            code=RetCode.PERMISSION_ERROR,
        )

    req = await get_request_json()
    target_user_id = req["user_id"]

    ut = UserTenantService.filter_by_tenant_and_user_id(tenant_id, target_user_id)
    if ut is None:
        return get_data_error_result(message="User is not a member of this team.")
    if ut.role != UserTenantRole.ADMIN:
        return get_data_error_result(message="User is not a team admin.")

    try:
        UserTenantService.filter_update(
            [UserTenant.tenant_id == tenant_id, UserTenant.user_id == target_user_id],
            {"role": UserTenantRole.NORMAL},
        )
        return get_json_result(data=True)
    except Exception as exc:
        return server_error_response(exc)
