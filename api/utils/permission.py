#
#  Copyright 2024 The InfiniFlow Authors. All Rights Reserved.
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
"""Centralized permission checking utilities for team-based access control.

Role hierarchy (high → low):
  superadmin  – User.is_superuser=True, full access to ALL teams
  owner       – UserTenant.role=OWNER,  team creator with full access
  teamadmin   – UserTenant.role=ADMIN,  team administrator with full access
  teammember  – UserTenant.role=NORMAL, read-only access to team resources

INVITE role is treated as "no access" until the user accepts the invitation.
"""
import inspect
import logging
from functools import wraps

from quart import g, request

from api.apps import current_user
from api.db import UserTenantRole
from api.db.services.user_service import UserTenantService, UserService
from common.constants import RetCode
from api.utils.api_utils import get_json_result


# ---------------------------------------------------------------------------
# Core role-checking helpers
# ---------------------------------------------------------------------------

def is_superadmin(user_id: str) -> bool:
    """Return True if *user_id* is a super-admin."""
    return UserService.is_admin(user_id)


def get_user_role_in_team(user_id: str, tenant_id: str) -> str | None:
    """Return the user's effective role in the given team.

    Returns one of ``"superadmin"``, ``"owner"``, ``"admin"``, ``"normal"``,
    or ``None`` when the user has no access to the team.
    INVITE users are treated as having no access.
    """
    if is_superadmin(user_id):
        return "superadmin"
    ut = UserTenantService.filter_by_tenant_and_user_id(tenant_id, user_id)
    if ut is None:
        return None
    if ut.role == UserTenantRole.INVITE:
        return None
    return ut.role


def is_team_admin(user_id: str, tenant_id: str) -> bool:
    """Return True if the user has admin-level access (superadmin / owner / admin)."""
    role = get_user_role_in_team(user_id, tenant_id)
    return role in ("superadmin", UserTenantRole.OWNER, UserTenantRole.ADMIN)


def is_team_member(user_id: str, tenant_id: str) -> bool:
    """Return True if the user has any access to the team (including admin roles)."""
    return get_user_role_in_team(user_id, tenant_id) is not None


def get_user_accessible_tenant_ids(user_id: str) -> list[str]:
    """Return tenant_ids of all teams the user can access (excluding INVITE)."""
    relations = UserTenantService.get_user_tenant_relation_by_user_id(user_id)
    return [
        r["tenant_id"]
        for r in relations
        if r.get("role") not in (None, UserTenantRole.INVITE)
    ]


# ---------------------------------------------------------------------------
# Tenant resolution from request context
# ---------------------------------------------------------------------------

def resolve_tenant_id() -> tuple[str, str | None]:
    """Resolve the effective *tenant_id* for the current request.

    Strategy:
      1. If ``X-Tenant-Id`` header is present, validate the current user has
         access to that team and return it.
      2. Otherwise fall back to the user's first accessible team, preferring
         OWNER → ADMIN → NORMAL ordering.
      3. Legacy fallback: return ``current_user.id`` (backward compat for
         single-tenant deployments).

    Returns ``(tenant_id, error_message)``.  When *error_message* is not None
    the caller should reject the request.
    """
    user_id = current_user.id
    header_tenant_id = request.headers.get("X-Tenant-Id")

    if header_tenant_id:
        if is_team_member(user_id, header_tenant_id):
            return header_tenant_id, None
        return header_tenant_id, "No permission to access this team."

    # No header – resolve from user's memberships
    relations = UserTenantService.get_user_tenant_relation_by_user_id(user_id)
    # Prefer OWNER, then ADMIN, then NORMAL
    for preferred_role in (UserTenantRole.OWNER, UserTenantRole.ADMIN, UserTenantRole.NORMAL):
        for r in relations:
            if r.get("role") == preferred_role:
                return r["tenant_id"], None
    # Any remaining relation
    for r in relations:
        if r.get("role") not in (None, UserTenantRole.INVITE):
            return r["tenant_id"], None

    # Legacy fallback – single-tenant mode
    # Superadmin without memberships: try user_id (personal kingdom)
    if is_superadmin(user_id):
        return user_id, None
    return user_id, None


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def team_admin_required(func):
    """Decorator: require team-admin-or-higher permission for write operations.

    **Must** be placed *below* ``add_tenant_id_to_kwargs`` so that
    ``tenant_id`` is already resolved in ``kwargs``.

    Example::

        @manager.route("/datasets", methods=["POST"])
        @login_required
        @add_tenant_id_to_kwargs
        @team_admin_required
        async def create(tenant_id):
            ...
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        tenant_id = kwargs.get("tenant_id")
        if not tenant_id:
            return get_json_result(
                data=False,
                message="Tenant ID not resolved.",
                code=RetCode.PERMISSION_ERROR,
            )
        if not is_team_admin(current_user.id, tenant_id):
            return get_json_result(
                data=False,
                message="Write permission denied. Team admin or higher role required.",
                code=RetCode.PERMISSION_ERROR,
            )
        if inspect.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        return func(*args, **kwargs)

    return wrapper
