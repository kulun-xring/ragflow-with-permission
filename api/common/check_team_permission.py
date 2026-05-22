#
#  Copyright 2025 The InfiniFlow Authors. All Rights Reserved.
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


from api.db import TenantPermission
from api.db.db_models import File, Knowledgebase, User
from api.db.services.file_service import FileService
from api.db.services.knowledgebase_service import KnowledgebaseService
from api.db.services.user_service import TenantService


def get_user_team_role(user_id: str, tenant_id: str) -> str:
    """
    Get the user's role in a specific team.

    Returns:
        'superadmin' : User.is_superadmin or User.is_superuser is True
        'teamadmin'  : UserTenant.role in ('admin', 'owner')
        'member'     : UserTenant.role == 'normal'
        'none'       : not a member of the team
    """
    # 1. SuperAdmin check (bypasses team membership)
    try:
        user = User.select(User.is_superuser, User.is_superadmin).where(User.id == user_id).first()
        if user and (getattr(user, 'is_superadmin', False) or user.is_superuser):
            return 'superadmin'
    except Exception:
        pass

    # 2. Team role check (uses get_user_teams_with_role — no role filter)
    teams = TenantService.get_user_teams_with_role(user_id)
    for team in teams:
        if team['tenant_id'] == tenant_id:
            role = team['role']
            if role in ('admin', 'owner'):
                return 'teamadmin'
            elif role == 'normal':
                return 'member'
            else:
                return 'none'  # 'invite' or other invalid roles

    return 'none'


def check_kb_team_permission(kb: dict | Knowledgebase, other: str) -> bool:
    """
    Check if user has read access to a knowledge base.

    Logic:
        1. KB owned by user (kb.tenant_id == other) -> allow
        2. KB permission is TEAM -> check user has any valid role in the team
        3. KB permission is ME -> deny
    """
    kb = kb.to_dict() if isinstance(kb, Knowledgebase) else kb
    kb_tenant_id = kb["tenant_id"]

    if kb_tenant_id == other:
        return True

    if kb["permission"] != TenantPermission.TEAM.value:
        return False

    role = get_user_team_role(other, kb_tenant_id)
    return role in ('superadmin', 'teamadmin', 'member')


def check_file_team_permission(file: dict | File, other: str) -> bool:
    """
    Check if user has read access to a file.

    Logic:
        1. File owned by user -> allow
        2. Check any KB containing this file is accessible
    """
    file = file.to_dict() if isinstance(file, File) else file

    file_tenant_id = file["tenant_id"]
    if file_tenant_id == other:
        return True

    file_id = file["id"]
    kb_ids = [kb_info["kb_id"] for kb_info in FileService.get_kb_id_by_file_id(file_id)]

    for kb_id in kb_ids:
        ok, kb = KnowledgebaseService.get_by_id(kb_id)
        if not ok:
            continue
        if check_kb_team_permission(kb, other):
            return True

    return False
