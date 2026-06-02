# Team-Based Permission System - Change Summary

## Overview

Implemented a three-tier permission model:
- **superadmin** (`User.is_superuser=True`): Full access to ALL teams, can create/delete teams, assign teamadmin
- **teamadmin** (`UserTenant.role=ADMIN`): Full management within their team (create/update/delete resources)
- **teammember** (`UserTenant.role=NORMAL`): Read-only access to team resources

## New Files

### `api/utils/permission.py`
Central permission checking utilities:
- `is_superadmin(user_id)` - Check superadmin status
- `get_user_role_in_team(user_id, tenant_id)` - Get effective role in a team
- `is_team_admin(user_id, tenant_id)` - Check admin-level access
- `is_team_member(user_id, tenant_id)` - Check any team membership
- `get_user_accessible_tenant_ids(user_id)` - List all accessible team IDs
- `resolve_tenant_id()` - Resolve active team from `X-Tenant-Id` header or auto-detect
- `team_admin_required` decorator - Require team-admin+ for write operations

## Modified Files

### Database Models (`api/db/db_models.py`)
- Changed default `permission` from `"me"` to `"team"` for:
  - `Knowledgebase.permission`
  - `UserCanvas.permission`
  - `Memory.permissions`

### Init Data (`api/db/init_data.py`)
- `init_superuser()`: Generate independent `tenant_id` (no longer `user_id == tenant_id`)

### User Registration (`api/apps/restful_apis/user_api.py`)
- `user_register()`: Generate independent `tenant_id` for multi-team support
- `rollback_user_registration()`: Clean up all tenant associations
- `tenant_info()`: Use `resolve_tenant_id()` for active team resolution
- `set_tenant_info()`: Verify `is_team_admin()` before updating team settings

### Tenant API (`api/apps/restful_apis/tenant_api.py`)
**New endpoints:**
- `POST /tenants` - Create a new team (superadmin only)
- `GET /tenants/<tenant_id>` - Get team detail (any member)
- `PUT /tenants/<tenant_id>` - Update team info (teamadmin+)
- `DELETE /tenants/<tenant_id>` - Delete a team (superadmin only)
- `POST /tenants/<tenant_id>/admins` - Assign teamadmin (superadmin only)
- `DELETE /tenants/<tenant_id>/admins` - Revoke teamadmin (superadmin only)

**Modified endpoints:**
- `GET /tenants` - superadmin sees ALL teams; others see only their own
- `GET /tenants/<tenant_id>/users` - Any team member can view
- `POST /tenants/<tenant_id>/users` - Require teamadmin+ to invite
- `DELETE /tenants/<tenant_id>/users` - Allow self-removal or teamadmin+; cannot remove OWNER

### API Utils (`api/utils/api_utils.py`)
- `add_tenant_id_to_kwargs()`: Now resolves tenant_id from `X-Tenant-Id` header, validates access, falls back to auto-detect from UserTenant relations, then legacy `current_user.id`

### Dataset API (`api/apps/restful_apis/dataset_api.py`)
Added `@team_admin_required` to write operations:
- `POST /datasets` (create)
- `DELETE /datasets` (delete)
- `PUT /datasets/<id>` (update)
- `DELETE /datasets/<id>/tags` (delete tags)
- `PUT /datasets/<id>/tags` (rename tag)
- `POST /datasets/<id>/index` (run index)
- `DELETE /datasets/<id>/index` (delete index)
- `POST /datasets/<id>/embedding` (run embedding)
- `PUT /datasets/<id>/metadata/config` (update metadata)

### Chat API (`api/apps/restful_apis/chat_api.py`)
- Added `_ensure_accessible_chat()` - any team member can read
- Added `_ensure_admin_chat()` - teamadmin+ for write operations
- `POST /chats` - Added `@add_tenant_id_to_kwargs` + `@team_admin_required`
- `GET /chats/<id>` - Use `_ensure_accessible_chat` (any member)
- `PUT/PATCH/DELETE /chats/<id>` - Use `_ensure_admin_chat` (teamadmin+)
- Session endpoints - Use `_ensure_accessible_chat` (any member can use)
- `list_chats` - Use `get_user_accessible_tenant_ids`

### Agent API (`api/apps/restful_apis/agent_api.py`)
- Added `_require_canvas_admin_async()` decorator for teamadmin+ write access
- `POST /agents` - Added `@team_admin_required`
- `PUT /agents/<id>` - Use `_require_canvas_admin_async`
- `DELETE /agents/<id>` - Use `_require_canvas_admin_async`
- `list_agents` / `list_agent_tags` - Use `get_user_accessible_tenant_ids`

### Memory API (`api/apps/restful_apis/memory_api.py`)
Added `@add_tenant_id_to_kwargs` + `@team_admin_required` to:
- `POST /memories` (create)
- `PUT /memories/<id>` (update)
- `DELETE /memories/<id>` (delete)
- `GET /memories` (list) - Added `@add_tenant_id_to_kwargs`

### Chunk API (`api/apps/restful_apis/chunk_api.py`)
Added `@team_admin_required` to write operations:
- `POST /datasets/<id>/documents/<id>/chunks` (add chunk)
- `DELETE /datasets/<id>/documents/<id>/chunks` (remove chunk)
- `PATCH /datasets/<id>/documents/<id>/chunks/<id>` (update chunk)
- `PATCH /datasets/<id>/documents/<id>/chunks` (switch chunks)

### Document API (`api/apps/restful_apis/document_api.py`)
Added `@team_admin_required` to all write operations (upload, update, delete, parse, etc.)

### System API (`api/apps/restful_apis/system_api.py`)
- API token management now uses `resolve_tenant_id()` and `is_team_admin()` instead of hardcoded owner role

### Knowledgebase Service (`api/db/services/knowledgebase_service.py`)
- `_visibility_and_status_filter()`: Simplified to check `tenant_id IN (accessible_teams)` only
- `accessible()`: Now checks team membership via `UserTenantService` + superadmin bypass
- Added `accessible_by_tenant()`: For API layer where tenant_id is already resolved

### Canvas Service (`api/db/services/canvas_service.py`)
- `accessible()`: Rewritten to check canvas owner's team membership against the resolved team

### Dataset API Service (`api/apps/services/dataset_api_service.py`)
- All `KnowledgebaseService.accessible()` calls replaced with `KnowledgebaseService.accessible_by_tenant()`

### Memory API Service (`api/apps/services/memory_api_service.py`)
- `_joined_tenant_ids()`: Uses `UserTenantService` directly, excludes INVITE
- `_memory_accessible()`: Uses `is_team_member()` / `is_superadmin()`
- `create_memory()`: Accepts optional `tenant_id` parameter

## Frontend Integration

No UI changes required. When a teammember tries a write operation, the API returns:
```json
{
  "code": 108,
  "message": "Write permission denied. Team admin or higher role required.",
  "data": false
}
```

Frontend should handle `code=108` (RetCode.PERMISSION_ERROR) with an appropriate error message.

To select a team, the frontend sends `X-Tenant-Id` header with the desired team ID.

## Migration Notes

1. **Existing users**: Each user already has a Tenant (with `id == user_id`) and a UserTenant record (role=OWNER). These continue to work unchanged.
2. **New users**: Get an independent `tenant_id` generated by `get_uuid()`, with a UserTenant OWNER record linking them.
3. **New teams**: Created via `POST /tenants` by superadmin. Each team gets an independent Tenant ID.
4. **Permission field**: All new resources default to `permission="team"` (was `"me"`). Existing resources with `permission="me"` still work but are only visible to their owner. Consider migrating existing data: `UPDATE knowledgebase SET permission='team' WHERE permission='me'`.

## Bug Fixes During Testing

1. **`api/apps/restful_apis/tenant_api.py`**: Removed `@add_tenant_id_to_kwargs` from all endpoints since `tenant_id` comes from URL path, not header.
   - Changed user invitation role from `INVITE` to `NORMAL` to skip invite flow.

2. **`api/apps/restful_apis/user_api.py`**: Prevented `login_user(user)` from overwriting existing session when a superadmin registers users. New condition: only call `login_user` if `session.get("_user_id")` is not set.

3. **`api/apps/restful_apis/chat_api.py`** (create): Changed `TenantService.get_by_id(current_user.id)` to `TenantService.get_by_id(tenant_id)` since tenant IDs are now independent.

4. **`api/apps/restful_apis/agent_api.py`** (create): 
   - Changed `req["user_id"] = tenant_id` to `req["user_id"] = current_user.id`
   - Changed duplicate-check query from `user_id=tenant_id` to `user_id=current_user.id`
   - Changed `_get_user_nickname(tenant_id)` to `_get_user_nickname(current_user.id)`
   - Changed `runtime_user_id=str(tenant_id)` to `runtime_user_id=str(current_user.id)`

## Verified Test Scenarios

All 26 test cases pass:
- Superadmin: login, list teams, create/delete teams, register users, invite members, appoint/revoke teamadmin
- Teamadmin: view team, create/list datasets, chats, agents
- Teammember: list datasets/chats (read OK), create/delete (blocked with 108), appoint/invite (blocked)

## Docker Image Build

A local Docker image containing all permission modifications can be built using the provided `Dockerfile.local`. This is a lightweight build that starts from the official `infiniflow/ragflow:v0.25.6` image and overwrites only the modified source files — no need to rebuild Python dependencies or download ML models.

### Prerequisites

- Docker installed and running
- Frontend built locally (done once):

```bash
cd web
npm install
NODE_OPTIONS="--max-old-space-size=8192" VITE_BUILD_SOURCEMAP=false VITE_MINIFY=esbuild npm run build
```

### Build the Image

```bash
cd /root/ragflow-with-permission
docker build -t ragflow-with-permission:latest -f Dockerfile.local .
```

### Verify the Image

```bash
docker run --rm --entrypoint ls ragflow-with-permission:latest /ragflow/api/utils/permission.py
docker run --rm --entrypoint ls ragflow-with-permission:latest /ragflow/web/dist/index.html
```

### Local Usage

Replace the official image in your local docker-compose:

```bash
docker tag ragflow-with-permission:latest infiniflow/ragflow:v0.25.6
cd docker
docker compose up -d
```

### Publish to Docker Hub (Optional)

```bash
docker tag ragflow-with-permission:latest <your-dockerhub-user>/ragflow-with-permission:latest
docker push <your-dockerhub-user>/ragflow-with-permission:latest
```
