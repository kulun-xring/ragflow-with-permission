# RAGFlow 权限管理系统实现设计文档（方案 B）

> **方案定位**：最小侵入式实现。核心思路：修复 `get_joined_tenants_by_user_id` 的角色过滤 bug；新增 `get_user_team_role()` 统一角色判断；新增 `@superadmin_or_teamadmin_required` 装饰器对写操作进行权限拦截。不改动数据库模型结构（仅新增一个字段）、不新增中间件、不修改业务 API handler 逻辑。

---

## 0. 现有代码库分析与设计前提

> 以下发现来自对 RAGFlow 源码及 graphify 知识图谱（27,339 节点 / 62,196 边 / 1,386 社区）的全面分析，是方案 B 设计的现实依据。

### 0.1 现有权限架构全景

现有 RAGFlow 的权限体系分散在多个层次，各层次实现不一致：

| 层次 | 函数/文件 | 权限逻辑 | 问题 |
|---|---|---|---|
| KB 读取 | `KnowledgebaseService.accessible()` | `kb.tenant_id == user_id` 或 `kb.permission==TEAM` + `get_joined_tenants_by_user_id` | `get_joined_tenants_by_user_id` 只返回 `role=='normal'` 的记录，**TeamAdmin 团队不在列表中，导致 TeamAdmin 无法访问自己团队的 KB** |
| KB 写入 | `check_kb_team_permission()` | 同上 | 同上 |
| 文件权限 | `check_file_team_permission()` | 复用 `check_kb_team_permission` | 同上 |
| 连接器 | `ConnectorService.accessible()` | 同上 + `get_joined_tenants_by_user_id` | 同上 |
| Agent 列表 | `agent_api.list_agents()` | `get_joined_tenants_by_user_id` | TeamAdmin 看不到自己团队 Agent |
| 对话列表 | `chat_api` | `get_joined_tenants_by_user_id` | TeamAdmin 看不到自己团队对话 |
| 搜索列表 | `search_api` | `get_joined_tenants_by_user_id` | TeamAdmin 看不到自己团队搜索 |
| 知识库列表 | `dataset_api_service.list_datasets` | `get_joined_tenants_by_user_id` | TeamAdmin 看不到自己团队 KB |
| 模型配置 | `user_api.set_tenant_info` | **无任何权限校验** | BOLA 漏洞：任意用户可修改任意团队配置 |

### 0.2 关键发现：`get_joined_tenants_by_user_id` 的角色过滤陷阱

```python
# user_service.py L202-213
def get_joined_tenants_by_user_id(cls, user_id):
    return list(cls.model.select(*fields)
        .join(UserTenant, on=(
            ... &
            (UserTenant.role == UserTenantRole.NORMAL)  # ⚠️ 只返回 normal 角色
        ))
        ...
    )
```

该函数过滤了 `role == 'normal'`，意味着 **TeamAdmin（role=='admin' 或 'owner'）的团队不在返回值中**。

**生产环境调用点（10 处）**：

| # | 文件 | 行号 | 受影响功能 |
|---|------|------|-----------|
| 1 | `check_team_permission.py` | 36 | `check_kb_team_permission`（KB 访问） |
| 2 | `knowledgebase_service.py` | 505 | `KnowledgebaseService.accessible()`（**30+ 端点依赖**） |
| 3 | `connector_service.py` | 82 | `ConnectorService.accessible()`（连接器访问） |
| 4 | `agent_api.py` | 509 | `list_agents`（Agent 列表） |
| 5 | `agent_api.py` | 547 | `list_agent_tags`（Agent 标签） |
| 6 | `chat_api.py` | 357 | Chat listing（对话列表） |
| 7 | `search_api.py` | 79 | Search listing（搜索列表） |
| 8 | `dataset_api_service.py` | 383 | `list_datasets`（知识库列表） |
| 9 | `admin/server/services.py` | 238 | Admin KB listing |
| 10 | `admin/server/services.py` | 253 | Admin agent listing |

**这是现有代码中多个权限检查失败的根本原因。** Phase 1 必须修复所有 10 处调用。

### 0.3 现有代码中权限检查的覆盖情况（图谱验证版）

通过 graphify 图谱交叉验证，生产环境中的权限检查函数使用情况：

| 检查函数 | 调用端点数 | 类型 |
|----------|-----------|------|
| `KnowledgebaseService.accessible()` | 30+ | 最广泛，team-aware |
| `check_kb_team_permission()` | 2 | 显式团队权限 |
| `check_file_team_permission()` | 6 | 文件团队权限 |
| `KnowledgebaseService.query(tenant_id=)` | 5+ | owner-only，无 team 共享 |
| `KnowledgebaseService.get_or_none(tenant_id=)` | 3+ | owner-only，无 team 共享 |
| `DocumentService.accessible()` | 3 | team-aware |
| `UserCanvasService.accessible()` | 6 | canvas 访问 |

**关键发现**：`check_kb_team_permission` 只被 2 个端点调用，绝大多数端点使用 `KnowledgebaseService.accessible()`。因此，任何只修改 `check_kb_team_permission` 的方案，影响面非常有限。

### 0.4 `is_superuser` 字段现状

- `User.is_superuser` 存在于数据库模型中（`db_models.py` L723），类型 `BooleanField`，默认 `False`
- `UserService.is_admin()` 方法存在但**从未被任何 API 层调用**
- `is_superuser` 只在 `user_account_service.py` 中用于"禁止删除超级管理员"业务逻辑
- **`is_superadmin` 字段不存在**，需要新增
- **结论：`check_kb_team_permission` 等函数从未使用 `is_superuser` 进行权限 bypass**

### 0.5 枚举值确认

```python
# api/db/__init__.py L21-25
class UserTenantRole(StrEnum):
    OWNER = 'owner'      # 小写
    ADMIN = 'admin'       # 小写
    NORMAL = 'normal'     # 小写
    INVITE = 'invite'     # 小写

# api/db/__init__.py L28-30
class TenantPermission(StrEnum):
    ME = 'me'
    TEAM = 'team'
```

所有枚举值均为**小写**，代码中的字符串比较应使用小写。

### 0.6 发现的 BOLA 安全漏洞

`PATCH /users/me/models`（`user_api.py` L583）存在 BOLA 漏洞：

```python
# user_api.py L583-630
@manager.route("/users/me/models", methods=["PATCH"])
@login_required
@validate_request("tenant_id", "asr_id", "embd_id", "img2txt_id", "llm_id")
async def set_tenant_info():
    req = await get_request_json()
    tid = req.pop("tenant_id")              # ⚠️ 直接从请求体取，未校验归属
    TenantService.update_by_id(tid, ...)    # ⚠️ 可以修改任意团队
```

任何登录用户可通过篡改请求体中的 `tenant_id` 修改任意团队的模型配置。

---

## 1. 设计原则

1. **最小侵入**：只改 4 个文件，业务 API handler 逻辑完全不动。
2. **复用现有架构**：`User.is_superadmin` 字段新增（不删除 `is_superuser`，保持向后兼容）。
3. **不改数据库模型结构**：`Tenant`、`UserTenant` 表结构不变，`role` 字段继续使用现有枚举。
4. **SuperAdmin 天然 TeamAdmin**：SuperAdmin 拥有所有团队的 TeamAdmin 权限，无需在 `UserTenant` 表中显式存储。
5. **修复 `role=='normal'` 过滤 bug**：通过新增 `get_user_teams_with_role()` 替换所有 `get_joined_tenants_by_user_id` 调用。
6. **写操作统一拦截**：通过 `@superadmin_or_teamadmin_required` 装饰器，而非修改每个 check 函数的签名。

---

## 2. 角色体系

### 2.1 角色定义

| 角色 | 说明 | 存储位置 |
|---|---|---|
| SuperAdmin | 全局唯一，创建所有 Team；在任意 Team 中享有 TeamAdmin 等价权限 | `User.is_superadmin = True` |
| TeamAdmin | 特定 Team 的管理员；可写、可管理成员 | `UserTenant.role in ('admin', 'owner')` |
| TeamMember | 特定 Team 的普通成员；仅读权限 | `UserTenant.role == 'normal'` |

### 2.2 权限矩阵

| 操作类型 | SuperAdmin | TeamAdmin | TeamMember |
|---|---|---|---|
| 创建 Team | ✅ | ❌ | ❌ |
| 删除 Team | ✅ | ❌ | ❌ |
| 邀请/移除成员 | ✅（任意团队） | ✅（所在团队） | ❌ |
| 创建/删除知识库 | ✅ | ✅ | ❌ |
| 上传/解析文档 | ✅ | ✅ | ❌ |
| 修改切片 | ✅ | ✅ | ❌ |
| 浏览知识库列表 | ✅ | ✅ | ✅ |
| 检索/对话 | ✅ | ✅ | ✅ |
| 创建/修改应用 | ✅ | ✅ | ❌ |

---

## 3. 数据模型扩展

### 3.1 User 表新增字段

在 `User` 表中新增 `is_superadmin` 字段，不删除现有的 `is_superuser`（保持兼容）：

```sql
ALTER TABLE user ADD COLUMN is_superadmin BOOLEAN NOT NULL DEFAULT FALSE;
```

同步更新 `db_models.py`：

```python
# api/db/db_models.py User 类中，is_superuser 字段旁边新增：
is_superadmin = BooleanField(null=False, help_text="is super admin", default=False, index=True)
```

### 3.2 UserTenant 表 role 字段复用

现有 `UserTenant.role` 字段继续使用，不新增表或字段：

| 现有枚举值 | 含义 | 权限级别 |
|---|---|---|
| `'owner'` | 租户所有者 | TeamAdmin（保留，向后兼容） |
| `'admin'` | 租户管理员 | TeamAdmin |
| `'normal'` | 普通成员 | TeamMember（只读） |
| `'invite'` | 受邀未激活 | 无权限 |

### 3.3 不变动的表

- `Tenant` 表结构完全不变
- 不新增跨表关联
- 不新增 Redis 缓存结构（第一阶段不做缓存）

---

## 4. 核心实现

### 4.1 文件修改清单

| 文件路径 | 修改类型 | 修改内容 | 预估行数 |
|---|---|---|---|
| `api/db/db_models.py` | 新增字段 | `User.is_superadmin` 字段 | ~2 行 |
| `api/db/services/user_service.py` | 新增方法 | `TenantService.get_user_teams_with_role()` | ~20 行 |
| `api/common/check_team_permission.py` | 新增 + 修改 | 新增 `get_user_team_role()`；修改 `check_kb_team_permission()` 和 `check_file_team_permission()` 使用新方法 | ~50 行 |
| `api/db/services/knowledgebase_service.py` | 修复 | `accessible()` 方法中 `get_joined_tenants_by_user_id` → `get_user_teams_with_role` | ~3 行 |
| `api/apps/__init__.py` | 新增 | `@superadmin_or_teamadmin_required` 装饰器 | ~25 行 |

**不需要改动的文件**：
- 所有业务 API handler（`dataset_api.py`、`document_api.py` 等）—— 通过装饰器自动拦截
- 所有其他 Service 文件
- 所有前端代码

### 4.2 新增 `TenantService.get_user_teams_with_role()`

```python
# api/db/services/user_service.py — 在 TenantService 类中新增

@classmethod
@DB.connection_context()
def get_user_teams_with_role(cls, user_id: str) -> list[dict]:
    """
    获取用户所有加入的团队及其角色（不过滤角色）。

    与 get_joined_tenants_by_user_id 的区别：
        - get_joined_tenants_by_user_id：只返回 role == 'normal' 的记录（现有 bug）
        - 本方法：返回所有有效角色（owner/admin/normal），用于权限判断

    返回格式：
        [{'tenant_id': 'xxx', 'name': 'yyy', 'role': 'owner'|'admin'|'normal'}, ...]
    """
    fields = [
        cls.model.id.alias("tenant_id"),
        cls.model.name,
        cls.model.llm_id,
        cls.model.embd_id,
        cls.model.asr_id,
        cls.model.img2txt_id,
        UserTenant.role
    ]
    return list(cls.model.select(*fields)
                .join(UserTenant, on=(
                    (cls.model.id == UserTenant.tenant_id) &
                    (UserTenant.user_id == user_id) &
                    (UserTenant.status == StatusEnum.VALID.value)
                    # 不过滤 role，返回 owner/admin/normal
                ))
                .where(cls.model.status == StatusEnum.VALID.value).dicts())
```

### 4.3 新增 `get_user_team_role()`

```python
# api/common/check_team_permission.py

from api.db.db_models import User
from api.db.services.user_service import TenantService


def get_user_team_role(user_id: str, tenant_id: str) -> str:
    """
    获取用户在指定团队中的角色。

    返回值：
        'superadmin' : User.is_superadmin == True 或 User.is_superuser == True
        'teamadmin'  : UserTenant.role in ('admin', 'owner')
        'member'     : UserTenant.role == 'normal'
        'none'       : 不在该团队中

    注意：
        - SuperAdmin 不在 UserTenant 表中，通过 is_superadmin/is_superuser 字段 bypass。
        - 本函数使用 TenantService.get_user_teams_with_role()（不过滤角色），
          而不是 get_joined_tenants_by_user_id()（后者硬编码 role=='normal'，
          会导致 TeamAdmin 的团队不在返回值中）。
    """
    # 1. SuperAdmin 检查
    try:
        user = User.select(User.is_superuser, User.is_superadmin).where(User.id == user_id).first()
        if user and (getattr(user, 'is_superadmin', False) or user.is_superuser):
            return 'superadmin'
    except Exception:
        pass

    # 2. 团队角色检查
    teams = TenantService.get_user_teams_with_role(user_id)
    for team in teams:
        if team['tenant_id'] == tenant_id:
            role = team['role']
            if role in ('admin', 'owner'):
                return 'teamadmin'
            elif role == 'normal':
                return 'member'
            else:
                return 'none'  # 'invite' 等无效角色

    return 'none'
```

### 4.4 修改 `check_kb_team_permission()`

```python
# api/common/check_team_permission.py

def check_kb_team_permission(kb: dict | Knowledgebase, other: str) -> bool:
    """
    检查用户是否有权访问指定知识库（读权限）。

    逻辑：
        1. 知识库归属当前用户（kb.tenant_id == other）→ 直接放行
        2. 知识库权限为 TEAM → 检查用户在 kb.tenant_id 中是否有有效角色
        3. 知识库权限为 ME → 拒绝

    注意：本函数只做读权限检查（能否看到这个 KB）。
    写权限拦截由 @superadmin_or_teamadmin_required 装饰器负责。
    """
    kb = kb.to_dict() if isinstance(kb, Knowledgebase) else kb
    kb_tenant_id = kb["tenant_id"]

    # 归属检查
    if kb_tenant_id == other:
        return True

    # 权限级别检查
    if kb["permission"] != TenantPermission.TEAM.value:
        return False

    # 使用新方法检查用户是否在团队中（不过滤角色）
    role = get_user_team_role(other, kb_tenant_id)
    return role in ('superadmin', 'teamadmin', 'member')
```

**改动说明**：
- 将 `get_joined_tenants_by_user_id` 替换为 `get_user_team_role()`
- 本函数只负责读权限（能否看到），写拦截由装饰器负责
- 不新增 `request_method` 参数——避免改动所有调用点的签名

### 4.5 修改 `check_file_team_permission()`

```python
# api/common/check_team_permission.py

def check_file_team_permission(file: dict | File, other: str) -> bool:
    """
    检查用户是否有权访问指定文件（读权限）。

    逻辑：
        1. 文件归属当前用户 → 直接放行
        2. 遍历文件所在的所有知识库，任一知识库可访问即放行

    注意：本函数只做读权限检查。写权限拦截由装饰器负责。
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
```

**改动说明**：签名不变（只有 `file` 和 `other` 两个参数），内部通过 `check_kb_team_permission` 自动使用新逻辑。

### 4.6 修复 `KnowledgebaseService.accessible()`

```python
# api/db/services/knowledgebase_service.py L484-506

@DB.connection_context()
def accessible(cls, kb_id, user_id):
    e, kb = cls.get_by_id(kb_id)
    if not e:
        return False
    if kb.status != StatusEnum.VALID.value:
        return False
    if kb.tenant_id == user_id:
        return True
    if kb.permission != TenantPermission.TEAM.value:
        return False

    # 修复：使用 get_user_teams_with_role 替代 get_joined_tenants_by_user_id
    # 后者硬编码 role=='normal'，导致 TeamAdmin 无法访问自己团队的 KB
    from api.common.check_team_permission import get_user_team_role
    role = get_user_team_role(user_id, kb.tenant_id)
    return role in ('superadmin', 'teamadmin', 'member')
```

**这是影响面最大的一处修复**——`accessible()` 被 30+ 个端点调用，修复后 TeamAdmin 即可正常访问自己团队的所有 KB 相关功能。

### 4.7 新增装饰器：`@superadmin_or_teamadmin_required`

```python
# api/apps/__init__.py

from functools import wraps
from api.utils.api_utils import get_error_data_result
from api.db import RetCode


def superadmin_or_teamadmin_required(func):
    """
    装饰器：要求当前用户在请求目标团队中拥有 TeamAdmin 或更高权限。
    用于保护创建/删除知识库、删除文档、邀请成员等写操作端点。

    使用方式：
        @manager.route("/xxx", methods=["POST"])
        @login_required
        @add_tenant_id_to_kwargs
        @superadmin_or_teamadmin_required
        async def some_write_operation(tenant_id: str, ...):
            ...

    执行顺序说明：
        装饰器从外到内执行：login_required → add_tenant_id_to_kwargs → superadmin_or_teamadmin_required
        所以 @superadmin_or_teamadmin_required 执行时，kwargs['tenant_id'] 已由 @add_tenant_id_to_kwargs 注入。

    注意：
        - tenant_id 来自 @add_tenant_id_to_kwargs，即 current_user.id（当前登录用户的 ID）。
        - 本装饰器不处理 Tenant-Id 请求头（见 §4.8）。
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        from api.common.check_team_permission import get_user_team_role
        from api.apps import current_user

        tenant_id = kwargs.get('tenant_id')
        if not tenant_id:
            return get_error_data_result(
                message="Missing tenant_id", code=RetCode.ARGUMENT_ERROR
            )

        role = get_user_team_role(current_user.id, tenant_id)
        if role == 'none':
            return get_error_data_result(
                message="您不是该团队的成员。", code=RetCode.AUTHENTICATION_ERROR
            )
        if role == 'member':
            return get_error_data_result(
                message="操作失败：您在该团队中仅拥有【只读】权限，无法执行涉及修改的操作。",
                code=RetCode.AUTHENTICATION_ERROR
            )
        # superadmin 或 teamadmin：放行
        return await func(*args, **kwargs)

    return wrapper
```

### 4.8 `add_tenant_id_to_kwargs` 不做修改

原方案建议修改 `add_tenant_id_to_kwargs` 支持从 `Tenant-Id` 请求头读取目标团队。经图谱分析，该装饰器有 **83 个调用点**，修改它会影响所有端点。

**安全风险**：如果写操作端点也从请求头读取 `tenant_id`，攻击者可以在请求头中设置 `Tenant-Id: <别人的团队ID>`，绕过归属检查。

**决定**：`add_tenant_id_to_kwargs` **保持原样**（只用 `current_user.id`）。

如果未来需要跨团队查询（如 SuperAdmin 查看其他团队资源），应在**单独的查询端点**中实现，而不是修改这个通用装饰器。

### 4.9 修复 BOLA 漏洞：`PATCH /users/me/models`

```python
# api/apps/restful_apis/user_api.py L583-630

@manager.route("/users/me/models", methods=["PATCH"])
@login_required
@validate_request("tenant_id", "asr_id", "embd_id", "img2txt_id", "llm_id")
async def set_tenant_info():
    req = await get_request_json()
    try:
        tid = req.pop("tenant_id")
        # 修复：校验 tid 是否属于当前用户（直接归属或团队管理员权限）
        from api.common.check_team_permission import get_user_team_role
        from api.apps import current_user
        role = get_user_team_role(current_user.id, tid)
        if role not in ('superadmin', 'teamadmin'):
            return server_error_response(
                PermissionError("You don't have permission to modify this tenant's models.")
            )
        update_dict = ensure_tenant_model_id_for_params(tid, req)
        TenantService.update_by_id(tid, update_dict)
        return get_json_result(data=True)
    except Exception as e:
        return server_error_response(e)
```

**改动说明**：新增 5 行代码，校验当前用户对目标 `tenant_id` 是否拥有 TeamAdmin 或更高权限。

---

## 5. 改动范围汇总

### 5.1 需改动的文件列表（最终版）

| 文件 | 行数改动（预估） | 改动性质 |
|---|---|---|
| `api/db/db_models.py` | ~2 行 | User 模型新增 `is_superadmin` 字段 |
| `api/db/services/user_service.py` | ~20 行 | 新增 `get_user_teams_with_role()` 方法 |
| `api/common/check_team_permission.py` | ~50 行 | 新增 `get_user_team_role()`；修改 `check_kb_team_permission()` 和 `check_file_team_permission()` |
| `api/db/services/knowledgebase_service.py` | ~5 行 | `accessible()` 方法替换 `get_joined_tenants_by_user_id` 调用 |
| `api/apps/__init__.py` | ~25 行 | 新增 `@superadmin_or_teamadmin_required` 装饰器 |
| `api/apps/restful_apis/user_api.py` | ~5 行 | `set_tenant_info()` 新增 BOLA 校验 |
| **合计** | **~107 行** | **6 个文件** |

### 5.2 需叠加 `@superadmin_or_teamadmin_required` 装饰器的端点

以下端点执行写操作，需要在 Phase 2 中叠加装饰器。**注意：这些端点不需要修改 handler 内部逻辑**，只需在函数定义上方添加一行装饰器。

| 文件 | 端点 | 方法 | 当前权限检查 | 需要改动 |
|---|---|---|---|---|
| `dataset_api.py` | `/datasets` | POST | 无（创建时自动归属当前用户） | 加装饰器 |
| `dataset_api.py` | `/datasets/{id}` | DELETE | `get_or_none(tenant_id=)` owner-only | 加装饰器 |
| `dataset_api.py` | `/datasets/{id}` | PUT | `get_or_none(tenant_id=)` owner-only | 加装饰器 |
| `dataset_api.py` | `/datasets/{id}/tags` | DELETE/PUT | `accessible()` team-aware | 加装饰器 |
| `dataset_api.py` | `/datasets/{id}/index` | POST/DELETE | `accessible()` team-aware | 加装饰器 |
| `dataset_api.py` | `/datasets/{id}/embedding` | POST | `accessible()` team-aware | 加装饰器 |
| `dataset_api.py` | `/datasets/{id}/metadata/config` | PUT | `get_or_none(tenant_id=)` owner-only | 加装饰器 |
| `document_api.py` | `/datasets/{id}/documents/{id}` | PATCH | `query(tenant_id=)` owner-only | 加装饰器 |
| `document_api.py` | `/datasets/{id}/documents` | POST | `check_kb_team_permission` | 自动继承 |
| `document_api.py` | `/datasets/{id}/documents` | DELETE | `accessible()` team-aware | 加装饰器 |
| `document_api.py` | `/datasets/{id}/documents/{id}/metadata/config` | PUT | `query(tenant_id=)` owner-only | 加装饰器 |
| `document_api.py` | `/datasets/{id}/documents/metadatas` | PATCH | `accessible()` team-aware | 加装饰器 |
| `document_api.py` | `/documents/ingest` | POST | `DocumentService.accessible()` | 加装饰器 |
| `document_api.py` | `/datasets/{id}/documents/parse` | POST | `accessible()` team-aware | 加装饰器 |
| `document_api.py` | `/datasets/{id}/documents/stop` | POST | `accessible()` team-aware | 加装饰器 |
| `document_api.py` | `/datasets/{id}/documents/batch-update-status` | POST | `query(tenant_id=)` owner-only | 加装饰器 |
| `document_api.py` | `/documents/upload` | POST | 无 | 加装饰器 |
| `chunk_api.py` | 所有写端点 | POST/DELETE/PUT | `accessible()` team-aware | 加装饰器 |
| `file_api.py` | `/files` | POST | 无 | 加装饰器 |
| `file_api.py` | `/files` | DELETE | `check_file_team_permission` | 自动继承 |
| `file_api.py` | `/files/move` | POST | `check_file_team_permission` | 自动继承 |
| `agent_api.py` | 创建/修改/删除 canvas | POST/PUT/DELETE | `UserCanvasService.accessible()` | 加装饰器 |
| `tenant_api.py` | `/tenants/{id}/users` | POST/DELETE | `current_user.id` 校验 | 加装饰器（需确认） |
| `user_api.py` | `/users/me/models` | PATCH | **无**（BOLA 漏洞） | §4.9 单独修复 |

> **"自动继承"**：这些端点已调用 `check_kb_team_permission` 或 `check_file_team_permission`，Phase 1 修复这两个函数后自动获得正确的读权限判断。写拦截由装饰器补充。

> **"加装饰器"**：只需在函数定义上方添加 `@superadmin_or_teamadmin_required`，不改函数内部逻辑。

### 5.3 不需要改动的文件

- 所有数据库模型文件（`db_models.py` 除外，仅新增 1 个字段）
- 所有 Blueprint 路由注册文件
- 所有前端代码
- `backward_compat.py`（兼容层，自动继承）

---

## 6. 错误响应

所有被本系统拦截的写操作，统一返回：

```json
HTTP 403 Forbidden
{
  "code": 403,
  "status": "error",
  "message": "操作失败：您在该团队中仅拥有【只读】权限，无法执行涉及修改的操作。"
}
```

非团队成员试图访问时返回：

```json
HTTP 403 Forbidden
{
  "code": 403,
  "status": "error",
  "message": "您不是该团队的成员。"
}
```

---

## 7. 测试要点

| 测试场景 | 预期结果 |
|---|---|
| SuperAdmin 创建 Team | ✅ 成功 |
| SuperAdmin 在任意 Team 做写操作 | ✅ 成功 |
| TeamAdmin 邀请成员 | ✅ 成功 |
| TeamAdmin 删除知识库 | ✅ 成功 |
| TeamAdmin 浏览自己团队的知识库列表 | ✅ 成功（Phase 1 修复后） |
| TeamAdmin 查看自己团队的 Agent 列表 | ✅ 成功（Phase 1 修复后） |
| TeamMember 尝试上传文档 | ❌ 403，提示只读权限 |
| TeamMember 尝试删除文档 | ❌ 403，提示只读权限 |
| TeamMember 尝试修改模型配置 | ❌ 403 |
| 非团队成员访问团队资源 | ❌ 403，提示非团队成员 |
| TeamAdmin A 试图通过篡改请求体修改 Team B 数据 | ❌ 403（BOLA 防护） |
| 普通用户试图通过篡改 `tenant_id` 修改其他团队模型配置 | ❌ 403（BOLA 修复） |
| TeamMember 浏览知识库列表 | ✅ 成功 |
| TeamMember 检索/对话 | ✅ 成功 |

---

## 8. 与 PRD2 的对照

| PRD2 章节 | 方案 B 对应实现 | 实际代码发现 |
|---|---|---|
| §2 角色定义 | ✅ SuperAdmin=`is_superadmin`；TeamAdmin=`role in (admin/owner)`；TeamMember=`role == normal` | `UserTenantRole` 枚举值均为小写，与方案一致 |
| §3 权限矩阵 | ✅ 由 `get_user_team_role()` 返回值驱动 | `get_joined_tenants_by_user_id` 硬编码 `role=='normal'`，影响 10 处调用 |
| §4.1 后端全局权限拦截器 | ✅ `@superadmin_or_teamadmin_required` 装饰器 + `check_*_team_permission` 修复 | 装饰器方案优于中间件，侵入更小 |
| §4.2 POST 白名单 | ✅ 无需此机制 | 查询类端点（list/search）不叠加写拦截装饰器，天然白名单 |
| §4.3 前端响应拦截 | ✅ 前端已有 403 处理逻辑 | 直接复用 |
| §5.1 性能/Redis 缓存 | 🔲 第一阶段暂不做缓存 | `get_user_teams_with_role()` 直接查库；第二阶段加 Redis |
| §5.2 BOLA 防护 | ✅ `check_kb_team_permission` 入口校验 + `user_api` BOLA 修复 | `PATCH /users/me/models` 存在 BOLA 漏洞，§4.9 已修复 |

---

## 9. 实施顺序

### Phase 1（核心修复 — 修复 TeamAdmin 无法访问团队资源的根本 bug）

**目标**：让 TeamAdmin 能正常看到和访问自己团队的所有资源。

1. **数据库**：`ALTER TABLE user ADD COLUMN is_superadmin BOOLEAN NOT NULL DEFAULT FALSE;`
2. **`db_models.py`**：User 模型新增 `is_superadmin` 字段（~2 行）
3. **`user_service.py`**：`TenantService.get_user_teams_with_role()` 新增（~20 行）
4. **`check_team_permission.py`**：
   - `get_user_team_role()` 新增
   - `check_kb_team_permission()` 改用 `get_user_team_role()`
   - `check_file_team_permission()` 内部自动继承
5. **`knowledgebase_service.py`**：`accessible()` 方法中 `get_joined_tenants_by_user_id` → `get_user_team_role`（~5 行）
6. **验证**：手动测试 TeamAdmin 浏览 KB 列表、Agent 列表、对话列表

### Phase 2（写操作拦截 — 叠加装饰器 + BOLA 修复）

**目标**：TeamMember 的写操作被 403 拦截。

7. **`api/apps/__init__.py`**：新增 `@superadmin_or_teamadmin_required` 装饰器
8. **逐个叠加装饰器**（按 §5.2 列表，只需添加装饰器，不改 handler 逻辑）：
   - `dataset_api.py` — 所有写端点
   - `document_api.py` — 所有写端点
   - `chunk_api.py` — 所有写端点
   - `file_api.py` — `POST /files`
   - `agent_api.py` — 创建/修改/删除 canvas
   - `tenant_api.py` — 邀请/移除成员
9. **`user_api.py`**：修复 `set_tenant_info()` BOLA 漏洞（§4.9）
10. **验证**：手动测试 TeamMember 写操作被 403 拦截

### Phase 3（可选优化）

11. Redis 缓存角色映射（如果性能测试不满足要求）
12. 异步任务上下文隔离校验（PRD2 §6 提到的 Celery 任务场景）
13. SDK API 端点（`api/apps/sdk/`）的权限控制
14. `ConnectorService.accessible()`、`UserCanvasService.accessible()` 等其他 `accessible` 方法的修复

---

## 10. 已知限制与后续工作

| 项目 | 说明 | 优先级 |
|---|---|---|
| `get_joined_tenants_by_user_id` 保留 | 不删除该函数，避免破坏外部调用方。但所有 RAGFlow 内部调用应迁移到 `get_user_teams_with_role` | P2 |
| `admin` 角色数据确认 | 需查询生产数据库确认 `role='admin'` 是否有实际数据。如果没有，`admin` 角色是死代码 | P2 |
| `accessible4deletion` 死代码 | `DocumentService.accessible4deletion` 和 `KnowledgebaseService.accessible4deletion` 零生产调用，可考虑清理 | P3 |
| SDK API 独立认证路径 | `apikey_required` 路径不走 `login_required`，需要单独处理角色注入 | P3 |
| 前端 403 提示 | 前端需确认全局响应拦截器已捕获 403 并弹出通知 | P2 |

---

*文档版本：v2.0（整合 graphify 图谱分析结果，修复 10 处 get_joined_tenants_by_user_id 调用、BOLA 漏洞、装饰器方案优化）*
*方案：方案 B（最小侵入式实现）*
*日期：2026-05-22*
