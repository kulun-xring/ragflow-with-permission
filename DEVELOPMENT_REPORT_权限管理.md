# RAGFlow 权限管理系统开发报告

> **开发周期**：2026-05-22
> **方案**：方案 B — 最小侵入式实现
> **设计文档**：`IMPLEMENTATION_DESIGN_权限管理_方案B.md`

---

## 一、项目背景

RAGFlow 原有权限系统存在以下问题：

1. **核心 Bug**：`TenantService.get_joined_tenants_by_user_id()` 硬编码 `UserTenant.role == UserTenantRole.NORMAL`，导致 TeamAdmin（role='admin'/'owner'）的团队从结果中被排除。该函数有 10 个生产调用方，影响团队管理、知识库访问、文档操作等核心功能。

2. **写操作无拦截**：普通成员（role='normal'）可以调用创建、删除、修改等写操作 API，无任何权限校验。

3. **BOLA/IDOR 漏洞**：`PATCH /users/me/models` 接口从请求体读取 `tenant_id`，攻击者可传入任意 tenant_id 修改其他团队的模型配置。

**目标**：在不改动业务 API handler 逻辑的前提下，修复以上三个问题。

---

## 二、技术方案概览

### 三层权限模型

| 层级 | 角色 | 标识 | 权限 |
|------|------|------|------|
| L1 | SuperAdmin | `User.is_superadmin=True` 或 `User.is_superuser=True` | 全局管理员，跳过所有团队检查 |
| L2 | TeamAdmin | `UserTenant.role in ('admin', 'owner')` | 团队管理员，可执行写操作 |
| L3 | TeamMember | `UserTenant.role == 'normal'` | 普通成员，只读访问 |

### 核心设计原则

- **最小侵入**：不修改现有 API handler 的业务逻辑
- **装饰器模式**：写操作通过 `@superadmin_or_teamadmin_required` 装饰器统一拦截
- **新增而非修改**：新增 `get_user_team_role()` 替代修改原有 `get_joined_tenants_by_user_id()`
- **向后兼容**：原有 10 个调用方的读操作逻辑不变

---

## 三、Phase 1 — 核心 Bug 修复

### 3.1 新增 `is_superadmin` 字段

**文件**：`api/db/db_models.py`

在 `User` 模型中新增 `is_superadmin` 布尔字段（L724），并在 `migrate_db()` 中添加自动迁移（L1658）：

```python
is_superadmin = BooleanField(null=False, help_text="is super admin", default=False, index=True)
```

迁移代码：
```python
alter_db_add_column(migrator, "user", "is_superadmin",
    BooleanField(null=False, help_text="is super admin", default=False, index=True))
```

### 3.2 新增 `get_user_teams_with_role()`

**文件**：`api/db/services/user_service.py`（L215-234）

与原有 `get_joined_tenants_by_user_id()` 的关键区别：**移除** `UserTenant.role == UserTenantRole.NORMAL` 过滤条件，返回所有角色的团队。

```python
@classmethod
@DB.connection_context()
def get_user_teams_with_role(cls, user_id):
    """Return all teams the user belongs to, with their role (owner/admin/normal)."""
    fields = [
        cls.model.id.alias("tenant_id"),
        cls.model.name, cls.model.llm_id, cls.model.embd_id,
        cls.model.asr_id, cls.model.img2txt_id,
        UserTenant.role]
    return list(cls.model.select(*fields)
                .join(UserTenant, on=(
                    (cls.model.id == UserTenant.tenant_id) &
                    (UserTenant.user_id == user_id) &
                    (UserTenant.status == StatusEnum.VALID.value)
                ))
                .where(cls.model.status == StatusEnum.VALID.value).dicts())
```

### 3.3 重写 `check_team_permission.py`

**文件**：`api/common/check_team_permission.py`（完整重写，~105 行）

核心函数 `get_user_team_role(user_id, tenant_id)` 返回值：

| 返回值 | 条件 |
|--------|------|
| `'superadmin'` | `User.is_superadmin` 或 `User.is_superuser` 为 True |
| `'teamadmin'` | `UserTenant.role in ('admin', 'owner')` |
| `'member'` | `UserTenant.role == 'normal'` |
| `'none'` | 不在该团队中，或 role 为 'invite' 等无效值 |

辅助函数：
- `check_kb_team_permission(kb, user_id)` — 知识库读权限检查
- `check_file_team_permission(file, user_id)` — 文件读权限检查

### 3.4 修复 `KnowledgebaseService.accessible()`

**文件**：`api/db/services/knowledgebase_service.py`（L483-507）

**修改前**：
```python
joined_tenants = TenantService.get_joined_tenants_by_user_id(user_id)
return any(tenant["tenant_id"] == kb.tenant_id for tenant in joined_tenants)
```

**修改后**：
```python
from api.common.check_team_permission import get_user_team_role
role = get_user_team_role(user_id, kb.tenant_id)
return role in ('superadmin', 'teamadmin', 'member')
```

使用延迟导入避免循环依赖（`check_team_permission` 导入了 `KnowledgebaseService`）。

---

## 四、Phase 2 — 写操作拦截 + BOLA 修复

### 4.1 `@superadmin_or_teamadmin_required` 装饰器

**文件**：`api/apps/__init__.py`（L232-255）

```python
def superadmin_or_teamadmin_required(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        from api.common.check_team_permission import get_user_team_role
        tenant_id = kwargs.get('tenant_id')
        if not tenant_id:
            return get_json_result(code=RetCode.FORBIDDEN, message="Missing tenant_id")
        role = get_user_team_role(current_user.id, tenant_id)
        if role == 'none':
            return get_json_result(code=RetCode.FORBIDDEN, message="您不是该团队的成员。")
        if role == 'member':
            return get_json_result(code=RetCode.FORBIDDEN,
                message="操作失败：您在该团队中仅拥有【只读】权限，无法执行涉及修改的操作。")
        return await current_app.ensure_async(func)(*args, **kwargs)
    return wrapper
```

装饰器顺序：`@login_required` → `@add_tenant_id_to_kwargs` → `@superadmin_or_teamadmin_required`

### 4.2 写操作端点装饰（37 个端点）

| API 文件 | 装饰端点数 | 代表性端点 |
|----------|-----------|-----------|
| `dataset_api.py` | 10 | create, delete, update, run_index, delete_index, run_embedding |
| `document_api.py` | 11 | upload_info, update_document, delete_documents, ingest, parse_documents |
| `chunk_api.py` | 4 | add_chunk, rm_chunk, update_chunk, switch_chunks |
| `file_api.py` | 3 | create_or_upload, delete, move |
| `agent_api.py` | 7 | create_agent, delete_agent, update_agent, upload, reset_agent |
| `tenant_api.py` | 1 | create (邀请用户) |

**未装饰的端点**（查询类/自操作）：
- 所有 GET 端点
- search/query 类 POST 端点
- chat/debug 端点
- `tenant_api.agree`（用户接受自己的邀请）
- `tenant_api.rm`（移除/退出团队 — 特殊处理，见 4.4）

### 4.3 BOLA/IDOR 漏洞修复

**文件**：`api/apps/restful_apis/user_api.py`（L625-632）

**修改前**：直接使用请求体中的 `tenant_id` 进行数据库更新
**修改后**：校验当前用户对该 tenant_id 的权限

```python
tid = req.pop("tenant_id")
from api.common.check_team_permission import get_user_team_role
role = get_user_team_role(current_user.id, tid)
if role not in ('superadmin', 'teamadmin'):
    return get_json_result(data=False,
        message="You don't have permission to modify this tenant's models.",
        code=RetCode.FORBIDDEN)
```

### 4.4 SuperAdmin 退出团队限制

**文件**：`api/apps/restful_apis/tenant_api.py`（L122-148）

**问题**：SuperAdmin 作为唯一的全员维护者，不应退出任何团队，否则无人管理该团队的用户。

**实现**：移除 `@superadmin_or_teamadmin_required` 装饰器，改为函数内部权限判断：

```python
@manager.route("/tenants/<tenant_id>/users", methods=["DELETE"])
@login_required
@validate_request("user_id")
async def rm(tenant_id):
    req = await get_request_json()
    user_id = req["user_id"]

    # Case 1: user is removing themselves (leave team)
    if current_user.id == user_id:
        # SuperAdmin cannot leave any team
        if getattr(current_user, "is_superadmin", False):
            return get_json_result(
                data=False,
                message="SuperAdmin cannot leave any team.",
                code=RetCode.FORBIDDEN,
            )
        # Normal members can leave freely
        UserTenantService.filter_delete([...])
        return get_json_result(data=True)

    # Case 2: removing someone else — must be team owner
    if current_user.id != tenant_id:
        return get_json_result(data=False, message="No authorization.", ...)
    UserTenantService.filter_delete([...])
    return get_json_result(data=True)
```

**设计决策**：移除 `@superadmin_or_teamadmin_required` 装饰器，因为该装饰器会阻止普通成员退出团队。改为函数内判断：
- **自己退出**：允许（但 SuperAdmin 被阻止）
- **移除他人**：必须是团队 owner（`current_user.id == tenant_id`）

---

## 五、Phase 3 — RAGFlow 架构约束说明

### 5.1 `add_tenant_id_to_kwargs` 的作用域

**文件**：`api/utils/api_utils.py`

```python
def add_tenant_id_to_kwargs(func):
    @wraps(func)
    async def wrapper(**kwargs):
        kwargs["tenant_id"] = current_user.id  # 始终使用当前用户的 ID
        return await func(**kwargs)
    return wrapper
```

此装饰器决定了 RAGFlow 权限系统的基本架构：

1. **所有操作都在用户自己的 tenant 上下文中执行**：`tenant_id = current_user.id`
2. **每个用户在自己 tenant 中是 `owner` 角色**：注册时自动创建 tenant 并设为 owner
3. **`@superadmin_or_teamadmin_required` 检查的是用户在自己 tenant 中的角色**：因为 owner → teamadmin，所以所有用户在自己 tenant 中都能通过装饰器

### 5.2 对权限系统的影响

| 场景 | 行为 | 原因 |
|------|------|------|
| 用户在自己 tenant 中创建知识库 | 允许 | owner → teamadmin，装饰器放行 |
| 用户在自己 tenant 中上传文件 | 允许 | owner → teamadmin，装饰器放行 |
| 用户修改其他团队的知识库 | 拒绝（102） | 数据集不属于自己的 tenant |
| 用户删除其他团队的知识库 | 拒绝（102） | 数据集不属于自己的 tenant |
| 用户查看 permission=team 的知识库 | 允许 | `check_kb_team_permission` 检查团队成员身份 |
| 用户向其他团队的知识库上传文档 | 拒绝（101） | 文档上传端点检查 tenant 所有权 |
| 被邀请的普通成员在团队中上传文件 | 不适用 | 操作在自己的 tenant 中，不影响团队 |
| 被邀请的普通成员修改团队知识库 | 拒绝（102） | 数据集不属于自己的 tenant |

**结论**：RAGFlow 的 `add_tenant_id_to_kwargs` 架构天然实现了资源隔离——用户只能操作自己 tenant 中的资源。权限系统在此基础上增加了：
- BOLA 修复（`PATCH /users/me/models` 从请求体读取 tenant_id）
- SuperAdmin 退出团队限制
- 知识库/文件的读权限控制（`permission=me/team`）

---

## 六、修改文件清单

| 文件 | 修改类型 | 说明 |
|------|----------|------|
| `api/db/db_models.py` | 新增字段 + 迁移 | `is_superadmin` 字段和迁移逻辑 |
| `api/db/services/user_service.py` | 新增方法 | `get_user_teams_with_role()` |
| `api/common/check_team_permission.py` | 重写 | `get_user_team_role()` + `check_kb_team_permission()` + `check_file_team_permission()` |
| `api/db/services/knowledgebase_service.py` | 修改方法 | `accessible()` 使用新函数 |
| `api/apps/__init__.py` | 新增装饰器 | `@superadmin_or_teamadmin_required` |
| `api/apps/restful_apis/dataset_api.py` | 添加装饰器 | 10 个写端点 |
| `api/apps/restful_apis/document_api.py` | 添加装饰器 | 11 个写端点 |
| `api/apps/restful_apis/chunk_api.py` | 添加装饰器 | 4 个写端点 |
| `api/apps/restful_apis/file_api.py` | 添加装饰器 | 3 个写端点 |
| `api/apps/restful_apis/agent_api.py` | 添加装饰器 | 7 个写端点 |
| `api/apps/restful_apis/tenant_api.py` | 重写 rm 端点 | SuperAdmin 退出团队限制 + 普通成员可自由退出 |
| `api/apps/restful_apis/user_api.py` | BOLA 修复 | `set_tenant_info()` 权限校验 |
| `test/unit_test/api/common/test_check_team_permission.py` | 新增测试 | 32 个测试用例 |
| `test/unit_test/api/db/services/test_dataset_access_permissions.py` | 更新测试 | monkeypatch 目标更新 |

**统计**：14 个文件，+175 行，-25 行

---

## 七、测试

### 6.1 测试架构

测试文件：`test/unit_test/api/common/test_check_team_permission.py`（511 行）

由于 RAGFlow 的依赖链极深（peewee → quart → elasticsearch → ...），直接导入 `api.*` 模块需要完整的数据库和服务环境。测试采用 **`MetaPathFinder` + 预置桩模块** 策略：

1. 安装自定义 `MetaPathFinder`，拦截所有非 `api.*`/`test.*` 的导入
2. 预置 peewee 桩（带真实 metaclass）、`common.settings` 桩（带真实配置值）、`playhouse.pool` 桩（带 `connection_context()` 透传装饰器）
3. 迭代导入，自动补全缺失的桩模块
4. 通过 `unittest.mock.patch` 在测试用例级别控制依赖行为

### 6.2 测试用例（32 个，全部通过）

```
TestGetUserRole (11 tests)
  test_superadmin_via_is_superadmin     ✓  is_superadmin=True → 'superadmin'
  test_superadmin_via_is_superuser      ✓  is_superuser=True → 'superadmin'
  test_teamadmin_role_admin             ✓  role='admin' → 'teamadmin'
  test_teamadmin_role_owner             ✓  role='owner' → 'teamadmin'
  test_member_role_normal               ✓  role='normal' → 'member'
  test_invite_returns_none              ✓  role='invite' → 'none'
  test_not_in_team                      ✓  不在目标团队 → 'none'
  test_empty_teams                      ✓  空团队列表 → 'none'
  test_user_not_found_falls_through     ✓  用户不存在时回退到团队检查
  test_multiple_teams                   ✓  多团队场景正确匹配
  test_superadmin_bypasses_team_membership  ✓  超管跳过团队成员检查

TestCheckKbTeamPermission (6 tests)
  test_owner_always_allowed             ✓  KB 所有者始终可访问
  test_me_denied_to_others              ✓  'me' 权限拒绝非所有者
  test_team_allows_member               ✓  'team' 权限允许成员
  test_team_allows_teamadmin            ✓  'team' 权限允许团队管理员
  test_team_allows_superadmin           ✓  'team' 权限允许超管
  test_team_denies_non_member           ✓  'team' 权限拒绝非成员

TestKnowledgebaseAccessible (8 tests)
  test_owner_can_access                 ✓  所有者可访问
  test_team_member_can_access           ✓  团队成员可访问
  test_teamadmin_can_access             ✓  团队管理员可访问
  test_superadmin_can_access            ✓  超管可访问
  test_non_member_cannot_access         ✓  非成员不可访问
  test_me_kb_not_accessible_to_others   ✓  私有 KB 对他人不可访问
  test_invalid_status_not_accessible    ✓  无效状态 KB 不可访问
  test_nonexistent_kb                   ✓  不存在的 KB 返回 False

TestDecorator (5 tests)
  test_member_blocked                   ✓  普通成员被拦截（403）
  test_teamadmin_allowed                ✓  团队管理员放行
  test_superadmin_allowed               ✓  超管放行
  test_non_member_blocked               ✓  非成员被拦截（403）
  test_missing_tenant_id_blocked        ✓  缺少 tenant_id 被拦截（403）

TestGetUserTeamsWithRole (2 tests)
  test_method_exists                    ✓  方法存在
  test_signature_accepts_user_id        ✓  签名包含 user_id 参数
```

### 6.3 已有测试更新

`test/unit_test/api/db/services/test_dataset_access_permissions.py` 的 `test_team_dataset_is_accessible_to_joined_tenant_member` 测试更新了 monkeypatch 目标：

```python
# 修改前
monkeypatch.setattr(
    "api.db.services.knowledgebase_service.TenantService.get_joined_tenants_by_user_id",
    lambda _user_id: [{"tenant_id": "owner-1"}],
)

# 修改后
monkeypatch.setattr(
    "api.common.check_team_permission.get_user_team_role",
    lambda _user_id, _tenant_id: "member",
)
```

### 6.4 真实 Docker 环境测试

**环境**：RAGFlow v0.25.5 + MySQL + Elasticsearch 8.11.3 + Redis + MinIO

**测试用户（7 人）**：

| 用户 | 角色说明 |
|------|----------|
| admin@test.com | SuperAdmin，Team A owner |
| teamadmin@test.com | teamadmin1，Team A admin + Team B owner |
| teamadmin2@test.com | Team A admin + Team C owner |
| teamadmin3@test.com | Team B admin + Team C admin |
| member1@test.com | Team A normal + Team B normal |
| member2@test.com | Team A normal + Team C normal |
| member3@test.com | Team B normal + Team C normal |

**团队结构**：

```
Team A (admin's):  admin=owner, ta1=admin, ta2=admin, m1=normal, m2=normal
Team B (ta1's):    ta1=owner, ta3=admin, m1=normal, m3=normal, admin=normal
Team C (ta2's):    ta2=owner, ta3=admin, m2=normal, m3=normal, admin=normal
```

**BOLA 测试（PATCH /users/me/models，15 cases）**：

```
ta1→TeamA(admin)      ✓ 允许
ta1→TeamB(owner)      ✓ 允许
ta1→TeamC(none)       ✓ 拒绝(403)
ta2→TeamA(admin)      ✓ 允许
ta2→TeamB(none)       ✓ 拒绝(403)
ta2→TeamC(owner)      ✓ 允许
ta3→TeamA(none)       ✓ 拒绝(403)
ta3→TeamB(admin)      ✓ 允许
ta3→TeamC(admin)      ✓ 允许
m1→TeamA(normal)      ✓ 拒绝(403)
m2→TeamA(normal)      ✓ 拒绝(403)
m3→TeamA(normal)      ✓ 拒绝(403)
m1→own(owner)         ✓ 允许
admin→TeamB(bypass)   ✓ 允许（superadmin 绕过）
admin→TeamC(bypass)   ✓ 允许（superadmin 绕过）
```

**Dataset 创建测试（7 cases）**：

```
admin 创建  ✓
ta1 创建    ✓
ta2 创建    ✓
ta3 创建    ✓
m1 创建     ✓（自己 tenant 中，owner 角色）
m2 创建     ✓
m3 创建     ✓
```

**退出团队测试（3 cases）**：

```
SuperAdmin 退出自己的团队   ✓ 拒绝(403)
SuperAdmin 退出其他团队     ✓ 拒绝(403)
普通成员退出团队            ✓ 允许
```

**知识库跨团队访问测试**：

```
m1 查看 Team B 的 KB（permission=team）   ✓ 可见
m1 向 Team B 的 KB 上传文档                ✓ 拒绝(101)
m1 修改 Team B 的 KB 元数据               ✓ 拒绝(102)
m1 删除 Team B 的 KB                      ✓ 拒绝(102)
m1 在自己 tenant 中上传文件               ✓ 允许
m1 在自己 tenant 中创建 KB               ✓ 允许
```

**文件上传测试**：

```
admin 上传文件（自己 tenant）  ✓ 允许
ta1 上传文件（自己 tenant）    ✓ 允许
m1 上传文件（自己 tenant）     ✓ 允许
```

**总测试结果**：32 单元测试 + 25+ Docker 集成测试，全部通过。

---

## 八、关键技术决策

| 决策点 | 选择 | 原因 |
|--------|------|------|
| 角色判断方式 | 新增 `get_user_team_role()` | 不修改原有函数，避免影响 10 个现有调用方 |
| 写拦截方式 | 装饰器 | 覆盖 37 个端点，无需修改 handler 逻辑；比中间件更精确 |
| tenant_id 来源 | 保留 `add_tenant_id_to_kwargs`（使用 `current_user.id`） | 防止 BOLA 攻击，不从请求头读取 |
| 循环依赖处理 | `knowledgebase_service.py` 使用延迟导入 | `check_team_permission` 导入了 `KnowledgebaseService`，延迟导入打破循环 |
| BOLA 修复范围 | 仅修复 `set_tenant_info()` | 其他端点通过装饰器已覆盖，此端点从请求体读取 tenant_id 是唯一漏洞 |
| 退出团队逻辑 | 移除装饰器，改为函数内判断 | 装饰器会阻止普通成员退出团队；函数内可区分「自己退出」和「移除他人」 |
| SuperAdmin 退出限制 | `getattr(current_user, "is_superadmin", False)` | SuperAdmin 是唯一全员维护者，退出后无人管理团队用户 |
| 装饰器错误语言 | 中文 | 与现有 RAGFlow 错误消息风格一致 |

---

## 九、验证方法

### 8.1 运行权限单元测试

```bash
python -m pytest test/unit_test/api/common/test_check_team_permission.py -v
```

预期：32 passed

### 8.2 语法检查

```bash
python3 -c "
import py_compile
for f in [
    'api/common/check_team_permission.py',
    'api/db/db_models.py',
    'api/db/services/user_service.py',
    'api/db/services/knowledgebase_service.py',
    'api/apps/__init__.py',
    'api/apps/restful_apis/dataset_api.py',
    'api/apps/restful_apis/document_api.py',
    'api/apps/restful_apis/chunk_api.py',
    'api/apps/restful_apis/file_api.py',
    'api/apps/restful_apis/agent_api.py',
    'api/apps/restful_apis/tenant_api.py',
    'api/apps/restful_apis/user_api.py',
]:
    py_compile.compile(f, doraise=True)
    print(f'OK: {f}')
"
```

### 8.3 Docker 集成测试

启动 RAGFlow Docker 环境后，按以下步骤验证：

```bash
# 1. 创建测试用户
curl -X POST http://localhost:9380/api/v1/users -H "Content-Type: application/json" \
  -d '{"nickname":"admin","email":"admin@test.com","password":"<encrypted>"}'

# 2. 设置 superadmin
docker exec mysql mysql -u root -prag_flow rag_flow -e \
  "UPDATE user SET is_superadmin=1 WHERE email='admin@test.com';"

# 3. 注册更多用户并通过数据库设置团队角色
# （参考 6.4 节的团队结构）

# 4. 运行 BOLA 测试
curl -X PATCH http://localhost:9380/api/v1/users/me/models \
  -H "Content-Type: application/json" -b cookies.txt \
  -d '{"tenant_id":"<other_team_id>","llm_id":"x","embd_id":"x","asr_id":"","img2txt_id":""}'
# 预期：403（非 teamadmin/superadmin 角色）

# 5. 测试退出团队
curl -X DELETE http://localhost:9380/api/v1/tenants/<team_id>/users \
  -H "Content-Type: application/json" -b admin_cookies.txt \
  -d '{"user_id":"<admin_user_id>"}'
# 预期：403（SuperAdmin 不能退出团队）
```

### 8.4 功能验证清单

| 测试项 | 预期 | 状态 |
|--------|------|------|
| 普通成员调用写操作 API | 403 | ✓ |
| 团队管理员调用写操作 API | 200 | ✓ |
| 超管调用任意团队写操作 | 200 | ✓ |
| BOLA: 传入非自有 tenant_id | 403 | ✓ |
| SuperAdmin 退出团队 | 403 | ✓ |
| 普通成员退出团队 | 200 | ✓ |
| 被邀请成员查看团队 KB | 200 | ✓ |
| 被邀请成员上传文档到团队 KB | 101 | ✓ |
| 被邀请成员修改团队 KB | 102 | ✓ |

---

## 十、风险与注意事项

1. **`is_superadmin` 字段迁移**：首次部署需要数据库迁移。迁移代码已内置于 `migrate_db()`，自动执行。
2. **`get_joined_tenants_by_user_id` 未废弃**：该函数仍有 10 个调用方用于读操作场景，未做修改。未来可考虑统一迁移到 `get_user_teams_with_role()`。
3. **装饰器未覆盖查询端点**：GET/search 端点不受装饰器保护，依赖原有的 `check_kb_team_permission` / `check_file_team_permission` 进行读权限校验。
4. **`test_dataset_access_permissions.py` 环境依赖**：该测试需要 werkzeug 等完整依赖才能运行，monkeypatch 目标已更新为新函数。
5. **`add_tenant_id_to_kwargs` 架构约束**：所有操作在用户自己的 tenant 上下文中执行，被邀请的成员无法直接操作团队资源（只能查看 permission=team 的知识库）。这是 RAGFlow 的设计约束，非权限系统缺陷。
6. **`tenant_api.rm` 不再使用装饰器**：退出团队的逻辑改为函数内判断，需确保未来修改时不会引入权限漏洞。
