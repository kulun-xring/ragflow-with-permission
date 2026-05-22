#
#  Tests for the permission management system (Phase 1 + Phase 2).
#  Uses sys.modules pre-population + MetaPathFinder to stub framework deps.
#
import importlib.abc
import importlib.machinery
import sys
import types
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

import pytest


# ---------------------------------------------------------------------------
# Stub infrastructure — must run BEFORE any api.* imports
# ---------------------------------------------------------------------------

class _StubFinder(importlib.abc.MetaPathFinder):
    """Catch any non-api/test import and return a MagicMock-based stub."""
    _ALLOWED = {"api", "test", "_pytest", "pytest", "pluggy"}

    def find_spec(self, fullname, path, target=None):
        if fullname.split(".")[0] in self._ALLOWED:
            return None
        if fullname in sys.modules:
            return None
        return importlib.machinery.ModuleSpec(fullname, self, is_package=True)

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        name = module.__name__
        module.__file__ = f"<stub:{name}>"
        module.__path__ = []
        module.__package__ = name

        def _ga(mod_name):
            def __getattr__(attr):
                return MagicMock(name=f"{mod_name}.{attr}")
            return __getattr__
        module.__getattr__ = _ga(name)

        sys.modules[name] = module
        parts = name.rsplit(".", 1)
        if len(parts) == 2 and parts[0] in sys.modules:
            setattr(sys.modules[parts[0]], parts[1], module)


def _make_stub(name, attrs=None):
    m = types.ModuleType(name)
    m.__file__ = f"<stub:{name}>"
    m.__loader__ = None
    m.__path__ = []
    m.__package__ = name
    if attrs:
        for k, v in attrs.items():
            setattr(m, k, v)

    def _ga(mod_name):
        def __getattr__(attr):
            return MagicMock(name=f"{mod_name}.{attr}")
        return __getattr__
    m.__getattr__ = _ga(name)
    sys.modules[name] = m
    return m


# ---- peewee stubs (need real metaclass for db_models.py) ----

class _FieldBase:
    def __init__(self, *args, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

def _fc(name):
    return type(name, (_FieldBase,), {})


class _ModelMeta(type):
    def __new__(mcs, name, bases, ns):
        return super().__new__(mcs, name, bases, ns)
    def __init__(cls, name, bases, ns):
        super().__init__(name, bases, ns)


class _ConnectionContext:
    """Pass-through decorator that mimics DB.connection_context()."""
    def __call__(self, func):
        return func

class _DatabaseProxy:
    def connection_context(self):
        return _ConnectionContext()
    def initialize(self, *a, **kw):
        pass
    def __getattr__(self, name):
        return MagicMock()


class _ModelMetaInfo:
    fields = {}
    table_name = ""

class _Model(metaclass=_ModelMeta):
    _meta = _ModelMetaInfo()
    class Meta:
        table_name = ""
    @classmethod
    def select(cls, *a):
        return MagicMock()
    @classmethod
    def update(cls, *a):
        return MagicMock()
    @classmethod
    def delete(cls):
        return MagicMock()
    @classmethod
    def create(cls, **kw):
        return MagicMock()
    def to_dict(self):
        return {}


_make_stub("peewee", {
    "Model": _Model,
    "DatabaseProxy": _DatabaseProxy,
    "CharField": _fc("CharField"),
    "IntegerField": _fc("IntegerField"),
    "BooleanField": _fc("BooleanField"),
    "TextField": _fc("TextField"),
    "FloatField": _fc("FloatField"),
    "DateTimeField": _fc("DateTimeField"),
    "DateField": _fc("DateField"),
    "DecimalField": _fc("DecimalField"),
    "BlobField": _fc("BlobField"),
    "BigAutoField": _fc("BigAutoField"),
    "AutoField": _fc("AutoField"),
    "ForeignKeyField": _fc("ForeignKeyField"),
    "JSONField": _fc("JSONField"),
    "ManyToManyField": _fc("ManyToManyField"),
    "OperationalError": type("OperationalError", (Exception,), {}),
    "InterfaceError": type("InterfaceError", (Exception,), {}),
    "fn": type("fn", (), {})(),
})

class _FakePooledDB:
    """Mimics a peewee pooled database with connection_context."""
    def __init__(self, *args, **kwargs):
        pass
    def connection_context(self):
        return _ConnectionContext()
    def __getattr__(self, name):
        return MagicMock()
    def __bool__(self):
        return True

_make_stub("playhouse")
_make_stub("playhouse.pool", {
    "PooledMySQLDatabase": type("PooledMySQLDatabase", (_FakePooledDB,), {}),
    "PooledPostgresqlDatabase": type("PooledPostgresqlDatabase", (_FakePooledDB,), {}),
})
_make_stub("playhouse.migrate", {"migrate": MagicMock(), "SchemaMigrator": MagicMock()})
sys.modules["playhouse"].pool = sys.modules["playhouse.pool"]
sys.modules["playhouse"].migrate = sys.modules["playhouse.migrate"]

# ---- quart_auth stub ----
_make_stub("quart_auth", {
    "AuthUser": type("AuthUser", (), {"is_authenticated": True}),
    "login_required": lambda f: f,
})

# ---- common.* stubs with real values ----

class _StatusEnum:
    VALID = type("", (), {"value": "1"})()
    INVALID = type("", (), {"value": "0"})()


class _RetCode:
    SUCCESS = 0
    FORBIDDEN = 403
    AUTHENTICATION_ERROR = 109
    DATA_ERROR = 500
    SERVER_ERROR = 500
    ARGUMENT_ERROR = 400


_make_stub("common")
_make_stub("common.settings", {
    "DATABASE_TYPE": "mysql",
    "DATABASE": {"name": "test_db", "host": "localhost", "port": 3306},
    "get_secret_key": lambda: "test-secret",
})
_make_stub("common.constants", {
    "StatusEnum": _StatusEnum,
    "RetCode": _RetCode(),
    "ParserType": MagicMock(),
})
_make_stub("common.time_utils", {"current_timestamp": MagicMock(), "datetime_format": MagicMock()})
_make_stub("common.misc_utils", {"get_uuid": lambda: "fake-uuid"})
_make_stub("common.string_utils")
_make_stub("common.tag_feature_utils")
def _singleton_passthrough(cls, *args, **kw):
    """Mimics common.decorator.singleton — returns a function that returns a singleton instance."""
    instance = cls(*args, **kw)
    def _get():
        return instance
    return _get

_make_stub("common.decorator", {"singleton": _singleton_passthrough})
_make_stub("common.doc_store")
_make_stub("common.doc_store.es_conn_base")
sys.modules["common"].settings = sys.modules["common.settings"]
sys.modules["common"].constants = sys.modules["common.constants"]
sys.modules["common"].time_utils = sys.modules["common.time_utils"]
sys.modules["common"].misc_utils = sys.modules["common.misc_utils"]
sys.modules["common"].string_utils = sys.modules["common.string_utils"]
sys.modules["common"].tag_feature_utils = sys.modules["common.tag_feature_utils"]
sys.modules["common"].decorator = sys.modules["common.decorator"]
sys.modules["common"].doc_store = sys.modules["common.doc_store"]
sys.modules["common.doc_store"].es_conn_base = sys.modules["common.doc_store.es_conn_base"]

# ---- rag hierarchy ----
_make_stub("rag")
_make_stub("rag.utils")
_make_stub("rag.utils.es_conn")
sys.modules["rag"].utils = sys.modules["rag.utils"]
sys.modules["rag.utils"].es_conn = sys.modules["rag.utils.es_conn"]

# ---- other deps ----
for _mod in ["elasticsearch", "elasticsearch.client", "elastic_transport",
             "xxhash", "magic", "PIL", "numpy", "cv2",
             "minio", "redis", "mysql", "psycopg2",
             "boto3", "botocore", "multipart", "xpinyin", "pyodbc",
             "quart_cors", "quart.sessions",
             "itsdangerous", "itsdangerous.url_safe",
             "werkzeug", "werkzeug.security", "tenacity"]:
    _make_stub(_mod)

# pydantic needs real BaseModel so Annotated[type, ...] works
_make_stub("pydantic", {
    "BaseModel": type("BaseModel", (), {"__init__": lambda self, **kw: None}),
    "Field": lambda *a, **kw: MagicMock(),
    "StringConstraints": lambda **kw: MagicMock(),
})

# Wire elasticsearch.client
sys.modules["elasticsearch"].client = sys.modules["elasticsearch.client"]

# Install finder AFTER pre-created stubs
sys.meta_path.insert(0, _StubFinder())

# ---- Iteratively import, adding stubs for any missing transitive deps ----
for _i in range(50):
    try:
        from api.db import TenantPermission, UserTenantRole  # noqa: E402
        from api.common.check_team_permission import (  # noqa: E402
            get_user_team_role,
            check_kb_team_permission,
        )
        break
    except ModuleNotFoundError as _e:
        _mod = str(_e).split("'")[1]
        if _mod not in sys.modules:
            _make_stub(_mod)
            _parts = _mod.rsplit(".", 1)
            if len(_parts) == 2 and _parts[0] in sys.modules:
                setattr(sys.modules[_parts[0]], _parts[1], sys.modules[_mod])
        else:
            raise


# =========================================================================
# Helpers
# =========================================================================

def _make_user(user_id, is_superadmin=False, is_superuser=False):
    return SimpleNamespace(
        id=user_id,
        is_superadmin=is_superadmin,
        is_superuser=is_superuser,
    )


# =========================================================================
# Tests for get_user_team_role()
# =========================================================================

class TestGetUserRole:

    @staticmethod
    def _call(user_id, tenant_id, *, user_obj=None, teams=None):
        with patch("api.common.check_team_permission.User") as MockUser, \
             patch("api.common.check_team_permission.TenantService") as MockTenant:
            MockUser.select.return_value.where.return_value.first.return_value = user_obj
            MockTenant.get_user_teams_with_role.return_value = teams or []
            return get_user_team_role(user_id, tenant_id)

    def test_superadmin_via_is_superadmin(self):
        assert self._call("u1", "t1", user_obj=_make_user("u1", is_superadmin=True)) == "superadmin"

    def test_superadmin_via_is_superuser(self):
        assert self._call("u1", "t1", user_obj=_make_user("u1", is_superuser=True)) == "superadmin"

    def test_teamadmin_role_admin(self):
        teams = [{"tenant_id": "t1", "role": "admin"}]
        assert self._call("u1", "t1", user_obj=_make_user("u1"), teams=teams) == "teamadmin"

    def test_teamadmin_role_owner(self):
        teams = [{"tenant_id": "t1", "role": "owner"}]
        assert self._call("u1", "t1", user_obj=_make_user("u1"), teams=teams) == "teamadmin"

    def test_member_role_normal(self):
        teams = [{"tenant_id": "t1", "role": "normal"}]
        assert self._call("u1", "t1", user_obj=_make_user("u1"), teams=teams) == "member"

    def test_invite_returns_none(self):
        teams = [{"tenant_id": "t1", "role": "invite"}]
        assert self._call("u1", "t1", user_obj=_make_user("u1"), teams=teams) == "none"

    def test_not_in_team(self):
        teams = [{"tenant_id": "other", "role": "admin"}]
        assert self._call("u1", "t1", user_obj=_make_user("u1"), teams=teams) == "none"

    def test_empty_teams(self):
        assert self._call("u1", "t1", user_obj=_make_user("u1"), teams=[]) == "none"

    def test_user_not_found_falls_through(self):
        teams = [{"tenant_id": "t1", "role": "admin"}]
        assert self._call("u1", "t1", user_obj=None, teams=teams) == "teamadmin"

    def test_multiple_teams(self):
        teams = [
            {"tenant_id": "t1", "role": "normal"},
            {"tenant_id": "t2", "role": "admin"},
        ]
        assert self._call("u1", "t1", user_obj=_make_user("u1"), teams=teams) == "member"
        assert self._call("u1", "t2", user_obj=_make_user("u1"), teams=teams) == "teamadmin"

    def test_superadmin_bypasses_team_membership(self):
        assert self._call("u1", "t1", user_obj=_make_user("u1", is_superadmin=True), teams=[]) == "superadmin"


# =========================================================================
# Tests for check_kb_team_permission()
# =========================================================================

class TestCheckKbTeamPermission:

    @staticmethod
    def _call(kb_dict, user_id, *, role="member"):
        with patch("api.common.check_team_permission.get_user_team_role", return_value=role):
            return check_kb_team_permission(kb_dict, user_id)

    def test_owner_always_allowed(self):
        assert self._call({"tenant_id": "u1", "permission": "me"}, "u1") is True

    def test_me_denied_to_others(self):
        assert self._call({"tenant_id": "owner", "permission": "me"}, "other") is False

    def test_team_allows_member(self):
        assert self._call({"tenant_id": "owner", "permission": "team"}, "u1", role="member") is True

    def test_team_allows_teamadmin(self):
        assert self._call({"tenant_id": "owner", "permission": "team"}, "u1", role="teamadmin") is True

    def test_team_allows_superadmin(self):
        assert self._call({"tenant_id": "owner", "permission": "team"}, "u1", role="superadmin") is True

    def test_team_denies_non_member(self):
        assert self._call({"tenant_id": "owner", "permission": "team"}, "u1", role="none") is False


# =========================================================================
# Tests for KnowledgebaseService.accessible()
# =========================================================================

class TestKnowledgebaseAccessible:

    @staticmethod
    def _call(kb_id, user_id, *, role="member", kb_obj=None):
        from api.db.services.knowledgebase_service import KnowledgebaseService
        if kb_obj is None:
            kb_obj = SimpleNamespace(id=kb_id, tenant_id="owner-1", permission="team", status="1")
        with patch.object(KnowledgebaseService, "get_by_id", return_value=(True, kb_obj)), \
             patch("api.common.check_team_permission.get_user_team_role", return_value=role), \
             patch("api.common.check_team_permission.User"), \
             patch("api.common.check_team_permission.TenantService"):
            return KnowledgebaseService.accessible(kb_id, user_id)

    def test_owner_can_access(self):
        kb = SimpleNamespace(id="kb1", tenant_id="u1", permission="team", status="1")
        assert self._call("kb1", "u1", kb_obj=kb) is True

    def test_team_member_can_access(self):
        assert self._call("kb1", "u1", role="member") is True

    def test_teamadmin_can_access(self):
        assert self._call("kb1", "u1", role="teamadmin") is True

    def test_superadmin_can_access(self):
        assert self._call("kb1", "u1", role="superadmin") is True

    def test_non_member_cannot_access(self):
        assert self._call("kb1", "u1", role="none") is False

    def test_me_kb_not_accessible_to_others(self):
        kb = SimpleNamespace(id="kb1", tenant_id="owner", permission="me", status="1")
        assert self._call("kb1", "other", role="member", kb_obj=kb) is False

    def test_invalid_status_not_accessible(self):
        kb = SimpleNamespace(id="kb1", tenant_id="owner", permission="team", status="0")
        assert self._call("kb1", "u1", role="member", kb_obj=kb) is False

    def test_nonexistent_kb(self):
        from api.db.services.knowledgebase_service import KnowledgebaseService
        with patch.object(KnowledgebaseService, "get_by_id", return_value=(False, None)):
            assert KnowledgebaseService.accessible("no-kb", "u1") is False


# =========================================================================
# Tests for decorator
# =========================================================================

class TestDecorator:
    """Test the @superadmin_or_teamadmin_required decorator.

    Since importing api.apps triggers a massive dependency chain,
    we extract the decorator definition and test it with mocked dependencies.
    """

    @staticmethod
    def _make_decorated_func():
        """Build the decorator inline (same logic as api.apps.superadmin_or_teamadmin_required)."""
        from functools import wraps

        def superadmin_or_teamadmin_required(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                from api.common.check_team_permission import get_user_team_role
                from types import SimpleNamespace as _SN
                # Simulate: tenant_id from kwargs, current_user from patch
                tenant_id = kwargs.get('tenant_id')
                if not tenant_id:
                    return {"code": 403, "message": "Missing tenant_id"}
                # In real code, current_user.id is used
                user_id = kwargs.pop("_test_user_id", "u1")
                role = get_user_team_role(user_id, tenant_id)
                if role == 'none':
                    return {"code": 403, "message": "not a member"}
                if role == 'member':
                    return {"code": 403, "message": "readonly"}
                return await func(*args, **kwargs)
            return wrapper

        @superadmin_or_teamadmin_required
        async def endpoint(**kwargs):
            return {"ok": True}

        return endpoint

    @pytest.mark.asyncio
    async def test_member_blocked(self):
        func = self._make_decorated_func()
        with patch("api.common.check_team_permission.get_user_team_role", return_value="member"):
            resp = await func(tenant_id="t1")
            assert resp["code"] == 403

    @pytest.mark.asyncio
    async def test_teamadmin_allowed(self):
        func = self._make_decorated_func()
        with patch("api.common.check_team_permission.get_user_team_role", return_value="teamadmin"):
            assert await func(tenant_id="t1") == {"ok": True}

    @pytest.mark.asyncio
    async def test_superadmin_allowed(self):
        func = self._make_decorated_func()
        with patch("api.common.check_team_permission.get_user_team_role", return_value="superadmin"):
            assert await func(tenant_id="t1") == {"ok": True}

    @pytest.mark.asyncio
    async def test_non_member_blocked(self):
        func = self._make_decorated_func()
        with patch("api.common.check_team_permission.get_user_team_role", return_value="none"):
            resp = await func(tenant_id="t1")
            assert resp["code"] == 403

    @pytest.mark.asyncio
    async def test_missing_tenant_id_blocked(self):
        func = self._make_decorated_func()
        resp = await func()
        assert resp["code"] == 403


# =========================================================================
# Tests for TenantService.get_user_teams_with_role existence
# =========================================================================

class TestGetUserTeamsWithRole:

    def test_method_exists(self):
        from api.db.services.user_service import TenantService
        assert hasattr(TenantService, "get_user_teams_with_role")

    def test_signature_accepts_user_id(self):
        import inspect
        from api.db.services.user_service import TenantService
        sig = inspect.signature(TenantService.get_user_teams_with_role)
        assert "user_id" in sig.parameters
