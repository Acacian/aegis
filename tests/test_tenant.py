"""Tests for multi-tenant policy isolation system."""

from __future__ import annotations

import concurrent.futures
import threading
from dataclasses import dataclass
from datetime import UTC, datetime

import pytest

from aegis.core.tenant import (
    DEFAULT_QUOTAS,
    Tenant,
    TenantIsolation,
    TenantNotFoundError,
    TenantQuota,
    TenantQuotaEnforcer,
    TenantQuotaExceededError,
    TenantRegistry,
    TenantTier,
    clear_tenant,
    get_tenant,
    set_tenant,
    tenant_scope,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_tenant(
    tenant_id: str = "t1",
    name: str = "Acme Corp",
    tier: TenantTier = TenantTier.COMMUNITY,
) -> Tenant:
    return Tenant(tenant_id=tenant_id, name=name, tier=tier)


@dataclass
class _FakeDecision:
    """Minimal decision object returned by _FakePolicy."""

    allowed: bool
    rule: str


class _FakePolicy:
    """Duck-typed Policy stand-in for testing TenantIsolation."""

    def __init__(self, rule: str = "default_rule") -> None:
        self._rule = rule

    def evaluate(self, action: object) -> _FakeDecision:
        return _FakeDecision(allowed=True, rule=self._rule)


class _BlockingPolicy:
    """Policy that always blocks."""

    def evaluate(self, action: object) -> _FakeDecision:
        return _FakeDecision(allowed=False, rule="block_all")


@dataclass(frozen=True)
class _FakeAction:
    """Minimal action stand-in."""

    type: str = "read"
    target: str = "db"


# ===================================================================
# Tenant dataclass
# ===================================================================


class TestTenant:
    """Tests for the Tenant frozen dataclass."""

    def test_creation_defaults(self) -> None:
        t = Tenant(tenant_id="t1", name="Acme")
        assert t.tenant_id == "t1"
        assert t.name == "Acme"
        assert t.tier == TenantTier.COMMUNITY
        assert isinstance(t.created_at, datetime)
        assert t.metadata == {}

    def test_creation_all_fields(self) -> None:
        now = datetime.now(UTC)
        t = Tenant(
            tenant_id="t2",
            name="BigCo",
            tier=TenantTier.ENTERPRISE,
            created_at=now,
            metadata={"region": "eu-west-1"},
        )
        assert t.tier == TenantTier.ENTERPRISE
        assert t.created_at == now
        assert t.metadata["region"] == "eu-west-1"

    def test_frozen(self) -> None:
        t = _make_tenant()
        with pytest.raises(AttributeError):
            t.name = "Other"  # type: ignore[misc]

    def test_equality(self) -> None:
        now = datetime.now(UTC)
        a = Tenant("x", "X", TenantTier.PRO, now)
        b = Tenant("x", "X", TenantTier.PRO, now)
        assert a == b

    def test_different_ids_not_equal(self) -> None:
        assert _make_tenant("a") != _make_tenant("b")


# ===================================================================
# TenantTier enum
# ===================================================================


class TestTenantTier:
    def test_values(self) -> None:
        assert TenantTier.COMMUNITY.value == "community"
        assert TenantTier.PRO.value == "pro"
        assert TenantTier.ENTERPRISE.value == "enterprise"

    def test_str_enum(self) -> None:
        assert str(TenantTier.PRO) == "pro"


# ===================================================================
# TenantContext (contextvars)
# ===================================================================


class TestTenantContext:
    def test_default_is_none(self) -> None:
        clear_tenant()
        assert get_tenant() is None

    def test_set_and_get(self) -> None:
        t = _make_tenant()
        token = set_tenant(t)
        assert get_tenant() is t
        clear_tenant(token)

    def test_clear_with_token_restores(self) -> None:
        t1 = _make_tenant("t1")
        t2 = _make_tenant("t2")
        tok1 = set_tenant(t1)
        tok2 = set_tenant(t2)
        assert get_tenant() is t2
        clear_tenant(tok2)
        assert get_tenant() is t1
        clear_tenant(tok1)

    def test_clear_without_token(self) -> None:
        set_tenant(_make_tenant())
        clear_tenant()
        assert get_tenant() is None

    def test_tenant_scope_basic(self) -> None:
        clear_tenant()
        t = _make_tenant()
        with tenant_scope(t) as scoped:
            assert scoped is t
            assert get_tenant() is t
        assert get_tenant() is None

    def test_tenant_scope_restores_previous(self) -> None:
        t1 = _make_tenant("outer")
        t2 = _make_tenant("inner")
        token = set_tenant(t1)
        with tenant_scope(t2):
            assert get_tenant() is t2
        assert get_tenant() is t1
        clear_tenant(token)

    def test_tenant_scope_on_exception(self) -> None:
        clear_tenant()
        t = _make_tenant()
        with pytest.raises(RuntimeError), tenant_scope(t):
            assert get_tenant() is t
            raise RuntimeError("boom")
        assert get_tenant() is None

    def test_context_isolation_across_threads(self) -> None:
        """Each thread gets its own context variable copy."""
        clear_tenant()
        results: dict[str, str | None] = {}
        barrier = threading.Barrier(3)

        def worker(tid: str) -> None:
            t = _make_tenant(tid)
            with tenant_scope(t):
                barrier.wait(timeout=5)
                current = get_tenant()
                results[tid] = current.tenant_id if current else None

        threads = [threading.Thread(target=worker, args=(f"w{i}",)) for i in range(3)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=10)

        assert results == {"w0": "w0", "w1": "w1", "w2": "w2"}

    def test_nested_scopes(self) -> None:
        clear_tenant()
        t1 = _make_tenant("outer")
        t2 = _make_tenant("inner")
        with tenant_scope(t1):
            assert get_tenant() is t1
            with tenant_scope(t2):
                assert get_tenant() is t2
            assert get_tenant() is t1
        assert get_tenant() is None


# ===================================================================
# TenantRegistry
# ===================================================================


class TestTenantRegistry:
    def test_register_and_get(self) -> None:
        reg = TenantRegistry()
        t = _make_tenant()
        reg.register(t)
        assert reg.get("t1") is t

    def test_register_duplicate_raises(self) -> None:
        reg = TenantRegistry()
        reg.register(_make_tenant("dup"))
        with pytest.raises(ValueError, match="already exists"):
            reg.register(_make_tenant("dup"))

    def test_get_missing_returns_none(self) -> None:
        reg = TenantRegistry()
        assert reg.get("missing") is None

    def test_remove_existing(self) -> None:
        reg = TenantRegistry()
        reg.register(_make_tenant("r1"))
        assert reg.remove("r1") is True
        assert reg.get("r1") is None

    def test_remove_missing(self) -> None:
        reg = TenantRegistry()
        assert reg.remove("nope") is False

    def test_list_tenants(self) -> None:
        reg = TenantRegistry()
        reg.register(_make_tenant("a"))
        reg.register(_make_tenant("b"))
        ids = {t.tenant_id for t in reg.list_tenants()}
        assert ids == {"a", "b"}

    def test_get_or_create_new(self) -> None:
        reg = TenantRegistry()
        t = reg.get_or_create("new1", "New One", TenantTier.PRO)
        assert t.tenant_id == "new1"
        assert t.tier == TenantTier.PRO
        assert len(reg) == 1

    def test_get_or_create_existing(self) -> None:
        reg = TenantRegistry()
        t1 = reg.get_or_create("x", "X")
        t2 = reg.get_or_create("x", "Ignored")
        assert t1 is t2

    def test_len(self) -> None:
        reg = TenantRegistry()
        assert len(reg) == 0
        reg.register(_make_tenant("a"))
        assert len(reg) == 1

    def test_contains(self) -> None:
        reg = TenantRegistry()
        reg.register(_make_tenant("c1"))
        assert "c1" in reg
        assert "c2" not in reg

    def test_concurrent_register(self) -> None:
        """Concurrent registrations must not lose tenants."""
        reg = TenantRegistry()
        errors: list[str] = []

        def register_batch(start: int) -> None:
            for i in range(start, start + 50):
                try:
                    reg.register(_make_tenant(f"t{i}", f"Tenant {i}"))
                except ValueError:
                    errors.append(f"t{i}")

        with concurrent.futures.ThreadPoolExecutor(4) as pool:
            futures = [pool.submit(register_batch, s) for s in range(0, 200, 50)]
            for f in futures:
                f.result(timeout=10)

        assert len(reg) == 200
        assert not errors

    def test_concurrent_get_or_create(self) -> None:
        """get_or_create must be idempotent under contention."""
        reg = TenantRegistry()
        results: list[Tenant] = []
        lock = threading.Lock()

        def worker() -> None:
            t = reg.get_or_create("shared", "Shared")
            with lock:
                results.append(t)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=10)

        # All threads must get the same object.
        assert len({id(t) for t in results}) == 1


# ===================================================================
# TenantIsolation
# ===================================================================


class TestTenantIsolation:
    def test_set_and_get_policy(self) -> None:
        iso = TenantIsolation()
        pol = _FakePolicy("acme_rule")
        iso.set_tenant_policy("t1", pol)
        assert iso.get_tenant_policy("t1") is pol

    def test_get_missing_policy(self) -> None:
        iso = TenantIsolation()
        assert iso.get_tenant_policy("missing") is None

    def test_isolated_evaluate_tenant_policy(self) -> None:
        pol = _FakePolicy("tenant_rule")
        iso = TenantIsolation()
        iso.set_tenant_policy("t1", pol)
        dec = iso.isolated_evaluate(_FakeAction(), "t1")
        assert dec.rule == "tenant_rule"

    def test_isolated_evaluate_falls_back(self) -> None:
        default = _FakePolicy("fallback")
        iso = TenantIsolation(default_policy=default)
        dec = iso.isolated_evaluate(_FakeAction(), "t_no_policy")
        assert dec.rule == "fallback"

    def test_isolated_evaluate_no_policy_raises(self) -> None:
        iso = TenantIsolation()
        with pytest.raises(ValueError, match="No policy"):
            iso.isolated_evaluate(_FakeAction(), "orphan")

    def test_different_tenants_different_policies(self) -> None:
        iso = TenantIsolation()
        iso.set_tenant_policy("a", _FakePolicy("rule_a"))
        iso.set_tenant_policy("b", _BlockingPolicy())
        da = iso.isolated_evaluate(_FakeAction(), "a")
        db = iso.isolated_evaluate(_FakeAction(), "b")
        assert da.allowed is True
        assert db.allowed is False

    def test_audit_trail_scoped(self) -> None:
        iso = TenantIsolation(default_policy=_FakePolicy())
        iso.isolated_evaluate(_FakeAction(), "t1")
        iso.isolated_evaluate(_FakeAction(), "t2")
        iso.isolated_evaluate(_FakeAction(), "t1")
        assert len(iso.get_tenant_audit("t1")) == 2
        assert len(iso.get_tenant_audit("t2")) == 1

    def test_clear_tenant_audit(self) -> None:
        iso = TenantIsolation(default_policy=_FakePolicy())
        iso.isolated_evaluate(_FakeAction(), "t1")
        iso.clear_tenant_audit("t1")
        assert iso.get_tenant_audit("t1") == []

    def test_remove_tenant_policy(self) -> None:
        iso = TenantIsolation()
        iso.set_tenant_policy("t1", _FakePolicy())
        assert iso.remove_tenant_policy("t1") is True
        assert iso.get_tenant_policy("t1") is None

    def test_remove_missing_policy(self) -> None:
        iso = TenantIsolation()
        assert iso.remove_tenant_policy("nope") is False

    def test_tenant_ids_with_policies(self) -> None:
        iso = TenantIsolation()
        iso.set_tenant_policy("a", _FakePolicy())
        iso.set_tenant_policy("b", _FakePolicy())
        ids = set(iso.tenant_ids_with_policies())
        assert ids == {"a", "b"}

    def test_audit_entry_has_timestamp(self) -> None:
        iso = TenantIsolation(default_policy=_FakePolicy())
        iso.isolated_evaluate(_FakeAction(), "t1")
        entries = iso.get_tenant_audit("t1")
        assert "timestamp" in entries[0]

    def test_concurrent_evaluate(self) -> None:
        """Concurrent evaluations on different tenants."""
        iso = TenantIsolation(default_policy=_FakePolicy())
        errors: list[Exception] = []

        def work(tid: str) -> None:
            try:
                for _ in range(50):
                    iso.isolated_evaluate(_FakeAction(), tid)
            except Exception as exc:
                errors.append(exc)

        with concurrent.futures.ThreadPoolExecutor(4) as pool:
            futures = [pool.submit(work, f"t{i}") for i in range(4)]
            for f in futures:
                f.result(timeout=10)

        assert not errors
        for i in range(4):
            assert len(iso.get_tenant_audit(f"t{i}")) == 50


# ===================================================================
# TenantQuota
# ===================================================================


class TestTenantQuota:
    def test_defaults(self) -> None:
        q = TenantQuota()
        assert q.max_agents == 10
        assert q.max_actions_per_hour == 1000
        assert q.max_policies == 5

    def test_custom(self) -> None:
        q = TenantQuota(
            max_agents=100,
            max_actions_per_hour=9999,
            max_policies=50,
        )
        assert q.max_agents == 100

    def test_frozen(self) -> None:
        q = TenantQuota()
        with pytest.raises(AttributeError):
            q.max_agents = 999  # type: ignore[misc]

    def test_default_quotas_per_tier(self) -> None:
        assert DEFAULT_QUOTAS[TenantTier.COMMUNITY].max_agents == 5
        assert DEFAULT_QUOTAS[TenantTier.PRO].max_agents == 50
        assert DEFAULT_QUOTAS[TenantTier.ENTERPRISE].max_agents == 500


# ===================================================================
# TenantQuotaEnforcer
# ===================================================================


class TestTenantQuotaEnforcer:
    def test_no_quota_always_passes(self) -> None:
        enf = TenantQuotaEnforcer()
        assert enf.check_agents("t1") is True
        assert enf.check_actions("t1") is True
        assert enf.check_policies("t1") is True

    def test_under_limit(self) -> None:
        enf = TenantQuotaEnforcer()
        enf.set_quota("t1", TenantQuota(max_agents=3))
        enf.set_agent_count("t1", 2)
        assert enf.check_agents("t1") is True

    def test_at_limit(self) -> None:
        enf = TenantQuotaEnforcer()
        enf.set_quota("t1", TenantQuota(max_agents=3))
        enf.set_agent_count("t1", 3)
        assert enf.check_agents("t1") is False

    def test_over_limit(self) -> None:
        enf = TenantQuotaEnforcer()
        enf.set_quota("t1", TenantQuota(max_agents=3))
        enf.set_agent_count("t1", 5)
        assert enf.check_agents("t1") is False

    def test_actions_limit(self) -> None:
        enf = TenantQuotaEnforcer()
        enf.set_quota("t1", TenantQuota(max_actions_per_hour=100))
        enf.set_action_count("t1", 100)
        assert enf.check_actions("t1") is False

    def test_policies_limit(self) -> None:
        enf = TenantQuotaEnforcer()
        enf.set_quota("t1", TenantQuota(max_policies=2))
        enf.set_policy_count("t1", 2)
        assert enf.check_policies("t1") is False

    def test_check_all(self) -> None:
        enf = TenantQuotaEnforcer()
        enf.set_quota(
            "t1",
            TenantQuota(
                max_agents=2,
                max_actions_per_hour=10,
                max_policies=1,
            ),
        )
        enf.set_agent_count("t1", 1)
        enf.set_action_count("t1", 10)
        enf.set_policy_count("t1", 0)
        result = enf.check_all("t1")
        assert result["agents"] is True
        assert result["actions"] is False
        assert result["policies"] is True

    def test_check_all_no_quota(self) -> None:
        enf = TenantQuotaEnforcer()
        result = enf.check_all("t1")
        assert all(result.values())

    def test_enforce_or_raise_passes(self) -> None:
        enf = TenantQuotaEnforcer()
        enf.set_quota("t1", TenantQuota(max_agents=10))
        enf.set_agent_count("t1", 5)
        enf.enforce_or_raise("t1", "agents")  # no exception

    def test_enforce_or_raise_exceeds(self) -> None:
        enf = TenantQuotaEnforcer()
        enf.set_quota("t1", TenantQuota(max_agents=2))
        enf.set_agent_count("t1", 5)
        with pytest.raises(TenantQuotaExceededError, match="agents"):
            enf.enforce_or_raise("t1", "agents")

    def test_enforce_or_raise_bad_resource(self) -> None:
        enf = TenantQuotaEnforcer()
        with pytest.raises(ValueError, match="Unknown resource"):
            enf.enforce_or_raise("t1", "widgets")

    def test_increment_action_count(self) -> None:
        enf = TenantQuotaEnforcer()
        assert enf.increment_action_count("t1") == 1
        assert enf.increment_action_count("t1") == 2
        assert enf.increment_action_count("t1", 3) == 5

    def test_reset_action_count(self) -> None:
        enf = TenantQuotaEnforcer()
        enf.set_action_count("t1", 100)
        enf.reset_action_count("t1")
        assert enf.check_actions("t1") is True

    def test_set_quota_from_tier(self) -> None:
        enf = TenantQuotaEnforcer()
        q = enf.set_quota_from_tier("t1", TenantTier.PRO)
        assert q.max_agents == 50
        assert enf.get_quota("t1") is q

    def test_get_usage(self) -> None:
        enf = TenantQuotaEnforcer()
        enf.set_quota("t1", TenantQuota(max_agents=5))
        enf.set_agent_count("t1", 3)
        usage = enf.get_usage("t1")
        assert usage["tenant_id"] == "t1"
        assert usage["agents"] == 3

    def test_concurrent_increment(self) -> None:
        """Concurrent increments must not lose counts."""
        enf = TenantQuotaEnforcer()
        n_threads = 8
        n_per_thread = 100

        def worker() -> None:
            for _ in range(n_per_thread):
                enf.increment_action_count("t1")

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=10)

        usage = enf.get_usage("t1")
        assert usage["actions"] == n_threads * n_per_thread


# ===================================================================
# Exception classes
# ===================================================================


class TestExceptions:
    def test_quota_exceeded_message(self) -> None:
        err = TenantQuotaExceededError("t1", "agents", TenantQuota(max_agents=5))
        assert "t1" in str(err)
        assert "agents" in str(err)
        assert "5" in str(err)

    def test_quota_exceeded_none_quota(self) -> None:
        err = TenantQuotaExceededError("t1", "agents", None)
        assert "unknown" in str(err)

    def test_tenant_not_found(self) -> None:
        err = TenantNotFoundError("missing_id")
        assert "missing_id" in str(err)
        assert err.tenant_id == "missing_id"
