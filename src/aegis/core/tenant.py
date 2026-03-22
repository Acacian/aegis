"""Multi-tenant policy isolation for enterprise deployments.

Provides namespace isolation so each tenant (org/team) gets its own
policy, audit, and rate-limit scope.  Prevents cross-tenant data
leakage in SaaS deployments.

Thread-safe: :class:`TenantRegistry` uses a lock for all mutations.
Context propagation uses :mod:`contextvars` for async-safe scoping.
"""

from __future__ import annotations

import threading
from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

# ---------------------------------------------------------------------------
# Tier enum
# ---------------------------------------------------------------------------


class TenantTier(StrEnum):
    """Pricing / capability tier for a tenant."""

    COMMUNITY = "community"
    PRO = "pro"
    ENTERPRISE = "enterprise"


# ---------------------------------------------------------------------------
# Tenant dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Tenant:
    """Immutable descriptor for a single tenant (org / team).

    Attributes:
        tenant_id: Globally unique identifier.
        name: Human-readable display name.
        tier: Pricing tier that controls feature access.
        created_at: When the tenant was provisioned.
        metadata: Arbitrary key-value pairs for integrations.
    """

    tenant_id: str
    name: str
    tier: TenantTier = TenantTier.COMMUNITY
    created_at: datetime = field(
        default_factory=lambda: datetime.now(UTC),
    )
    metadata: dict[str, object] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Quota dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TenantQuota:
    """Resource limits for a tenant.

    Attributes:
        max_agents: Maximum concurrent agents.
        max_actions_per_hour: Throughput cap (0 = unlimited).
        max_policies: Maximum number of policies.
    """

    max_agents: int = 10
    max_actions_per_hour: int = 1000
    max_policies: int = 5


# Default quotas per tier.
DEFAULT_QUOTAS: dict[TenantTier, TenantQuota] = {
    TenantTier.COMMUNITY: TenantQuota(
        max_agents=5,
        max_actions_per_hour=500,
        max_policies=3,
    ),
    TenantTier.PRO: TenantQuota(
        max_agents=50,
        max_actions_per_hour=5000,
        max_policies=20,
    ),
    TenantTier.ENTERPRISE: TenantQuota(
        max_agents=500,
        max_actions_per_hour=50000,
        max_policies=200,
    ),
}

# ---------------------------------------------------------------------------
# Context variable for tenant propagation
# ---------------------------------------------------------------------------

_current_tenant: ContextVar[Tenant | None] = ContextVar(
    "current_tenant",
    default=None,
)


def set_tenant(tenant: Tenant) -> Token[Tenant | None]:
    """Set the current tenant for this context.

    Returns a token that can be used with ``clear_tenant`` to restore
    the previous value.
    """
    return _current_tenant.set(tenant)


def get_tenant() -> Tenant | None:
    """Return the current tenant, or ``None`` if not set."""
    return _current_tenant.get()


def clear_tenant(token: Token[Tenant | None] | None = None) -> None:
    """Clear (or restore) the current tenant.

    When *token* is provided the context variable is reset to its
    previous value.  Otherwise it is set to ``None``.
    """
    if token is not None:
        _current_tenant.reset(token)
    else:
        _current_tenant.set(None)


@contextmanager
def tenant_scope(
    tenant: Tenant,
) -> Generator[Tenant, None, None]:
    """Context manager that sets the active tenant for a block.

    The previous tenant (if any) is restored on exit, even if an
    exception is raised::

        with tenant_scope(acme):
            assert get_tenant() == acme
        assert get_tenant() is None  # restored
    """
    token = set_tenant(tenant)
    try:
        yield tenant
    finally:
        clear_tenant(token)


# ---------------------------------------------------------------------------
# Duck-typed protocol for Policy (avoids circular import)
# ---------------------------------------------------------------------------


class _PolicyLike(Protocol):
    """Minimal interface used by :class:`TenantIsolation`."""

    def evaluate(self, action: Any) -> Any: ...


# ---------------------------------------------------------------------------
# Tenant Registry (thread-safe)
# ---------------------------------------------------------------------------


class TenantRegistry:
    """Thread-safe registry of tenants.

    All mutating operations are serialised via an internal lock.
    Read operations are also guarded to ensure a consistent snapshot.
    """

    def __init__(self) -> None:
        self._tenants: dict[str, Tenant] = {}
        self._lock = threading.Lock()

    # -- CRUD ---------------------------------------------------------------

    def register(self, tenant: Tenant) -> None:
        """Register a new tenant.

        Raises:
            ValueError: If a tenant with the same id already exists.
        """
        with self._lock:
            if tenant.tenant_id in self._tenants:
                raise ValueError(f"Tenant '{tenant.tenant_id}' already exists")
            self._tenants[tenant.tenant_id] = tenant

    def get(self, tenant_id: str) -> Tenant | None:
        """Return the tenant with *tenant_id*, or ``None``."""
        with self._lock:
            return self._tenants.get(tenant_id)

    def remove(self, tenant_id: str) -> bool:
        """Remove a tenant.  Returns ``True`` if it existed."""
        with self._lock:
            return self._tenants.pop(tenant_id, None) is not None

    def list_tenants(self) -> list[Tenant]:
        """Return a snapshot of all registered tenants."""
        with self._lock:
            return list(self._tenants.values())

    def get_or_create(
        self,
        tenant_id: str,
        name: str,
        tier: TenantTier = TenantTier.COMMUNITY,
    ) -> Tenant:
        """Return existing tenant or create a new one (idempotent)."""
        with self._lock:
            existing = self._tenants.get(tenant_id)
            if existing is not None:
                return existing
            tenant = Tenant(
                tenant_id=tenant_id,
                name=name,
                tier=tier,
            )
            self._tenants[tenant_id] = tenant
            return tenant

    def __len__(self) -> int:
        with self._lock:
            return len(self._tenants)

    def __contains__(self, tenant_id: str) -> bool:
        with self._lock:
            return tenant_id in self._tenants


# ---------------------------------------------------------------------------
# Tenant Isolation — scoped policy / audit routing
# ---------------------------------------------------------------------------


class TenantIsolation:
    """Decorates policy evaluation with per-tenant scoping.

    Each tenant can have its own policy.  When no tenant-specific
    policy is set the *default_policy* is used as a fallback.

    Audit entries returned by :meth:`get_tenant_audit` are filtered
    by ``tenant_id``.
    """

    def __init__(
        self,
        default_policy: _PolicyLike | None = None,
    ) -> None:
        self._default_policy = default_policy
        self._policies: dict[str, _PolicyLike] = {}
        self._audit: dict[str, list[dict[str, object]]] = {}
        self._lock = threading.Lock()

    # -- policy routing -----------------------------------------------------

    def set_tenant_policy(
        self,
        tenant_id: str,
        policy: _PolicyLike,
    ) -> None:
        """Assign a policy to *tenant_id*."""
        with self._lock:
            self._policies[tenant_id] = policy

    def get_tenant_policy(
        self,
        tenant_id: str,
    ) -> _PolicyLike | None:
        """Return the policy for *tenant_id* (or ``None``)."""
        with self._lock:
            return self._policies.get(tenant_id)

    def remove_tenant_policy(self, tenant_id: str) -> bool:
        """Remove tenant-specific policy.  Returns ``True`` if found."""
        with self._lock:
            return self._policies.pop(tenant_id, None) is not None

    def isolated_evaluate(
        self,
        action: Any,
        tenant_id: str,
    ) -> Any:
        """Evaluate *action* against the tenant's policy.

        Falls back to the default policy when no tenant-specific
        policy is registered.

        Raises:
            ValueError: If neither a tenant policy nor a default
                policy is available.
        """
        with self._lock:
            policy = self._policies.get(tenant_id)
        if policy is None:
            policy = self._default_policy
        if policy is None:
            raise ValueError(
                f"No policy for tenant '{tenant_id}' and no default policy configured"
            )
        decision = policy.evaluate(action)
        # Record to tenant-scoped audit trail.
        entry: dict[str, object] = {
            "tenant_id": tenant_id,
            "action": str(action),
            "decision": str(decision),
            "timestamp": datetime.now(UTC).isoformat(),
        }
        with self._lock:
            self._audit.setdefault(tenant_id, []).append(entry)
        return decision

    # -- audit queries ------------------------------------------------------

    def get_tenant_audit(
        self,
        tenant_id: str,
    ) -> list[dict[str, object]]:
        """Return audit entries scoped to *tenant_id*."""
        with self._lock:
            return list(self._audit.get(tenant_id, []))

    def clear_tenant_audit(self, tenant_id: str) -> None:
        """Remove all audit entries for *tenant_id*."""
        with self._lock:
            self._audit.pop(tenant_id, None)

    def tenant_ids_with_policies(self) -> list[str]:
        """Return tenant ids that have a custom policy."""
        with self._lock:
            return list(self._policies.keys())


# ---------------------------------------------------------------------------
# Quota Enforcer
# ---------------------------------------------------------------------------


class TenantQuotaEnforcer:
    """Enforces resource quotas for tenants.

    Tracks current usage and checks against :class:`TenantQuota`
    limits.  All state is in-memory (suitable for single-process
    deployments or as a local cache ahead of a distributed backend).
    """

    def __init__(self) -> None:
        self._quotas: dict[str, TenantQuota] = {}
        self._agent_counts: dict[str, int] = {}
        self._action_counts: dict[str, int] = {}
        self._policy_counts: dict[str, int] = {}
        self._lock = threading.Lock()

    # -- quota management ---------------------------------------------------

    def set_quota(
        self,
        tenant_id: str,
        quota: TenantQuota,
    ) -> None:
        """Assign a quota to *tenant_id*."""
        with self._lock:
            self._quotas[tenant_id] = quota

    def get_quota(self, tenant_id: str) -> TenantQuota | None:
        """Return the quota for *tenant_id* (or ``None``)."""
        with self._lock:
            return self._quotas.get(tenant_id)

    def set_quota_from_tier(
        self,
        tenant_id: str,
        tier: TenantTier,
    ) -> TenantQuota:
        """Set quota from default tier values.  Returns the quota."""
        quota = DEFAULT_QUOTAS[tier]
        self.set_quota(tenant_id, quota)
        return quota

    # -- usage tracking -----------------------------------------------------

    def set_agent_count(
        self,
        tenant_id: str,
        count: int,
    ) -> None:
        """Set the current agent count for *tenant_id*."""
        with self._lock:
            self._agent_counts[tenant_id] = count

    def set_action_count(
        self,
        tenant_id: str,
        count: int,
    ) -> None:
        """Set the current hourly action count for *tenant_id*."""
        with self._lock:
            self._action_counts[tenant_id] = count

    def set_policy_count(
        self,
        tenant_id: str,
        count: int,
    ) -> None:
        """Set the current policy count for *tenant_id*."""
        with self._lock:
            self._policy_counts[tenant_id] = count

    def increment_action_count(
        self,
        tenant_id: str,
        delta: int = 1,
    ) -> int:
        """Atomically increment actions and return new count."""
        with self._lock:
            current = self._action_counts.get(tenant_id, 0)
            new = current + delta
            self._action_counts[tenant_id] = new
            return new

    def reset_action_count(self, tenant_id: str) -> None:
        """Reset the hourly action counter for *tenant_id*."""
        with self._lock:
            self._action_counts.pop(tenant_id, None)

    # -- enforcement checks -------------------------------------------------

    def check_agents(self, tenant_id: str) -> bool:
        """Return ``True`` if agent quota is not exceeded."""
        with self._lock:
            quota = self._quotas.get(tenant_id)
            if quota is None:
                return True
            count = self._agent_counts.get(tenant_id, 0)
            return count < quota.max_agents

    def check_actions(self, tenant_id: str) -> bool:
        """Return ``True`` if hourly action quota is not exceeded."""
        with self._lock:
            quota = self._quotas.get(tenant_id)
            if quota is None:
                return True
            count = self._action_counts.get(tenant_id, 0)
            return count < quota.max_actions_per_hour

    def check_policies(self, tenant_id: str) -> bool:
        """Return ``True`` if policy quota is not exceeded."""
        with self._lock:
            quota = self._quotas.get(tenant_id)
            if quota is None:
                return True
            count = self._policy_counts.get(tenant_id, 0)
            return count < quota.max_policies

    def check_all(self, tenant_id: str) -> dict[str, bool]:
        """Check all quotas at once.  Returns a mapping of results."""
        with self._lock:
            quota = self._quotas.get(tenant_id)
            if quota is None:
                return {
                    "agents": True,
                    "actions": True,
                    "policies": True,
                }
            agents_ok = self._agent_counts.get(tenant_id, 0) < quota.max_agents
            actions_ok = self._action_counts.get(tenant_id, 0) < quota.max_actions_per_hour
            policies_ok = self._policy_counts.get(tenant_id, 0) < quota.max_policies
            return {
                "agents": agents_ok,
                "actions": actions_ok,
                "policies": policies_ok,
            }

    def enforce_or_raise(
        self,
        tenant_id: str,
        resource: str,
    ) -> None:
        """Raise :class:`TenantQuotaExceededError` if over limit.

        Args:
            tenant_id: The tenant to check.
            resource: One of ``"agents"``, ``"actions"``,
                ``"policies"``.
        """
        checkers: dict[str, Any] = {
            "agents": self.check_agents,
            "actions": self.check_actions,
            "policies": self.check_policies,
        }
        checker = checkers.get(resource)
        if checker is None:
            raise ValueError(f"Unknown resource '{resource}'. Must be one of {sorted(checkers)}")
        if not checker(tenant_id):
            quota = self.get_quota(tenant_id)
            raise TenantQuotaExceededError(
                tenant_id=tenant_id,
                resource=resource,
                quota=quota,
            )

    def get_usage(
        self,
        tenant_id: str,
    ) -> dict[str, object]:
        """Return current usage summary for *tenant_id*."""
        with self._lock:
            return {
                "tenant_id": tenant_id,
                "agents": self._agent_counts.get(tenant_id, 0),
                "actions": self._action_counts.get(tenant_id, 0),
                "policies": self._policy_counts.get(tenant_id, 0),
                "quota": self._quotas.get(tenant_id),
            }


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class TenantQuotaExceededError(Exception):
    """Raised when a tenant exceeds a resource quota."""

    def __init__(
        self,
        tenant_id: str,
        resource: str,
        quota: TenantQuota | None,
    ) -> None:
        self.tenant_id = tenant_id
        self.resource = resource
        self.quota = quota
        limit = "unknown"
        if quota is not None:
            limits: dict[str, int] = {
                "agents": quota.max_agents,
                "actions": quota.max_actions_per_hour,
                "policies": quota.max_policies,
            }
            limit = str(limits.get(resource, "unknown"))
        super().__init__(f"Tenant '{tenant_id}' exceeded {resource} quota (limit: {limit})")


class TenantNotFoundError(Exception):
    """Raised when a tenant lookup fails."""

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        super().__init__(f"Tenant '{tenant_id}' not found")
