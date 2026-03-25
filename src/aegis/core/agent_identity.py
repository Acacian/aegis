"""Agent Trust Chain — identity, capability-based permissions, and delegation.

Provides a standalone agent identity and registry system that enables:

- **AgentIdentity**: Frozen dataclass representing an agent with capabilities
  and a trust level.
- **AgentRegistry**: Manages known agents, delegation chains, and revocation.
- **DelegationEvent**: Immutable audit record for every delegation.
- **capability_matches**: Glob-based capability matching (``fnmatch``).

Delegation enforces the *principle of least privilege*: a child agent can
never exceed its parent's capabilities or trust level.

Example::

    registry = AgentRegistry()
    root = AgentIdentity(
        agent_id="orchestrator",
        name="Orchestrator",
        capabilities=frozenset({"read_*", "write_crm"}),
        trust_level=90,
    )
    registry.register(root)

    worker = AgentIdentity(
        agent_id="worker-1",
        name="CRM Worker",
        capabilities=frozenset({"read_crm", "write_crm"}),
        trust_level=80,
    )
    delegated = registry.delegate("orchestrator", worker)
    # delegated.capabilities = {"read_crm", "write_crm"}  (intersection)
    # delegated.trust_level  = 80  (min of parent 90 and child 80)
"""

from __future__ import annotations

import fnmatch
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aegis.core.constitution import AgentConstitution

# ── helpers ─────────────────────────────────────────────────────────────


def capability_matches(capability: str, pattern: str) -> bool:
    """Check whether *capability* matches a glob *pattern*.

    Both the pattern and the capability string are compared using
    :func:`fnmatch.fnmatch`, so ``"read_crm"`` matches ``"read_*"``.
    """
    return fnmatch.fnmatch(capability, pattern)


def _effective_capabilities(
    parent_caps: frozenset[str],
    child_caps: frozenset[str],
) -> frozenset[str]:
    """Compute effective capabilities as the intersection.

    A child capability is retained only when *at least one* parent
    capability pattern matches it (or it literally exists in the
    parent set).  Conversely, parent glob patterns are kept only
    when at least one child capability matches them.

    This ensures the child can never exceed the parent.
    """
    effective: set[str] = set()
    for child_cap in child_caps:
        for parent_cap in parent_caps:
            if capability_matches(child_cap, parent_cap):
                effective.add(child_cap)
                break
    return frozenset(effective)


def has_capability(agent_capabilities: frozenset[str], required: str) -> bool:
    """Return ``True`` if any of *agent_capabilities* matches *required*.

    Supports glob patterns in the agent's capability set::

        has_capability(frozenset({"read_*"}), "read_crm")  # True
        has_capability(frozenset({"write_crm"}), "write_*")  # False
    """
    return any(capability_matches(required, cap) for cap in agent_capabilities)


# ── data models ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AgentIdentity:
    """Immutable identity for an AI agent.

    Attributes:
        agent_id: Unique identifier.
        name: Human-readable display name.
        capabilities: Glob-capable permission tokens.
        trust_level: 0–100; higher means more trusted.
        parent_id: The agent that delegated to this one (``None`` for roots).
        metadata: Arbitrary string key-value pairs.
    """

    agent_id: str
    name: str
    capabilities: frozenset[str] = field(default_factory=frozenset)
    trust_level: int = 0
    parent_id: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)
    constitution: AgentConstitution | None = None

    def __post_init__(self) -> None:
        if not self.agent_id:
            raise ValueError("agent_id must be a non-empty string")
        if not (0 <= self.trust_level <= 100):
            raise ValueError(f"trust_level must be 0–100, got {self.trust_level}")

    def __str__(self) -> str:
        parent = f" parent={self.parent_id}" if self.parent_id else ""
        return (
            f"Agent({self.agent_id}, trust={self.trust_level}, "
            f"caps={sorted(self.capabilities)}{parent})"
        )


@dataclass(frozen=True)
class DelegationEvent:
    """Audit record for a single delegation.

    Created automatically by :meth:`AgentRegistry.delegate`.
    """

    timestamp: datetime
    parent_id: str
    child_id: str
    granted_capabilities: frozenset[str]
    effective_trust: int


# ── registry ────────────────────────────────────────────────────────────


class AgentRegistry:
    """Thread-safe registry of agent identities and their delegation chains.

    The registry is standalone — it does not depend on ``Runtime`` or any
    other Aegis component, so it can be used in isolation.
    """

    def __init__(self) -> None:
        self._agents: dict[str, AgentIdentity] = {}
        self._delegation_log: list[DelegationEvent] = []
        self._lock = threading.Lock()

    # ── basic CRUD ──────────────────────────────────────────────────────

    def register(self, agent: AgentIdentity) -> None:
        """Register a new agent identity.

        Raises:
            ValueError: If an agent with the same ``agent_id`` already exists.
        """
        with self._lock:
            if agent.agent_id in self._agents:
                raise ValueError(f"Agent already registered: {agent.agent_id}")
            self._agents[agent.agent_id] = agent

    def get(self, agent_id: str) -> AgentIdentity | None:
        """Retrieve an agent by ID, or ``None`` if not found."""
        with self._lock:
            return self._agents.get(agent_id)

    def list_agents(self) -> list[AgentIdentity]:
        """Return a snapshot of all registered agents."""
        with self._lock:
            return list(self._agents.values())

    # ── delegation ──────────────────────────────────────────────────────

    def delegate(self, parent_id: str, child: AgentIdentity) -> AgentIdentity:
        """Delegate authority from *parent_id* to *child*.

        The returned :class:`AgentIdentity` has:

        * ``capabilities`` = intersection of parent and child capabilities.
        * ``trust_level`` = ``min(parent.trust_level, child.trust_level)``.
        * ``parent_id`` = *parent_id*.

        The delegated identity is automatically registered.

        Raises:
            KeyError: If the parent is not registered.
            ValueError: If the child ID is already registered.
            ValueError: If delegation would produce zero capabilities.
        """
        with self._lock:
            parent = self._agents.get(parent_id)
            if parent is None:
                raise KeyError(f"Parent agent not found: {parent_id}")
            if child.agent_id in self._agents:
                raise ValueError(f"Agent already registered: {child.agent_id}")

            effective_caps = _effective_capabilities(parent.capabilities, child.capabilities)
            if not effective_caps:
                raise ValueError(
                    f"Delegation from {parent_id} to {child.agent_id} "
                    "would produce zero effective capabilities"
                )

            effective_trust = min(parent.trust_level, child.trust_level)

            # Constitutional inheritance
            effective_constitution: AgentConstitution | None = None
            if parent.constitution is not None or child.constitution is not None:
                from aegis.core.constitution import AgentConstitution as _AC

                effective_constitution = _AC.merge_inherited(
                    parent=parent.constitution,
                    child=child.constitution,
                    intersect_capabilities=effective_caps,
                )

            delegated = AgentIdentity(
                agent_id=child.agent_id,
                name=child.name,
                capabilities=effective_caps,
                trust_level=effective_trust,
                parent_id=parent_id,
                metadata=child.metadata,
                constitution=effective_constitution,
            )

            self._agents[delegated.agent_id] = delegated
            self._delegation_log.append(
                DelegationEvent(
                    timestamp=datetime.now(UTC),
                    parent_id=parent_id,
                    child_id=child.agent_id,
                    granted_capabilities=effective_caps,
                    effective_trust=effective_trust,
                )
            )
            return delegated

    # ── trust chain ─────────────────────────────────────────────────────

    def get_trust_chain(self, agent_id: str) -> list[AgentIdentity]:
        """Return the full delegation chain from root to *agent_id*.

        The first element is the root (no parent), the last is the
        requested agent itself.

        Raises:
            KeyError: If *agent_id* is not registered.
            RuntimeError: If a cycle is detected in the chain.
        """
        with self._lock:
            return self._build_chain(agent_id)

    def _build_chain(self, agent_id: str) -> list[AgentIdentity]:
        """Build chain without acquiring lock (caller holds it)."""
        agent = self._agents.get(agent_id)
        if agent is None:
            raise KeyError(f"Agent not found: {agent_id}")

        chain: list[AgentIdentity] = []
        visited: set[str] = set()
        current: AgentIdentity | None = agent

        while current is not None:
            if current.agent_id in visited:
                raise RuntimeError(f"Cycle detected in trust chain at {current.agent_id}")
            visited.add(current.agent_id)
            chain.append(current)
            current = self._agents.get(current.parent_id) if current.parent_id else None

        chain.reverse()
        return chain

    # ── revocation ──────────────────────────────────────────────────────

    def revoke(self, agent_id: str) -> list[str]:
        """Revoke an agent and all of its descendants.

        Returns the list of revoked agent IDs (including *agent_id*).

        Raises:
            KeyError: If *agent_id* is not registered.
        """
        with self._lock:
            if agent_id not in self._agents:
                raise KeyError(f"Agent not found: {agent_id}")

            revoked: list[str] = []
            to_revoke = [agent_id]

            while to_revoke:
                current_id = to_revoke.pop()
                if current_id not in self._agents:
                    continue
                del self._agents[current_id]
                revoked.append(current_id)
                # Find children delegated by current_id
                for aid, a in list(self._agents.items()):
                    if a.parent_id == current_id:
                        to_revoke.append(aid)

            return revoked

    # ── audit ───────────────────────────────────────────────────────────

    @property
    def delegation_log(self) -> list[DelegationEvent]:
        """Return a snapshot of the delegation audit log."""
        with self._lock:
            return list(self._delegation_log)

    # ── capability / trust checks (for policy integration) ──────────────

    def check_capability(self, agent_id: str, required_capability: str) -> bool:
        """Return ``True`` if the agent has a capability matching *required_capability*.

        Returns ``False`` if the agent is not registered.
        """
        agent = self.get(agent_id)
        if agent is None:
            return False
        return has_capability(agent.capabilities, required_capability)

    def check_trust_level(self, agent_id: str, min_trust: int) -> bool:
        """Return ``True`` if the agent's trust level >= *min_trust*.

        Returns ``False`` if the agent is not registered.
        """
        agent = self.get(agent_id)
        if agent is None:
            return False
        return agent.trust_level >= min_trust
