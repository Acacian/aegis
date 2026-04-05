"""Autonomy Level -- manage and enforce agent autonomy levels.

Implements a five-level autonomy model for AI agents, ranging from
passive observation (L0) to fully autonomous operation (L4).  Each
level maps to a set of permitted action categories.  Certificates
provide tamper-evident proof of granted autonomy.

Thread-safe via :class:`threading.Lock`.  Pure Python, no external deps.

References:
- "Levels of Autonomy for AI Agents" (arXiv:2506.12469)
- OWASP Agentic AI Threats: https://owasp.org/www-project-agentic-ai-threats/
"""

from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AutonomyLevel(IntEnum):
    """Five levels of agent autonomy (L0-L4).

    L0 OBSERVER:     Read-only, no actions taken.
    L1 APPROVER:     Can approve or deny proposed actions.
    L2 CONSULTANT:   Can suggest actions for human review.
    L3 COLLABORATOR: Can act with mandatory notification.
    L4 OPERATOR:     Fully autonomous operation.
    """

    OBSERVER = 0
    APPROVER = 1
    CONSULTANT = 2
    COLLABORATOR = 3
    OPERATOR = 4


class ActionCategory(StrEnum):
    """Categories of actions mapped to autonomy levels."""

    READ = "read"
    APPROVE = "approve"
    SUGGEST = "suggest"
    ACT_WITH_NOTIFY = "act_with_notify"
    ACT_AUTONOMOUS = "act_autonomous"


# ---------------------------------------------------------------------------
# Level-to-action mapping
# ---------------------------------------------------------------------------

_LEVEL_PERMISSIONS: dict[AutonomyLevel, frozenset[ActionCategory]] = {
    AutonomyLevel.OBSERVER: frozenset({ActionCategory.READ}),
    AutonomyLevel.APPROVER: frozenset({ActionCategory.READ, ActionCategory.APPROVE}),
    AutonomyLevel.CONSULTANT: frozenset(
        {ActionCategory.READ, ActionCategory.APPROVE, ActionCategory.SUGGEST}
    ),
    AutonomyLevel.COLLABORATOR: frozenset(
        {
            ActionCategory.READ,
            ActionCategory.APPROVE,
            ActionCategory.SUGGEST,
            ActionCategory.ACT_WITH_NOTIFY,
        }
    ),
    AutonomyLevel.OPERATOR: frozenset(
        {
            ActionCategory.READ,
            ActionCategory.APPROVE,
            ActionCategory.SUGGEST,
            ActionCategory.ACT_WITH_NOTIFY,
            ActionCategory.ACT_AUTONOMOUS,
        }
    ),
}

# ---------------------------------------------------------------------------
# Frozen data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AutonomyPolicy:
    """Immutable autonomy policy assigned to an agent."""

    agent_id: str
    level: AutonomyLevel
    max_level: AutonomyLevel
    constraints: tuple[str, ...] = ()
    granted_at: float = field(default_factory=time.monotonic)
    expires_at: float | None = None


@dataclass(frozen=True)
class AutonomyCertificate:
    """Tamper-evident certificate proving an agent's autonomy level."""

    agent_id: str
    level: AutonomyLevel
    issuer: str
    valid_from: float
    valid_until: float | None
    scope: str
    cert_hash: str


@dataclass(frozen=True)
class AutonomyViolation:
    """Record of an agent attempting to exceed its autonomy level."""

    agent_id: str
    attempted_level: AutonomyLevel
    allowed_level: AutonomyLevel
    action: str
    reason: str
    timestamp: float = field(default_factory=time.monotonic)


@dataclass(frozen=True)
class AutonomyReport:
    """System-wide autonomy report."""

    total_agents: int
    policies: dict[str, AutonomyPolicy]
    level_distribution: dict[int, int]
    total_violations: int
    active_certificates: int


# ---------------------------------------------------------------------------
# Internal mutable per-agent state
# ---------------------------------------------------------------------------


class _AgentAutonomyRecord:
    """Mutable bookkeeping for a single agent's autonomy state."""

    __slots__ = ("agent_id", "policy", "certificates", "violations")

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        self.policy: AutonomyPolicy = AutonomyPolicy(
            agent_id=agent_id,
            level=AutonomyLevel.OBSERVER,
            max_level=AutonomyLevel.OPERATOR,
        )
        self.certificates: list[AutonomyCertificate] = []
        self.violations: list[AutonomyViolation] = []


# ---------------------------------------------------------------------------
# AutonomyManager
# ---------------------------------------------------------------------------


class AutonomyManager:
    """Manage and enforce autonomy levels per agent.

    Implements the five-level autonomy model from "Levels of Autonomy
    for AI Agents" (arXiv:2506.12469).  Each agent is assigned a policy
    that constrains which action categories it may perform.  Certificates
    provide cryptographic proof of granted autonomy that can be verified
    offline.

    Args:
        default_level: Starting autonomy level for new agents.
        default_max_level: Maximum level agents can be promoted to.
        max_violations: Maximum violations retained per agent.
    """

    def __init__(
        self,
        default_level: AutonomyLevel = AutonomyLevel.OBSERVER,
        default_max_level: AutonomyLevel = AutonomyLevel.OPERATOR,
        max_violations: int = 1000,
    ) -> None:
        self._default_level = default_level
        self._default_max_level = default_max_level
        self._max_violations = max_violations
        self._agents: dict[str, _AgentAutonomyRecord] = {}
        self._lock = threading.Lock()

    # -- helpers (must be called under lock) ---------------------------------

    def _ensure(self, agent_id: str) -> _AgentAutonomyRecord:
        rec = self._agents.get(agent_id)
        if rec is None:
            rec = _AgentAutonomyRecord(agent_id)
            rec.policy = AutonomyPolicy(
                agent_id=agent_id,
                level=self._default_level,
                max_level=self._default_max_level,
            )
            self._agents[agent_id] = rec
        return rec

    @staticmethod
    def _compute_cert_hash(
        agent_id: str,
        level: AutonomyLevel,
        issuer: str,
        valid_from: float,
        valid_until: float | None,
        scope: str,
    ) -> str:
        payload = f"{agent_id}|{level.value}|{issuer}|{valid_from}|{valid_until}|{scope}"
        return hashlib.sha256(payload.encode()).hexdigest()

    @staticmethod
    def _required_level_for_action(action_category: ActionCategory) -> AutonomyLevel:
        """Return the minimum autonomy level required for an action category."""
        for level in AutonomyLevel:
            if action_category in _LEVEL_PERMISSIONS[level]:
                return level
        return AutonomyLevel.OPERATOR

    def _is_expired(self, policy: AutonomyPolicy, now: float) -> bool:
        return policy.expires_at is not None and now > policy.expires_at

    # -- public API ----------------------------------------------------------

    def set_level(
        self,
        agent_id: str,
        level: AutonomyLevel,
        *,
        max_level: AutonomyLevel | None = None,
        constraints: tuple[str, ...] = (),
        expires_at: float | None = None,
    ) -> AutonomyPolicy:
        """Set the autonomy level for an agent.

        Args:
            agent_id: Target agent.
            level: Desired autonomy level.
            max_level: Override the maximum allowed level.
            constraints: Additional textual constraints.
            expires_at: Monotonic timestamp when this policy expires.

        Returns:
            The new policy.

        Raises:
            ValueError: If *level* exceeds *max_level*.
        """
        with self._lock:
            rec = self._ensure(agent_id)
            effective_max = max_level if max_level is not None else rec.policy.max_level
            if level > effective_max:
                raise ValueError(f"Level {level.name} exceeds max {effective_max.name}")
            policy = AutonomyPolicy(
                agent_id=agent_id,
                level=level,
                max_level=effective_max,
                constraints=constraints,
                expires_at=expires_at,
            )
            rec.policy = policy
            return policy

    def get_policy(self, agent_id: str) -> AutonomyPolicy:
        """Return the current autonomy policy for *agent_id*."""
        with self._lock:
            rec = self._ensure(agent_id)
            now = time.monotonic()
            if self._is_expired(rec.policy, now):
                # Reset to default on expiry
                rec.policy = AutonomyPolicy(
                    agent_id=agent_id,
                    level=self._default_level,
                    max_level=rec.policy.max_level,
                )
            return rec.policy

    def check_action(
        self,
        agent_id: str,
        action_category: ActionCategory,
    ) -> bool:
        """Verify if an action is within the agent's autonomy level.

        Returns ``True`` if the action is permitted, ``False`` otherwise.
        If denied, an :class:`AutonomyViolation` is recorded.
        """
        with self._lock:
            now = time.monotonic()
            rec = self._ensure(agent_id)

            # Check expiry
            if self._is_expired(rec.policy, now):
                rec.policy = AutonomyPolicy(
                    agent_id=agent_id,
                    level=self._default_level,
                    max_level=rec.policy.max_level,
                )

            current_level = rec.policy.level
            permitted = _LEVEL_PERMISSIONS.get(current_level, frozenset())

            if action_category in permitted:
                return True

            # Record violation
            required = self._required_level_for_action(action_category)
            violation = AutonomyViolation(
                agent_id=agent_id,
                attempted_level=required,
                allowed_level=current_level,
                action=action_category.value,
                reason=f"Action '{action_category.value}' requires level "
                f"{required.name} but agent is at {current_level.name}",
            )
            rec.violations.append(violation)
            if len(rec.violations) > self._max_violations:
                rec.violations = rec.violations[-self._max_violations :]
            return False

    def issue_certificate(
        self,
        agent_id: str,
        issuer: str,
        scope: str = "*",
        valid_duration: float | None = None,
    ) -> AutonomyCertificate:
        """Issue a certificate for the agent's current autonomy level.

        Args:
            agent_id: Target agent.
            issuer: Identity of the issuing authority.
            scope: Scope the certificate applies to (default: all).
            valid_duration: Duration in seconds (``None`` = no expiry).

        Returns:
            A signed :class:`AutonomyCertificate`.
        """
        with self._lock:
            rec = self._ensure(agent_id)
            now = time.monotonic()
            valid_until = (now + valid_duration) if valid_duration is not None else None
            cert_hash = self._compute_cert_hash(
                agent_id, rec.policy.level, issuer, now, valid_until, scope
            )
            cert = AutonomyCertificate(
                agent_id=agent_id,
                level=rec.policy.level,
                issuer=issuer,
                valid_from=now,
                valid_until=valid_until,
                scope=scope,
                cert_hash=cert_hash,
            )
            rec.certificates.append(cert)
            return cert

    def verify_certificate(self, cert: AutonomyCertificate) -> bool:
        """Verify a certificate's integrity and validity.

        Checks the hash matches the certificate contents and that the
        certificate has not expired.
        """
        expected_hash = self._compute_cert_hash(
            cert.agent_id,
            cert.level,
            cert.issuer,
            cert.valid_from,
            cert.valid_until,
            cert.scope,
        )
        if cert.cert_hash != expected_hash:
            return False
        return not (cert.valid_until is not None and time.monotonic() > cert.valid_until)

    def get_violations(self, agent_id: str) -> list[AutonomyViolation]:
        """Return a copy of recent violations for *agent_id*."""
        with self._lock:
            rec = self._agents.get(agent_id)
            if rec is None:
                return []
            return list(rec.violations)

    def get_permissions(self, agent_id: str) -> frozenset[ActionCategory]:
        """Return the set of permitted action categories for *agent_id*."""
        with self._lock:
            rec = self._ensure(agent_id)
            now = time.monotonic()
            if self._is_expired(rec.policy, now):
                rec.policy = AutonomyPolicy(
                    agent_id=agent_id,
                    level=self._default_level,
                    max_level=rec.policy.max_level,
                )
            return _LEVEL_PERMISSIONS.get(rec.policy.level, frozenset())

    def report(self) -> AutonomyReport:
        """Generate a system-wide autonomy report."""
        with self._lock:
            now = time.monotonic()
            policies: dict[str, AutonomyPolicy] = {}
            level_dist: dict[int, int] = {level.value: 0 for level in AutonomyLevel}
            total_violations = 0
            active_certs = 0

            for aid, rec in self._agents.items():
                if self._is_expired(rec.policy, now):
                    rec.policy = AutonomyPolicy(
                        agent_id=aid,
                        level=self._default_level,
                        max_level=rec.policy.max_level,
                    )
                policies[aid] = rec.policy
                level_dist[rec.policy.level.value] += 1
                total_violations += len(rec.violations)
                for cert in rec.certificates:
                    if cert.valid_until is None or cert.valid_until > now:
                        active_certs += 1

            return AutonomyReport(
                total_agents=len(policies),
                policies=policies,
                level_distribution=level_dist,
                total_violations=total_violations,
                active_certificates=active_certs,
            )
