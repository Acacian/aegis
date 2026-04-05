"""Trust Score -- weighted trust accumulator for AI agent governance.

Tracks per-agent trust scores based on compliance history using a
severity-weighted scoring model.  Trust decays over time without positive
signals, encouraging continuous compliance.  Threshold policies map
minimum trust levels to action risk categories.

Thread-safe via :class:`threading.Lock`.  Pure Python, no external deps.

References:
- "Governance-as-a-Service: Runtime Policy Enforcement"
  (arXiv:2508.18765)
- OWASP Agentic AI Threats: https://owasp.org/www-project-agentic-ai-threats/
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import StrEnum

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TrustLevel(StrEnum):
    """Five-level trust classification for agents."""

    UNTRUSTED = "untrusted"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    VERIFIED = "verified"


class TrustEventType(StrEnum):
    """Types of events that affect an agent's trust score."""

    COMPLIANCE = "compliance"
    VIOLATION = "violation"
    ESCALATION = "escalation"
    AUDIT_PASS = "audit_pass"
    AUDIT_FAIL = "audit_fail"


# ---------------------------------------------------------------------------
# Frozen data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrustEvent:
    """Immutable record of a trust-affecting event."""

    agent_id: str
    event_type: TrustEventType
    weight: float
    timestamp: float
    description: str


@dataclass(frozen=True)
class TrustScore:
    """Immutable snapshot of an agent's current trust state."""

    agent_id: str
    score: float
    level: TrustLevel
    history_size: int
    last_updated: float


@dataclass(frozen=True)
class TrustThresholdPolicy:
    """Maps action risk levels to minimum trust requirements."""

    risk_level: str
    min_trust: float
    description: str


@dataclass(frozen=True)
class TrustReport:
    """System-wide trust report across all tracked agents."""

    total_agents: int
    scores: dict[str, TrustScore]
    level_distribution: dict[str, int]
    total_events: int
    generated_at: float = field(default_factory=time.monotonic)


# ---------------------------------------------------------------------------
# Default weight map and thresholds
# ---------------------------------------------------------------------------

_DEFAULT_EVENT_WEIGHTS: dict[TrustEventType, float] = {
    TrustEventType.COMPLIANCE: 0.05,
    TrustEventType.VIOLATION: -0.15,
    TrustEventType.ESCALATION: -0.05,
    TrustEventType.AUDIT_PASS: 0.10,
    TrustEventType.AUDIT_FAIL: -0.20,
}

_DEFAULT_THRESHOLD_POLICIES: list[TrustThresholdPolicy] = [
    TrustThresholdPolicy("low", 0.0, "Low-risk actions: no trust minimum"),
    TrustThresholdPolicy("medium", 0.3, "Medium-risk: requires LOW trust or above"),
    TrustThresholdPolicy("high", 0.6, "High-risk: requires MODERATE trust or above"),
    TrustThresholdPolicy("critical", 0.85, "Critical: requires VERIFIED trust"),
]


# ---------------------------------------------------------------------------
# Internal mutable per-agent state
# ---------------------------------------------------------------------------


class _AgentTrustRecord:
    """Mutable bookkeeping for a single agent's trust history."""

    __slots__ = ("agent_id", "events", "raw_score", "last_updated")

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        self.events: deque[TrustEvent] = deque()
        self.raw_score: float = 0.5  # start at neutral
        self.last_updated: float = time.monotonic()


# ---------------------------------------------------------------------------
# TrustScorer
# ---------------------------------------------------------------------------


class TrustScorer:
    """Weighted trust accumulator per agent based on compliance history.

    Implements the trust scoring model from "Governance-as-a-Service:
    Runtime Policy Enforcement" (arXiv:2508.18765).  Each agent starts at
    a neutral score (0.5) and accumulates trust via compliance events or
    loses trust via violations.  Trust decays toward neutral over time
    without recent positive signals.

    Args:
        max_history: Maximum events retained per agent.
        decay_rate: Trust decay per second of inactivity (toward 0.5).
        event_weights: Override default weights per event type.
        threshold_policies: Override default risk-to-trust mappings.
    """

    def __init__(
        self,
        max_history: int = 1000,
        decay_rate: float = 0.001,
        event_weights: dict[TrustEventType, float] | None = None,
        threshold_policies: list[TrustThresholdPolicy] | None = None,
    ) -> None:
        self._max_history = max_history
        self._decay_rate = decay_rate
        self._weights = dict(event_weights or _DEFAULT_EVENT_WEIGHTS)
        self._policies = list(threshold_policies or _DEFAULT_THRESHOLD_POLICIES)
        self._agents: dict[str, _AgentTrustRecord] = {}
        self._lock = threading.Lock()

    # -- helpers (must be called under lock) ---------------------------------

    def _ensure(self, agent_id: str) -> _AgentTrustRecord:
        rec = self._agents.get(agent_id)
        if rec is None:
            rec = _AgentTrustRecord(agent_id)
            self._agents[agent_id] = rec
        return rec

    def _apply_decay(self, rec: _AgentTrustRecord, now: float) -> None:
        """Decay trust toward 0.5 (neutral) based on elapsed time."""
        elapsed = now - rec.last_updated
        if elapsed <= 0:
            return
        decay_amount = self._decay_rate * elapsed
        if rec.raw_score > 0.5:
            rec.raw_score = max(0.5, rec.raw_score - decay_amount)
        elif rec.raw_score < 0.5:
            rec.raw_score = min(0.5, rec.raw_score + decay_amount)

    @staticmethod
    def _clamp(value: float) -> float:
        return max(0.0, min(1.0, value))

    @staticmethod
    def _score_to_level(score: float) -> TrustLevel:
        if score >= 0.85:
            return TrustLevel.VERIFIED
        if score >= 0.65:
            return TrustLevel.HIGH
        if score >= 0.45:
            return TrustLevel.MODERATE
        if score >= 0.25:
            return TrustLevel.LOW
        return TrustLevel.UNTRUSTED

    def _snapshot(self, rec: _AgentTrustRecord) -> TrustScore:
        score = self._clamp(rec.raw_score)
        return TrustScore(
            agent_id=rec.agent_id,
            score=score,
            level=self._score_to_level(score),
            history_size=len(rec.events),
            last_updated=rec.last_updated,
        )

    # -- public API ----------------------------------------------------------

    def record_event(
        self,
        agent_id: str,
        event_type: TrustEventType,
        *,
        weight: float | None = None,
        description: str = "",
        severity: float = 1.0,
    ) -> TrustScore:
        """Record a trust-affecting event for *agent_id*.

        Args:
            agent_id: The agent to record the event for.
            event_type: Type of trust event.
            weight: Override default weight for this event type.
            description: Human-readable description.
            severity: Multiplier for the weight (0.0-1.0 for reduced impact,
                >1.0 for amplified impact).

        Returns:
            Updated trust score snapshot.
        """
        with self._lock:
            now = time.monotonic()
            rec = self._ensure(agent_id)
            self._apply_decay(rec, now)

            w = weight if weight is not None else self._weights.get(event_type, 0.0)
            effective_weight = w * severity

            event = TrustEvent(
                agent_id=agent_id,
                event_type=event_type,
                weight=effective_weight,
                timestamp=now,
                description=description,
            )
            rec.events.append(event)
            if len(rec.events) > self._max_history:
                rec.events.popleft()

            rec.raw_score = self._clamp(rec.raw_score + effective_weight)
            rec.last_updated = now
            return self._snapshot(rec)

    def get_score(self, agent_id: str) -> TrustScore:
        """Get current trust score for an agent, applying time decay."""
        with self._lock:
            now = time.monotonic()
            rec = self._ensure(agent_id)
            self._apply_decay(rec, now)
            rec.last_updated = now
            return self._snapshot(rec)

    def decay(self, agent_id: str, seconds: float) -> TrustScore:
        """Manually apply time-based trust decay for *seconds*.

        Useful for testing or simulating passage of time.
        """
        with self._lock:
            rec = self._ensure(agent_id)
            now = rec.last_updated
            decay_amount = self._decay_rate * seconds
            if rec.raw_score > 0.5:
                rec.raw_score = max(0.5, rec.raw_score - decay_amount)
            elif rec.raw_score < 0.5:
                rec.raw_score = min(0.5, rec.raw_score + decay_amount)
            rec.last_updated = now + seconds
            return self._snapshot(rec)

    def check_threshold(self, agent_id: str, risk_level: str) -> bool:
        """Check if agent meets the trust threshold for a given risk level.

        Returns ``True`` if the agent's trust score meets or exceeds the
        minimum required for the specified risk level.
        """
        score = self.get_score(agent_id)
        for policy in self._policies:
            if policy.risk_level == risk_level:
                return score.score >= policy.min_trust
        # Unknown risk level: deny by default
        return False

    def get_events(self, agent_id: str) -> list[TrustEvent]:
        """Return a copy of recent trust events for *agent_id*."""
        with self._lock:
            rec = self._agents.get(agent_id)
            if rec is None:
                return []
            return list(rec.events)

    def report(self) -> TrustReport:
        """Generate a system-wide trust report."""
        with self._lock:
            now = time.monotonic()
            scores: dict[str, TrustScore] = {}
            level_dist: dict[str, int] = {level.value: 0 for level in TrustLevel}
            total_events = 0

            for aid, rec in self._agents.items():
                self._apply_decay(rec, now)
                snap = self._snapshot(rec)
                scores[aid] = snap
                level_dist[snap.level.value] += 1
                total_events += len(rec.events)

            return TrustReport(
                total_agents=len(scores),
                scores=scores,
                level_distribution=level_dist,
                total_events=total_events,
            )
