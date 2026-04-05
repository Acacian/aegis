"""Cascade Guard -- prevent cascading failures in multi-agent systems.

Addresses OWASP Agentic Application Security Initiative ASI08
(Cascading Failures).  In multi-agent architectures a compromised or
failing agent can poison downstream agents, causing a chain reaction of
degraded outputs.  This module implements circuit-breaker-style health
tracking per agent and cascade-aware gating that blocks inter-agent
communication when the risk of error propagation is too high.

Key mechanisms:

* **Sliding-window error rates** -- only failures within *window_s*
  seconds count toward an agent's error rate.
* **Three-state health model** -- ``healthy`` / ``degraded`` /
  ``quarantined``, derived from the windowed error rate and explicit
  quarantine calls.
* **Cascade depth limit** -- communication chains deeper than
  *max_propagation_depth* are blocked to prevent deep cascade paths.
* **Degraded-to-degraded blocking** -- when both source and target
  agents are degraded, communication is blocked to prevent error
  amplification.

Thread-safe: every mutation is guarded by a single :class:`threading.Lock`.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from enum import StrEnum

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AgentState(StrEnum):
    """Health state for a tracked agent."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    QUARANTINED = "quarantined"


class CascadeEventType(StrEnum):
    """Type of cascade event recorded by the guard."""

    BLOCKED = "blocked"
    ALLOWED = "allowed"
    QUARANTINED = "quarantined"


# ---------------------------------------------------------------------------
# Frozen data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentHealth:
    """Immutable snapshot of an agent's health."""

    agent_id: str
    success_count: int
    failure_count: int
    error_rate: float
    last_failure_time: float | None
    state: AgentState


@dataclass(frozen=True)
class CascadeEvent:
    """Immutable record of a cascade-related event."""

    source_agent: str
    target_agent: str
    event_type: CascadeEventType
    timestamp: float
    error_message: str
    propagation_depth: int


@dataclass(frozen=True)
class CascadeDecision:
    """Result of a cascade check between two agents."""

    allowed: bool
    reason: str
    source_health: AgentHealth
    target_health: AgentHealth
    propagation_depth: int


@dataclass(frozen=True)
class CascadeReport:
    """System-wide health report."""

    total_agents: int
    healthy_count: int
    degraded_count: int
    quarantined_count: int
    cascade_events_count: int
    agents: dict[str, AgentHealth]


# ---------------------------------------------------------------------------
# Internal mutable per-agent state (not exposed)
# ---------------------------------------------------------------------------


class _AgentRecord:
    """Mutable bookkeeping for a single agent."""

    __slots__ = (
        "agent_id",
        "successes",
        "failures",
        "last_failure_time",
        "quarantined_at",
        "quarantine_reason",
    )

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        self.successes: deque[float] = deque()
        self.failures: deque[float] = deque()
        self.last_failure_time: float | None = None
        self.quarantined_at: float | None = None
        self.quarantine_reason: str = ""


# ---------------------------------------------------------------------------
# CascadeGuard
# ---------------------------------------------------------------------------


class CascadeGuard:
    """Multi-agent cascade prevention engine.

    Args:
        failure_threshold: Error-rate (0.0--1.0) at which an agent is
            considered degraded.
        window_s: Sliding window in seconds for counting
            successes/failures.
        quarantine_s: Duration in seconds an agent stays quarantined.
        max_propagation_depth: Maximum allowed depth of inter-agent
            communication chains.
    """

    def __init__(
        self,
        failure_threshold: float = 0.5,
        window_s: float = 60.0,
        quarantine_s: float = 300.0,
        max_propagation_depth: int = 3,
    ) -> None:
        self._threshold = failure_threshold
        self._window_s = window_s
        self._quarantine_s = quarantine_s
        self._max_depth = max_propagation_depth
        self._agents: dict[str, _AgentRecord] = {}
        self._events: deque[CascadeEvent] = deque(maxlen=1000)
        self._lock = threading.Lock()

    # -- helpers (must be called under lock) ---------------------------------

    def _ensure(self, agent_id: str) -> _AgentRecord:
        rec = self._agents.get(agent_id)
        if rec is None:
            rec = _AgentRecord(agent_id)
            self._agents[agent_id] = rec
        return rec

    def _trim(self, dq: deque[float], now: float) -> None:
        cutoff = now - self._window_s
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _error_rate(self, rec: _AgentRecord, now: float) -> float:
        self._trim(rec.successes, now)
        self._trim(rec.failures, now)
        total = len(rec.successes) + len(rec.failures)
        if total == 0:
            return 0.0
        return len(rec.failures) / total

    def _resolve_state(self, rec: _AgentRecord, now: float) -> AgentState:
        # Check quarantine first
        if rec.quarantined_at is not None:
            if now - rec.quarantined_at >= self._quarantine_s:
                # Auto-release
                rec.quarantined_at = None
                rec.quarantine_reason = ""
            else:
                return AgentState.QUARANTINED

        rate = self._error_rate(rec, now)
        if rate >= self._threshold:
            return AgentState.DEGRADED
        return AgentState.HEALTHY

    def _snapshot(self, rec: _AgentRecord, now: float) -> AgentHealth:
        self._trim(rec.successes, now)
        self._trim(rec.failures, now)
        state = self._resolve_state(rec, now)
        return AgentHealth(
            agent_id=rec.agent_id,
            success_count=len(rec.successes),
            failure_count=len(rec.failures),
            error_rate=self._error_rate(rec, now),
            last_failure_time=rec.last_failure_time,
            state=state,
        )

    # -- public API ----------------------------------------------------------

    def record_success(self, agent_id: str) -> None:
        """Record a successful operation for *agent_id*."""
        with self._lock:
            rec = self._ensure(agent_id)
            rec.successes.append(time.monotonic())

    def record_failure(self, agent_id: str, error: str = "") -> AgentHealth:
        """Record a failed operation and return the updated health snapshot."""
        with self._lock:
            now = time.monotonic()
            rec = self._ensure(agent_id)
            rec.failures.append(now)
            rec.last_failure_time = now

            # Auto-quarantine when degraded and sustained
            state = self._resolve_state(rec, now)
            if state == AgentState.DEGRADED:
                rate = self._error_rate(rec, now)
                if rate >= self._threshold and len(rec.failures) >= 3:
                    rec.quarantined_at = now
                    rec.quarantine_reason = error or "auto-quarantine: sustained failures"

            return self._snapshot(rec, now)

    def can_proceed(self, agent_id: str) -> bool:
        """Return whether *agent_id* is healthy enough to proceed."""
        with self._lock:
            now = time.monotonic()
            rec = self._agents.get(agent_id)
            if rec is None:
                return True  # unknown agent is assumed healthy
            state = self._resolve_state(rec, now)
            return state != AgentState.QUARANTINED

    def check_cascade(
        self,
        source_agent: str,
        target_agent: str,
        depth: int = 0,
    ) -> CascadeDecision:
        """Decide whether *source_agent* may communicate with *target_agent*."""
        with self._lock:
            now = time.monotonic()
            src = self._ensure(source_agent)
            tgt = self._ensure(target_agent)
            src_health = self._snapshot(src, now)
            tgt_health = self._snapshot(tgt, now)

            # Rule 1: quarantined source blocks
            if src_health.state == AgentState.QUARANTINED:
                reason = f"source '{source_agent}' is quarantined"
                self._record_event(
                    source_agent,
                    target_agent,
                    CascadeEventType.BLOCKED,
                    now,
                    reason,
                    depth,
                )
                return CascadeDecision(False, reason, src_health, tgt_health, depth)

            # Rule 2: propagation depth exceeded
            if depth > self._max_depth:
                reason = f"propagation depth {depth} exceeds max {self._max_depth}"
                self._record_event(
                    source_agent,
                    target_agent,
                    CascadeEventType.BLOCKED,
                    now,
                    reason,
                    depth,
                )
                return CascadeDecision(False, reason, src_health, tgt_health, depth)

            # Rule 3: degraded-to-degraded amplification
            if src_health.state == AgentState.DEGRADED and tgt_health.state == AgentState.DEGRADED:
                reason = "both source and target degraded -- blocking to prevent amplification"
                self._record_event(
                    source_agent,
                    target_agent,
                    CascadeEventType.BLOCKED,
                    now,
                    reason,
                    depth,
                )
                return CascadeDecision(False, reason, src_health, tgt_health, depth)

            # Rule 4: quarantined target blocks
            if tgt_health.state == AgentState.QUARANTINED:
                reason = f"target '{target_agent}' is quarantined"
                self._record_event(
                    source_agent,
                    target_agent,
                    CascadeEventType.BLOCKED,
                    now,
                    reason,
                    depth,
                )
                return CascadeDecision(False, reason, src_health, tgt_health, depth)

            reason = "allowed"
            self._record_event(
                source_agent,
                target_agent,
                CascadeEventType.ALLOWED,
                now,
                reason,
                depth,
            )
            return CascadeDecision(True, reason, src_health, tgt_health, depth)

    def quarantine(self, agent_id: str, reason: str = "") -> None:
        """Manually quarantine *agent_id*."""
        with self._lock:
            now = time.monotonic()
            rec = self._ensure(agent_id)
            rec.quarantined_at = now
            rec.quarantine_reason = reason or "manual quarantine"
            self._record_event(
                agent_id,
                "",
                CascadeEventType.QUARANTINED,
                now,
                rec.quarantine_reason,
                0,
            )

    def release(self, agent_id: str) -> bool:
        """Release *agent_id* from quarantine if the quarantine period has elapsed.

        Returns ``True`` if the agent was released, ``False`` otherwise.
        """
        with self._lock:
            now = time.monotonic()
            rec = self._agents.get(agent_id)
            if rec is None or rec.quarantined_at is None:
                return False
            if now - rec.quarantined_at >= self._quarantine_s:
                rec.quarantined_at = None
                rec.quarantine_reason = ""
                return True
            return False

    def get_health(self, agent_id: str) -> AgentHealth:
        """Return the current health snapshot for *agent_id*."""
        with self._lock:
            now = time.monotonic()
            rec = self._ensure(agent_id)
            return self._snapshot(rec, now)

    def get_cascade_events(self) -> list[CascadeEvent]:
        """Return a copy of recent cascade events."""
        with self._lock:
            return list(self._events)

    def report(self) -> CascadeReport:
        """Generate a system-wide health report."""
        with self._lock:
            now = time.monotonic()
            agents: dict[str, AgentHealth] = {}
            healthy = degraded = quarantined = 0
            for aid, rec in self._agents.items():
                h = self._snapshot(rec, now)
                agents[aid] = h
                if h.state == AgentState.HEALTHY:
                    healthy += 1
                elif h.state == AgentState.DEGRADED:
                    degraded += 1
                else:
                    quarantined += 1
            return CascadeReport(
                total_agents=len(agents),
                healthy_count=healthy,
                degraded_count=degraded,
                quarantined_count=quarantined,
                cascade_events_count=len(self._events),
                agents=agents,
            )

    # -- internal event logging -----------------------------------------------

    def _record_event(
        self,
        source: str,
        target: str,
        etype: CascadeEventType,
        ts: float,
        msg: str,
        depth: int,
    ) -> None:
        self._events.append(
            CascadeEvent(
                source_agent=source,
                target_agent=target,
                event_type=etype,
                timestamp=ts,
                error_message=msg,
                propagation_depth=depth,
            )
        )
