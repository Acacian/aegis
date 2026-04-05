"""Temporal monitoring for agentic system tool invocations.

Monitors sequences of tool invocations against a set of temporal rules
and detects violations in real time.  Supports simplified temporal logic
patterns including ordering constraints, timing windows, repetition
limits, and forbidden sequences.

Key mechanisms:

* **ALWAYS_BEFORE** -- action A must always precede action B.
* **NEVER_AFTER** -- action A must never follow action B.
* **WITHIN_TIME** -- action B must occur within N seconds of action A.
* **MAX_REPEAT** -- action A cannot repeat more than N times in a window.
* **SEQUENCE** -- actions must occur in exact sequence [A, B, C].
* **FORBIDDEN_SEQUENCE** -- sequence [A, B] must never occur.

Thread-safe via :class:`threading.Lock`.  Pure Python, no external deps.

Reference:
    Checking Correctness for Agentic Systems.
    arXiv:2509.20364 (2025).
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PatternType(StrEnum):
    """Supported temporal pattern types."""

    ALWAYS_BEFORE = "always_before"
    NEVER_AFTER = "never_after"
    WITHIN_TIME = "within_time"
    MAX_REPEAT = "max_repeat"
    SEQUENCE = "sequence"
    FORBIDDEN_SEQUENCE = "forbidden_sequence"


class Severity(StrEnum):
    """Severity levels for violations."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Frozen data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TemporalRule:
    """A temporal rule that events are checked against.

    Attributes:
        rule_id: Unique identifier for this rule.
        name: Human-readable name.
        pattern: The pattern type (see :class:`PatternType`).
        description: Explanation of what the rule enforces.
        severity: How serious a violation is.
        actions: Ordered list of event types involved in this rule.
        params: Additional parameters (e.g. ``{"window_s": 5.0}``
            for WITHIN_TIME, ``{"max_count": 3, "window_s": 60.0}``
            for MAX_REPEAT).
    """

    rule_id: str
    name: str
    pattern: str
    description: str
    severity: str = Severity.MEDIUM
    actions: tuple[str, ...] = ()
    params: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class TemporalEvent:
    """A single observed event in the agentic system."""

    event_id: str
    event_type: str
    agent_id: str
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class TemporalViolation:
    """A detected violation of a temporal rule."""

    rule_id: str
    events: tuple[TemporalEvent, ...] = ()
    description: str = ""
    severity: str = Severity.MEDIUM


@dataclass(frozen=True)
class MonitorState:
    """Snapshot of the monitor's current state."""

    total_events: int
    violations: int
    active_rules: int
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class TemporalMonitor:
    """Monitor tool invocation sequences against temporal rules.

    Parameters
    ----------
    max_events:
        Maximum number of events to retain per agent.
    """

    def __init__(self, max_events: int = 10000) -> None:
        self._max_events = max_events
        self._rules: dict[str, TemporalRule] = {}
        # Per-agent event buffers.
        self._events: dict[str, deque[TemporalEvent]] = {}
        self._violations: list[TemporalViolation] = []
        self._lock = threading.Lock()

    # -- public API --------------------------------------------------------

    def add_rule(self, rule: TemporalRule) -> None:
        """Add a temporal rule to the monitor."""
        with self._lock:
            self._rules[rule.rule_id] = rule

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule. Returns True if found and removed."""
        with self._lock:
            return self._rules.pop(rule_id, None) is not None

    def record_event(self, event: TemporalEvent) -> list[TemporalViolation]:
        """Record an event and check against all rules.

        Returns any violations triggered by this event.
        """
        with self._lock:
            buf = self._events.setdefault(event.agent_id, deque(maxlen=self._max_events))
            buf.append(event)
            violations = self._check_all_rules_unlocked(event)
            self._violations.extend(violations)
            return list(violations)

    def check_sequence(
        self,
        events: list[TemporalEvent],
    ) -> list[TemporalViolation]:
        """Check a sequence of events against all rules (batch mode).

        Does not modify internal state.
        """
        with self._lock:
            violations: list[TemporalViolation] = []
            for rule in self._rules.values():
                violations.extend(self._check_rule_against_sequence(rule, events))
            return violations

    def get_violations(
        self,
        agent_id: str | None = None,
        rule_id: str | None = None,
    ) -> list[TemporalViolation]:
        """Return all detected violations, optionally filtered."""
        with self._lock:
            result = list(self._violations)
        if agent_id is not None:
            result = [v for v in result if any(e.agent_id == agent_id for e in v.events)]
        if rule_id is not None:
            result = [v for v in result if v.rule_id == rule_id]
        return result

    def get_state(self) -> MonitorState:
        """Return a snapshot of the monitor's current state."""
        with self._lock:
            total_events = sum(len(buf) for buf in self._events.values())
            return MonitorState(
                total_events=total_events,
                violations=len(self._violations),
                active_rules=len(self._rules),
            )

    # -- internal (must be called under lock) --------------------------------

    def _check_all_rules_unlocked(
        self,
        event: TemporalEvent,
    ) -> list[TemporalViolation]:
        """Check the newly recorded event against all rules."""
        violations: list[TemporalViolation] = []
        agent_events = list(self._events.get(event.agent_id, []))
        for rule in self._rules.values():
            violations.extend(self._check_rule_on_event(rule, event, agent_events))
        return violations

    def _check_rule_on_event(
        self,
        rule: TemporalRule,
        event: TemporalEvent,
        agent_events: list[TemporalEvent],
    ) -> list[TemporalViolation]:
        """Check a single rule against a newly recorded event."""
        pattern = rule.pattern

        if pattern == PatternType.ALWAYS_BEFORE:
            return self._check_always_before(rule, event, agent_events)
        if pattern == PatternType.NEVER_AFTER:
            return self._check_never_after(rule, event, agent_events)
        if pattern == PatternType.WITHIN_TIME:
            return self._check_within_time(rule, event, agent_events)
        if pattern == PatternType.MAX_REPEAT:
            return self._check_max_repeat(rule, event, agent_events)
        if pattern == PatternType.SEQUENCE:
            return self._check_sequence_rule(rule, event, agent_events)
        if pattern == PatternType.FORBIDDEN_SEQUENCE:
            return self._check_forbidden_sequence(rule, event, agent_events)
        return []

    def _check_rule_against_sequence(
        self,
        rule: TemporalRule,
        events: list[TemporalEvent],
    ) -> list[TemporalViolation]:
        """Check a rule against a full sequence of events (batch mode)."""
        violations: list[TemporalViolation] = []
        for i, event in enumerate(events):
            sub_events = events[: i + 1]
            violations.extend(self._check_rule_on_event(rule, event, sub_events))
        return violations

    # -- pattern checkers ----------------------------------------------------

    def _check_always_before(
        self,
        rule: TemporalRule,
        event: TemporalEvent,
        agent_events: list[TemporalEvent],
    ) -> list[TemporalViolation]:
        """A must always precede B. Triggered when B occurs without prior A."""
        if len(rule.actions) < 2:
            return []
        action_a, action_b = rule.actions[0], rule.actions[1]
        if event.event_type != action_b:
            return []
        # Check if A ever occurred before this event.
        prior = [
            e for e in agent_events if e.event_type == action_a and e.timestamp < event.timestamp
        ]
        if prior:
            return []
        return [
            TemporalViolation(
                rule_id=rule.rule_id,
                events=(event,),
                description=(
                    f"'{action_b}' occurred without prior '{action_a}'. Rule: {rule.name}."
                ),
                severity=rule.severity,
            )
        ]

    def _check_never_after(
        self,
        rule: TemporalRule,
        event: TemporalEvent,
        agent_events: list[TemporalEvent],
    ) -> list[TemporalViolation]:
        """A must never follow B. Triggered when A occurs after B."""
        if len(rule.actions) < 2:
            return []
        action_a, action_b = rule.actions[0], rule.actions[1]
        if event.event_type != action_a:
            return []
        # Check if B occurred before this event.
        prior_b = [
            e for e in agent_events if e.event_type == action_b and e.timestamp < event.timestamp
        ]
        if not prior_b:
            return []
        return [
            TemporalViolation(
                rule_id=rule.rule_id,
                events=(prior_b[-1], event),
                description=(f"'{action_a}' occurred after '{action_b}'. Rule: {rule.name}."),
                severity=rule.severity,
            )
        ]

    def _check_within_time(
        self,
        rule: TemporalRule,
        event: TemporalEvent,
        agent_events: list[TemporalEvent],
    ) -> list[TemporalViolation]:
        """B must occur within N seconds of A."""
        if len(rule.actions) < 2:
            return []
        action_a, action_b = rule.actions[0], rule.actions[1]
        window_s = float(rule.params.get("window_s", 5.0))

        # We only trigger when we see a *new* event that is NOT action_b,
        # and there is a pending action_a that has expired.
        # But the simpler approach: when action_b arrives, check timing.
        # And when any non-B event arrives, check if a stale A exists.
        if event.event_type == action_b:
            # Check that a corresponding A exists within window.
            prior_a = [
                e
                for e in agent_events
                if e.event_type == action_a and e.timestamp <= event.timestamp
            ]
            if not prior_a:
                return []
            latest_a = prior_a[-1]
            if event.timestamp - latest_a.timestamp <= window_s:
                return []
            return [
                TemporalViolation(
                    rule_id=rule.rule_id,
                    events=(latest_a, event),
                    description=(
                        f"'{action_b}' occurred {event.timestamp - latest_a.timestamp:.2f}s "
                        f"after '{action_a}' (limit: {window_s}s). "
                        f"Rule: {rule.name}."
                    ),
                    severity=rule.severity,
                )
            ]
        return []

    def _check_max_repeat(
        self,
        rule: TemporalRule,
        event: TemporalEvent,
        agent_events: list[TemporalEvent],
    ) -> list[TemporalViolation]:
        """Action A cannot repeat more than N times in a window."""
        if not rule.actions:
            return []
        action_a = rule.actions[0]
        if event.event_type != action_a:
            return []
        max_count = int(rule.params.get("max_count", 3))
        window_s = float(rule.params.get("window_s", 60.0))
        cutoff = event.timestamp - window_s
        recent = [e for e in agent_events if e.event_type == action_a and e.timestamp >= cutoff]
        if len(recent) <= max_count:
            return []
        return [
            TemporalViolation(
                rule_id=rule.rule_id,
                events=tuple(recent[-max_count - 1 :]),
                description=(
                    f"'{action_a}' repeated {len(recent)} times in "
                    f"{window_s}s (max: {max_count}). Rule: {rule.name}."
                ),
                severity=rule.severity,
            )
        ]

    def _check_sequence_rule(
        self,
        rule: TemporalRule,
        event: TemporalEvent,
        agent_events: list[TemporalEvent],
    ) -> list[TemporalViolation]:
        """Actions must occur in exact sequence [A, B, C].

        Violation: the sequence is partially matched but a wrong event
        interrupts it.
        """
        actions = rule.actions
        if len(actions) < 2:
            return []
        if event.event_type != actions[-1]:
            return []
        # Check if the preceding events match the required sequence.
        relevant = [e for e in agent_events if e.event_type in actions]
        if len(relevant) < len(actions):
            return []
        # Take the last len(actions) relevant events.
        tail = relevant[-len(actions) :]
        actual_sequence = tuple(e.event_type for e in tail)
        if actual_sequence == tuple(actions):
            return []  # Sequence is correct.
        return [
            TemporalViolation(
                rule_id=rule.rule_id,
                events=tuple(tail),
                description=(
                    f"Expected sequence {list(actions)} but got "
                    f"{list(actual_sequence)}. Rule: {rule.name}."
                ),
                severity=rule.severity,
            )
        ]

    def _check_forbidden_sequence(
        self,
        rule: TemporalRule,
        event: TemporalEvent,
        agent_events: list[TemporalEvent],
    ) -> list[TemporalViolation]:
        """Sequence [A, B] must never occur."""
        actions = rule.actions
        if len(actions) < 2:
            return []
        if event.event_type != actions[-1]:
            return []
        # Check if the forbidden sequence just completed.
        seq_len = len(actions)
        relevant = [e for e in agent_events if e.event_type in actions]
        if len(relevant) < seq_len:
            return []
        tail = relevant[-seq_len:]
        actual = tuple(e.event_type for e in tail)
        if actual != tuple(actions):
            return []
        return [
            TemporalViolation(
                rule_id=rule.rule_id,
                events=tuple(tail),
                description=(f"Forbidden sequence {list(actions)} detected. Rule: {rule.name}."),
                severity=rule.severity,
            )
        ]
