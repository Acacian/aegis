"""Tests for the Temporal Monitor module."""

from __future__ import annotations

import threading
import time

import pytest

from aegis.core.temporal_monitor import (
    MonitorState,
    PatternType,
    TemporalEvent,
    TemporalMonitor,
    TemporalRule,
    TemporalViolation,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEQ = 0


def _event(
    event_type: str,
    agent_id: str = "agent-1",
    timestamp: float | None = None,
) -> TemporalEvent:
    global _SEQ
    _SEQ += 1
    return TemporalEvent(
        event_id=f"evt-{_SEQ}",
        event_type=event_type,
        agent_id=agent_id,
        timestamp=timestamp if timestamp is not None else time.time(),
    )


# ---------------------------------------------------------------------------
# Frozen dataclass smoke tests
# ---------------------------------------------------------------------------


class TestDataModels:
    def test_temporal_rule_frozen(self) -> None:
        r = TemporalRule(rule_id="r1", name="test", pattern="always_before", description="d")
        with pytest.raises(AttributeError):
            r.rule_id = "r2"  # type: ignore[misc]

    def test_temporal_event_frozen(self) -> None:
        e = TemporalEvent(event_id="e1", event_type="read", agent_id="a")
        with pytest.raises(AttributeError):
            e.event_type = "write"  # type: ignore[misc]

    def test_temporal_violation_frozen(self) -> None:
        v = TemporalViolation(rule_id="r1")
        with pytest.raises(AttributeError):
            v.rule_id = "r2"  # type: ignore[misc]

    def test_monitor_state_frozen(self) -> None:
        s = MonitorState(total_events=0, violations=0, active_rules=0)
        with pytest.raises(AttributeError):
            s.total_events = 5  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Rule management
# ---------------------------------------------------------------------------


class TestRuleManagement:
    def test_add_and_remove_rule(self) -> None:
        m = TemporalMonitor()
        rule = TemporalRule(
            rule_id="r1",
            name="test",
            pattern=PatternType.ALWAYS_BEFORE,
            description="A before B",
            actions=("auth", "access"),
        )
        m.add_rule(rule)
        state = m.get_state()
        assert state.active_rules == 1

        assert m.remove_rule("r1") is True
        assert m.get_state().active_rules == 0

    def test_remove_nonexistent_rule(self) -> None:
        m = TemporalMonitor()
        assert m.remove_rule("nonexistent") is False


# ---------------------------------------------------------------------------
# ALWAYS_BEFORE pattern
# ---------------------------------------------------------------------------


class TestAlwaysBefore:
    def test_violation_when_b_without_a(self) -> None:
        m = TemporalMonitor()
        rule = TemporalRule(
            rule_id="r1",
            name="auth_before_access",
            pattern=PatternType.ALWAYS_BEFORE,
            description="Auth must precede access",
            actions=("auth", "access"),
        )
        m.add_rule(rule)
        violations = m.record_event(_event("access"))
        assert len(violations) == 1
        assert violations[0].rule_id == "r1"
        assert "auth" in violations[0].description

    def test_no_violation_when_a_precedes_b(self) -> None:
        m = TemporalMonitor()
        rule = TemporalRule(
            rule_id="r1",
            name="auth_before_access",
            pattern=PatternType.ALWAYS_BEFORE,
            description="Auth must precede access",
            actions=("auth", "access"),
        )
        m.add_rule(rule)
        m.record_event(_event("auth"))
        violations = m.record_event(_event("access"))
        assert len(violations) == 0

    def test_no_violation_for_unrelated_event(self) -> None:
        m = TemporalMonitor()
        rule = TemporalRule(
            rule_id="r1",
            name="auth_before_access",
            pattern=PatternType.ALWAYS_BEFORE,
            description="d",
            actions=("auth", "access"),
        )
        m.add_rule(rule)
        violations = m.record_event(_event("other_action"))
        assert len(violations) == 0


# ---------------------------------------------------------------------------
# NEVER_AFTER pattern
# ---------------------------------------------------------------------------


class TestNeverAfter:
    def test_violation_when_a_follows_b(self) -> None:
        m = TemporalMonitor()
        rule = TemporalRule(
            rule_id="r1",
            name="no_delete_after_archive",
            pattern=PatternType.NEVER_AFTER,
            description="Delete must never follow archive",
            actions=("delete", "archive"),
        )
        m.add_rule(rule)
        m.record_event(_event("archive"))
        violations = m.record_event(_event("delete"))
        assert len(violations) == 1
        assert "delete" in violations[0].description

    def test_no_violation_without_prior_b(self) -> None:
        m = TemporalMonitor()
        rule = TemporalRule(
            rule_id="r1",
            name="no_delete_after_archive",
            pattern=PatternType.NEVER_AFTER,
            description="d",
            actions=("delete", "archive"),
        )
        m.add_rule(rule)
        violations = m.record_event(_event("delete"))
        assert len(violations) == 0


# ---------------------------------------------------------------------------
# WITHIN_TIME pattern
# ---------------------------------------------------------------------------


class TestWithinTime:
    def test_violation_when_b_too_late(self) -> None:
        m = TemporalMonitor()
        rule = TemporalRule(
            rule_id="r1",
            name="confirm_within_5s",
            pattern=PatternType.WITHIN_TIME,
            description="Confirm within 5s of request",
            actions=("request", "confirm"),
            params={"window_s": 5.0},
        )
        m.add_rule(rule)
        now = time.time()
        m.record_event(_event("request", timestamp=now - 10.0))
        violations = m.record_event(_event("confirm", timestamp=now))
        assert len(violations) == 1
        assert "5.0" in violations[0].description

    def test_no_violation_when_b_within_window(self) -> None:
        m = TemporalMonitor()
        rule = TemporalRule(
            rule_id="r1",
            name="confirm_within_5s",
            pattern=PatternType.WITHIN_TIME,
            description="d",
            actions=("request", "confirm"),
            params={"window_s": 5.0},
        )
        m.add_rule(rule)
        now = time.time()
        m.record_event(_event("request", timestamp=now - 2.0))
        violations = m.record_event(_event("confirm", timestamp=now))
        assert len(violations) == 0


# ---------------------------------------------------------------------------
# MAX_REPEAT pattern
# ---------------------------------------------------------------------------


class TestMaxRepeat:
    def test_violation_on_excess_repeats(self) -> None:
        m = TemporalMonitor()
        rule = TemporalRule(
            rule_id="r1",
            name="max_3_retries",
            pattern=PatternType.MAX_REPEAT,
            description="Max 3 retries in 60s",
            actions=("retry",),
            params={"max_count": 3, "window_s": 60.0},
        )
        m.add_rule(rule)
        now = time.time()
        for i in range(3):
            m.record_event(_event("retry", timestamp=now + i))
        violations = m.record_event(_event("retry", timestamp=now + 3))
        assert len(violations) == 1
        assert "4" in violations[0].description

    def test_no_violation_within_limit(self) -> None:
        m = TemporalMonitor()
        rule = TemporalRule(
            rule_id="r1",
            name="max_3_retries",
            pattern=PatternType.MAX_REPEAT,
            description="d",
            actions=("retry",),
            params={"max_count": 3, "window_s": 60.0},
        )
        m.add_rule(rule)
        now = time.time()
        for i in range(3):
            violations = m.record_event(_event("retry", timestamp=now + i))
        assert len(violations) == 0


# ---------------------------------------------------------------------------
# SEQUENCE pattern
# ---------------------------------------------------------------------------


class TestSequence:
    def test_correct_sequence_no_violation(self) -> None:
        m = TemporalMonitor()
        rule = TemporalRule(
            rule_id="r1",
            name="abc_sequence",
            pattern=PatternType.SEQUENCE,
            description="Must follow A-B-C",
            actions=("A", "B", "C"),
        )
        m.add_rule(rule)
        m.record_event(_event("A"))
        m.record_event(_event("B"))
        violations = m.record_event(_event("C"))
        assert len(violations) == 0

    def test_wrong_sequence_violation(self) -> None:
        m = TemporalMonitor()
        rule = TemporalRule(
            rule_id="r1",
            name="abc_sequence",
            pattern=PatternType.SEQUENCE,
            description="Must follow A-B-C",
            actions=("A", "B", "C"),
        )
        m.add_rule(rule)
        m.record_event(_event("B"))
        m.record_event(_event("A"))
        violations = m.record_event(_event("C"))
        assert len(violations) == 1


# ---------------------------------------------------------------------------
# FORBIDDEN_SEQUENCE pattern
# ---------------------------------------------------------------------------


class TestForbiddenSequence:
    def test_forbidden_sequence_detected(self) -> None:
        m = TemporalMonitor()
        rule = TemporalRule(
            rule_id="r1",
            name="no_read_then_delete",
            pattern=PatternType.FORBIDDEN_SEQUENCE,
            description="read-then-delete is forbidden",
            actions=("read", "delete"),
        )
        m.add_rule(rule)
        m.record_event(_event("read"))
        violations = m.record_event(_event("delete"))
        assert len(violations) == 1
        assert "Forbidden" in violations[0].description

    def test_no_violation_for_non_forbidden(self) -> None:
        m = TemporalMonitor()
        rule = TemporalRule(
            rule_id="r1",
            name="no_read_then_delete",
            pattern=PatternType.FORBIDDEN_SEQUENCE,
            description="d",
            actions=("read", "delete"),
        )
        m.add_rule(rule)
        m.record_event(_event("write"))
        violations = m.record_event(_event("delete"))
        assert len(violations) == 0


# ---------------------------------------------------------------------------
# Batch sequence check
# ---------------------------------------------------------------------------


class TestBatchCheck:
    def test_check_sequence_batch(self) -> None:
        m = TemporalMonitor()
        rule = TemporalRule(
            rule_id="r1",
            name="auth_before_access",
            pattern=PatternType.ALWAYS_BEFORE,
            description="d",
            actions=("auth", "access"),
        )
        m.add_rule(rule)
        events = [_event("access"), _event("auth")]
        violations = m.check_sequence(events)
        # First event is "access" without prior "auth" -> violation.
        assert len(violations) >= 1


# ---------------------------------------------------------------------------
# Get violations with filters
# ---------------------------------------------------------------------------


class TestGetViolations:
    def test_get_all_violations(self) -> None:
        m = TemporalMonitor()
        rule = TemporalRule(
            rule_id="r1",
            name="test",
            pattern=PatternType.ALWAYS_BEFORE,
            description="d",
            actions=("auth", "access"),
        )
        m.add_rule(rule)
        m.record_event(_event("access", agent_id="a1"))
        m.record_event(_event("access", agent_id="a2"))
        all_v = m.get_violations()
        assert len(all_v) == 2

    def test_filter_by_agent(self) -> None:
        m = TemporalMonitor()
        rule = TemporalRule(
            rule_id="r1",
            name="test",
            pattern=PatternType.ALWAYS_BEFORE,
            description="d",
            actions=("auth", "access"),
        )
        m.add_rule(rule)
        m.record_event(_event("access", agent_id="a1"))
        m.record_event(_event("access", agent_id="a2"))
        filtered = m.get_violations(agent_id="a1")
        assert len(filtered) == 1

    def test_filter_by_rule(self) -> None:
        m = TemporalMonitor()
        r1 = TemporalRule(
            rule_id="r1",
            name="t1",
            pattern=PatternType.ALWAYS_BEFORE,
            description="d",
            actions=("auth", "access"),
        )
        r2 = TemporalRule(
            rule_id="r2",
            name="t2",
            pattern=PatternType.FORBIDDEN_SEQUENCE,
            description="d",
            actions=("read", "delete"),
        )
        m.add_rule(r1)
        m.add_rule(r2)
        m.record_event(_event("access"))
        m.record_event(_event("read"))
        m.record_event(_event("delete"))
        by_r2 = m.get_violations(rule_id="r2")
        assert all(v.rule_id == "r2" for v in by_r2)


# ---------------------------------------------------------------------------
# Monitor state
# ---------------------------------------------------------------------------


class TestMonitorState:
    def test_state_after_events(self) -> None:
        m = TemporalMonitor()
        rule = TemporalRule(
            rule_id="r1",
            name="test",
            pattern=PatternType.ALWAYS_BEFORE,
            description="d",
            actions=("auth", "access"),
        )
        m.add_rule(rule)
        m.record_event(_event("access"))
        state = m.get_state()
        assert state.total_events == 1
        assert state.violations == 1
        assert state.active_rules == 1

    def test_empty_state(self) -> None:
        m = TemporalMonitor()
        state = m.get_state()
        assert state.total_events == 0
        assert state.violations == 0
        assert state.active_rules == 0


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_record_and_check(self) -> None:
        m = TemporalMonitor()
        rule = TemporalRule(
            rule_id="r1",
            name="test",
            pattern=PatternType.ALWAYS_BEFORE,
            description="d",
            actions=("auth", "access"),
        )
        m.add_rule(rule)
        errors: list[Exception] = []

        def recorder(agent_id: str) -> None:
            try:
                for _ in range(50):
                    m.record_event(_event("access", agent_id=agent_id))
            except Exception as exc:
                errors.append(exc)

        def checker() -> None:
            try:
                for _ in range(50):
                    m.get_violations()
                    m.get_state()
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=recorder, args=(f"a{i}",)) for i in range(3)]
        threads.append(threading.Thread(target=checker))
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        assert errors == []


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_rule_with_single_action(self) -> None:
        """Rules that require 2 actions should not crash with 1."""
        m = TemporalMonitor()
        rule = TemporalRule(
            rule_id="r1",
            name="broken",
            pattern=PatternType.ALWAYS_BEFORE,
            description="d",
            actions=("only_one",),
        )
        m.add_rule(rule)
        violations = m.record_event(_event("only_one"))
        assert len(violations) == 0

    def test_multiple_rules_same_event(self) -> None:
        m = TemporalMonitor()
        r1 = TemporalRule(
            rule_id="r1",
            name="t1",
            pattern=PatternType.ALWAYS_BEFORE,
            description="d",
            actions=("auth", "access"),
        )
        r2 = TemporalRule(
            rule_id="r2",
            name="t2",
            pattern=PatternType.NEVER_AFTER,
            description="d",
            actions=("access", "logout"),
        )
        m.add_rule(r1)
        m.add_rule(r2)
        m.record_event(_event("logout"))
        # access without auth -> r1 violation; access after logout -> r2 violation
        violations = m.record_event(_event("access"))
        rule_ids = {v.rule_id for v in violations}
        assert "r1" in rule_ids
        assert "r2" in rule_ids
