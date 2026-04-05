"""Tests for the Cascade Guard engine (OWASP ASI08)."""

from __future__ import annotations

import threading
import time

import pytest

from aegis.core.cascade_guard import (
    AgentHealth,
    AgentState,
    CascadeDecision,
    CascadeEvent,
    CascadeEventType,
    CascadeGuard,
    CascadeReport,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_guard(
    failure_threshold: float = 0.5,
    window_s: float = 60.0,
    quarantine_s: float = 0.1,
    max_propagation_depth: int = 3,
) -> CascadeGuard:
    return CascadeGuard(
        failure_threshold=failure_threshold,
        window_s=window_s,
        quarantine_s=quarantine_s,
        max_propagation_depth=max_propagation_depth,
    )


def _degrade(guard: CascadeGuard, agent_id: str) -> None:
    """Push an agent into degraded/quarantined state via failures."""
    for _ in range(5):
        guard.record_failure(agent_id, "err")


# ---------------------------------------------------------------------------
# Frozen dataclass invariants
# ---------------------------------------------------------------------------


class TestDataModels:
    def test_agent_health_frozen(self) -> None:
        h = AgentHealth("a", 1, 0, 0.0, None, AgentState.HEALTHY)
        with pytest.raises(AttributeError):
            h.agent_id = "b"  # type: ignore[misc]

    def test_cascade_event_frozen(self) -> None:
        e = CascadeEvent("a", "b", CascadeEventType.BLOCKED, 0.0, "", 0)
        with pytest.raises(AttributeError):
            e.source_agent = "x"  # type: ignore[misc]

    def test_cascade_decision_frozen(self) -> None:
        h = AgentHealth("a", 0, 0, 0.0, None, AgentState.HEALTHY)
        d = CascadeDecision(True, "ok", h, h, 0)
        with pytest.raises(AttributeError):
            d.allowed = False  # type: ignore[misc]

    def test_cascade_report_frozen(self) -> None:
        r = CascadeReport(0, 0, 0, 0, 0, {})
        with pytest.raises(AttributeError):
            r.total_agents = 5  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Healthy agent operations
# ---------------------------------------------------------------------------


class TestHealthyAgent:
    def test_unknown_agent_can_proceed(self) -> None:
        guard = _make_guard()
        assert guard.can_proceed("unknown") is True

    def test_healthy_agent_can_proceed(self) -> None:
        guard = _make_guard()
        guard.record_success("agent-a")
        assert guard.can_proceed("agent-a") is True

    def test_healthy_state_after_successes(self) -> None:
        guard = _make_guard()
        for _ in range(10):
            guard.record_success("a")
        health = guard.get_health("a")
        assert health.state == AgentState.HEALTHY
        assert health.error_rate == 0.0
        assert health.success_count == 10


# ---------------------------------------------------------------------------
# Degradation and quarantine
# ---------------------------------------------------------------------------


class TestDegradation:
    def test_failures_trigger_degraded_then_quarantine(self) -> None:
        guard = _make_guard(failure_threshold=0.5)
        guard.record_success("a")
        # Two failures against one success -> rate = 2/3 > 0.5 -> degraded
        guard.record_failure("a", "e1")
        h = guard.record_failure("a", "e2")
        # After >=3 failures at high rate, auto-quarantine kicks in
        h = guard.record_failure("a", "e3")
        assert h.state == AgentState.QUARANTINED

    def test_quarantine_blocks_proceed(self) -> None:
        guard = _make_guard()
        _degrade(guard, "a")
        assert guard.can_proceed("a") is False

    def test_manual_quarantine(self) -> None:
        guard = _make_guard()
        guard.quarantine("a", "suspicious")
        assert guard.can_proceed("a") is False
        health = guard.get_health("a")
        assert health.state == AgentState.QUARANTINED

    def test_quarantine_auto_expires(self) -> None:
        guard = _make_guard(quarantine_s=0.05)
        guard.quarantine("a", "temp")
        assert guard.can_proceed("a") is False
        time.sleep(0.06)
        assert guard.can_proceed("a") is True

    def test_release_before_expiry_fails(self) -> None:
        guard = _make_guard(quarantine_s=100.0)
        guard.quarantine("a")
        assert guard.release("a") is False

    def test_release_after_expiry_succeeds(self) -> None:
        guard = _make_guard(quarantine_s=0.05)
        guard.quarantine("a")
        time.sleep(0.06)
        assert guard.release("a") is True
        assert guard.get_health("a").state == AgentState.HEALTHY


# ---------------------------------------------------------------------------
# Cascade checks
# ---------------------------------------------------------------------------


class TestCascadeChecks:
    def test_healthy_to_healthy_allowed(self) -> None:
        guard = _make_guard()
        guard.record_success("src")
        guard.record_success("tgt")
        decision = guard.check_cascade("src", "tgt")
        assert decision.allowed is True
        assert decision.propagation_depth == 0

    def test_quarantined_source_blocked(self) -> None:
        guard = _make_guard()
        guard.quarantine("src")
        decision = guard.check_cascade("src", "tgt")
        assert decision.allowed is False
        assert "quarantined" in decision.reason

    def test_quarantined_target_blocked(self) -> None:
        guard = _make_guard()
        guard.quarantine("tgt")
        guard.record_success("src")
        decision = guard.check_cascade("src", "tgt")
        assert decision.allowed is False
        assert "quarantined" in decision.reason

    def test_depth_limit_blocks(self) -> None:
        guard = _make_guard(max_propagation_depth=2)
        decision = guard.check_cascade("a", "b", depth=3)
        assert decision.allowed is False
        assert "depth" in decision.reason

    def test_depth_at_limit_allowed(self) -> None:
        guard = _make_guard(max_propagation_depth=3)
        decision = guard.check_cascade("a", "b", depth=3)
        assert decision.allowed is True

    def test_degraded_to_degraded_blocked(self) -> None:
        guard = _make_guard(failure_threshold=0.5, quarantine_s=999.0)
        # Make both agents degraded but not quarantined:
        # 1 success + 1 failure = 50% error rate = degraded, but < 3 failures
        # so auto-quarantine won't trigger.
        guard.record_success("src")
        guard.record_failure("src")
        guard.record_success("tgt")
        guard.record_failure("tgt")
        decision = guard.check_cascade("src", "tgt")
        assert decision.allowed is False
        assert "amplification" in decision.reason


# ---------------------------------------------------------------------------
# Sliding window
# ---------------------------------------------------------------------------


class TestSlidingWindow:
    def test_old_failures_expire(self) -> None:
        guard = _make_guard(window_s=0.05)
        guard.record_failure("a")
        guard.record_failure("a")
        time.sleep(0.06)
        # After window, old failures expire -- agent is healthy again
        guard.record_success("a")
        health = guard.get_health("a")
        assert health.failure_count == 0
        assert health.state == AgentState.HEALTHY

    def test_error_rate_reflects_window(self) -> None:
        guard = _make_guard(window_s=0.05)
        guard.record_failure("a")
        time.sleep(0.06)
        guard.record_success("a")
        health = guard.get_health("a")
        # Old failure expired; only the success remains
        assert health.error_rate == 0.0


# ---------------------------------------------------------------------------
# Events and reporting
# ---------------------------------------------------------------------------


class TestEventsAndReport:
    def test_cascade_events_recorded(self) -> None:
        guard = _make_guard()
        guard.check_cascade("a", "b")
        events = guard.get_cascade_events()
        assert len(events) == 1
        assert events[0].source_agent == "a"
        assert events[0].target_agent == "b"

    def test_quarantine_event_recorded(self) -> None:
        guard = _make_guard()
        guard.quarantine("a", "bad actor")
        events = guard.get_cascade_events()
        assert any(e.event_type == CascadeEventType.QUARANTINED for e in events)

    def test_report_counts(self) -> None:
        guard = _make_guard(quarantine_s=999.0)
        guard.record_success("healthy1")
        guard.record_success("healthy2")
        guard.quarantine("bad")
        report = guard.report()
        assert report.total_agents == 3
        assert report.healthy_count == 2
        assert report.quarantined_count == 1
        assert isinstance(report.agents, dict)
        assert "bad" in report.agents

    def test_report_with_degraded(self) -> None:
        guard = _make_guard(failure_threshold=0.5, quarantine_s=999.0)
        guard.record_success("d")
        guard.record_failure("d")
        report = guard.report()
        assert report.degraded_count == 1


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_operations(self) -> None:
        guard = _make_guard()
        barrier = threading.Barrier(4)

        def do_successes() -> None:
            barrier.wait()
            for _ in range(100):
                guard.record_success("shared")

        def do_failures() -> None:
            barrier.wait()
            for _ in range(100):
                guard.record_failure("shared")

        def do_checks() -> None:
            barrier.wait()
            for _ in range(100):
                guard.can_proceed("shared")

        def do_cascades() -> None:
            barrier.wait()
            for _ in range(100):
                guard.check_cascade("shared", "other")

        threads = [
            threading.Thread(target=do_successes),
            threading.Thread(target=do_failures),
            threading.Thread(target=do_checks),
            threading.Thread(target=do_cascades),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        # No crashes; report still works
        report = guard.report()
        assert report.total_agents >= 1
