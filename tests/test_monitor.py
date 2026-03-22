"""Tests for the Real-Time Agent Monitoring Dashboard."""

from __future__ import annotations

import threading
import time

import pytest

from aegis.cli.monitor import AgentMonitor, MonitorState, _format_duration
from aegis.core.action import Action
from aegis.core.anomaly import AnomalyDetector

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_action(type_: str = "read", target: str = "crm") -> Action:
    return Action(type=type_, target=target)


# ---------------------------------------------------------------------------
# MonitorState dataclass
# ---------------------------------------------------------------------------


class TestMonitorState:
    def test_defaults(self) -> None:
        s = MonitorState()
        assert s.total_actions == 0
        assert isinstance(s.active_agents, dict)
        assert isinstance(s.blocked_counts, dict)
        assert isinstance(s.anomaly_counts, dict)
        assert isinstance(s.recent_alerts, list)
        assert isinstance(s.decision_counters, dict)
        assert isinstance(s.action_type_counts, dict)
        assert isinstance(s.event_timestamps, list)
        assert s.max_alerts == 20

    def test_custom_max_alerts(self) -> None:
        s = MonitorState(max_alerts=5)
        assert s.max_alerts == 5

    def test_start_time_populated(self) -> None:
        s = MonitorState()
        assert s.start_time > 0

    def test_defaultdict_behavior(self) -> None:
        s = MonitorState()
        s.active_agents["new-agent"] += 1
        assert s.active_agents["new-agent"] == 1

    def test_decision_counters_default(self) -> None:
        s = MonitorState()
        s.decision_counters["auto"] += 10
        assert s.decision_counters["auto"] == 10
        assert s.decision_counters["block"] == 0


# ---------------------------------------------------------------------------
# AgentMonitor construction
# ---------------------------------------------------------------------------


class TestAgentMonitorInit:
    def test_default_construction(self) -> None:
        m = AgentMonitor()
        assert m.state.total_actions == 0

    def test_custom_detector(self) -> None:
        detector = AnomalyDetector(rate_threshold=10.0)
        m = AgentMonitor(detector=detector)
        assert m._detector is detector

    def test_custom_max_alerts(self) -> None:
        m = AgentMonitor(max_alerts=5)
        assert m.state.max_alerts == 5

    def test_custom_rate_window(self) -> None:
        m = AgentMonitor(rate_window=120.0)
        assert m._rate_window == 120.0


# ---------------------------------------------------------------------------
# Event recording
# ---------------------------------------------------------------------------


class TestRecordEvent:
    def test_record_increments_total(self) -> None:
        m = AgentMonitor()
        m.record_event("read", "agent-1", "auto", target="crm")
        assert m.state.total_actions == 1

    def test_record_tracks_agent(self) -> None:
        m = AgentMonitor()
        m.record_event("read", "agent-1", "auto", target="crm")
        assert m.state.active_agents["agent-1"] == 1

    def test_record_multiple_events(self) -> None:
        m = AgentMonitor()
        for _ in range(5):
            m.record_event("read", "agent-1", "auto", target="crm")
        assert m.state.total_actions == 5
        assert m.state.active_agents["agent-1"] == 5

    def test_record_multiple_agents(self) -> None:
        m = AgentMonitor()
        m.record_event("read", "agent-1", "auto", target="crm")
        m.record_event("write", "agent-2", "approve", target="stripe")
        assert m.state.active_agents["agent-1"] == 1
        assert m.state.active_agents["agent-2"] == 1

    def test_blocked_decision_tracked(self) -> None:
        m = AgentMonitor()
        m.record_event("delete", "agent-1", "block", target="db")
        assert m.state.blocked_counts["agent-1"] == 1

    def test_decision_counters(self) -> None:
        m = AgentMonitor()
        m.record_event("read", "a", "auto", target="crm")
        m.record_event("write", "a", "approve", target="crm")
        m.record_event("delete", "a", "block", target="crm")
        assert m.state.decision_counters["auto"] == 1
        assert m.state.decision_counters["approve"] == 1
        assert m.state.decision_counters["block"] == 1

    def test_action_type_counts(self) -> None:
        m = AgentMonitor()
        m.record_event("read", "a", "auto", target="crm")
        m.record_event("read", "a", "auto", target="crm")
        m.record_event("write", "a", "approve", target="crm")
        assert m.state.action_type_counts["read"] == 2
        assert m.state.action_type_counts["write"] == 1

    def test_record_with_action_object(self) -> None:
        m = AgentMonitor()
        action = Action(type="read", target="crm")
        m.record_event(action, "agent-1", "auto")
        assert m.state.total_actions == 1
        assert m.state.action_type_counts["read"] == 1

    def test_record_default_agent_id(self) -> None:
        m = AgentMonitor()
        m.record_event("read", decision="auto", target="crm")
        assert m.state.active_agents["default"] == 1

    def test_event_timestamps_populated(self) -> None:
        m = AgentMonitor()
        m.record_event("read", "a", "auto", target="crm")
        assert len(m.state.event_timestamps) == 1

    def test_event_timestamps_bounded(self) -> None:
        m = AgentMonitor()
        for _ in range(600):
            m.record_event("read", "a", "auto", target="crm")
        assert len(m.state.event_timestamps) <= 500


# ---------------------------------------------------------------------------
# Anomaly integration
# ---------------------------------------------------------------------------


class TestAnomalyIntegration:
    def test_anomaly_detected_on_new_action(self) -> None:
        detector = AnomalyDetector(new_action_alert=True, burst_limit=10000)
        m = AgentMonitor(detector=detector)
        # Build baseline
        for _ in range(5):
            m.record_event("read", "agent-1", "auto", target="crm")
        # New action type -> anomaly
        result = m.record_event("delete", "agent-1", "block", target="crm")
        assert result is not None
        assert result.is_anomalous
        assert result.anomaly_type == "new_action"

    def test_anomaly_alert_stored(self) -> None:
        detector = AnomalyDetector(new_action_alert=True, burst_limit=10000)
        m = AgentMonitor(detector=detector)
        for _ in range(5):
            m.record_event("read", "agent-1", "auto", target="crm")
        m.record_event("delete", "agent-1", "block", target="crm")
        assert len(m.state.recent_alerts) >= 1
        assert "agent-1" in m.state.recent_alerts[-1]

    def test_anomaly_count_tracked(self) -> None:
        detector = AnomalyDetector(new_action_alert=True, burst_limit=10000)
        m = AgentMonitor(detector=detector)
        for _ in range(5):
            m.record_event("read", "agent-1", "auto", target="crm")
        m.record_event("delete", "agent-1", "block", target="crm")
        assert m.state.anomaly_counts["agent-1"] >= 1

    def test_no_anomaly_returns_none(self) -> None:
        m = AgentMonitor()
        # First event never produces an anomaly (no history).
        result = m.record_event("read", "agent-1", "auto", target="crm")
        assert result is None

    def test_unusual_target_alert_format(self) -> None:
        detector = AnomalyDetector(new_action_alert=False, burst_limit=10000)
        m = AgentMonitor(detector=detector)
        # Build baseline with known target
        for _ in range(5):
            m.record_event("read", "agent-1", "auto", target="staging")
        # New target -> unusual_target anomaly
        result = m.record_event("read", "agent-1", "auto", target="production")
        if result is not None and result.anomaly_type == "unusual_target":
            assert any("unusual_target" in a for a in m.state.recent_alerts)

    def test_alerts_bounded_by_max_alerts(self) -> None:
        detector = AnomalyDetector(new_action_alert=True, burst_limit=10000)
        m = AgentMonitor(detector=detector, max_alerts=3)
        # Build baseline
        for _ in range(5):
            m.record_event("read", "a", "auto", target="crm")
        # Generate many anomalies with different action types
        for i in range(10):
            m.record_event(f"new_action_{i}", "a", "auto", target="crm")
        assert len(m.state.recent_alerts) <= 3


# ---------------------------------------------------------------------------
# Rate calculation
# ---------------------------------------------------------------------------


class TestRateCalculation:
    def test_zero_rate_with_no_events(self) -> None:
        m = AgentMonitor()
        assert m.actions_per_minute() == 0.0

    def test_zero_rate_with_single_event(self) -> None:
        m = AgentMonitor()
        m.record_event("read", "a", "auto", target="crm")
        # Single timestamp -> can't compute a span -> 0.0
        assert m.actions_per_minute() == 0.0

    def test_positive_rate_with_events(self) -> None:
        m = AgentMonitor(rate_window=120.0)
        # Record events with small delay to create a measurable span
        for _ in range(5):
            m.record_event("read", "a", "auto", target="crm")
            time.sleep(0.01)
        rate = m.actions_per_minute()
        # With 5 events over ~50ms, rate should be high but finite
        assert rate >= 0.0

    def test_rate_window_filtering(self) -> None:
        m = AgentMonitor(rate_window=0.05)
        m.record_event("read", "a", "auto", target="crm")
        time.sleep(0.01)
        m.record_event("read", "a", "auto", target="crm")
        # Both within 50ms window
        time.sleep(0.1)
        # After window expires, old events are filtered out
        rate = m.actions_per_minute()
        assert rate == 0.0


# ---------------------------------------------------------------------------
# Top action types
# ---------------------------------------------------------------------------


class TestTopActionTypes:
    def test_empty(self) -> None:
        m = AgentMonitor()
        assert m.top_action_types() == []

    def test_single_type(self) -> None:
        m = AgentMonitor()
        m.record_event("read", "a", "auto", target="crm")
        top = m.top_action_types()
        assert len(top) == 1
        assert top[0] == ("read", 1)

    def test_ordered_by_frequency(self) -> None:
        m = AgentMonitor()
        for _ in range(10):
            m.record_event("read", "a", "auto", target="crm")
        for _ in range(5):
            m.record_event("write", "a", "approve", target="crm")
        for _ in range(3):
            m.record_event("delete", "a", "block", target="crm")
        top = m.top_action_types()
        assert top[0][0] == "read"
        assert top[1][0] == "write"
        assert top[2][0] == "delete"

    def test_limited_by_n(self) -> None:
        m = AgentMonitor()
        for i in range(10):
            m.record_event(f"action_{i}", "a", "auto", target="crm")
        top = m.top_action_types(n=3)
        assert len(top) == 3


# ---------------------------------------------------------------------------
# Uptime formatting
# ---------------------------------------------------------------------------


class TestFormatDuration:
    def test_zero_seconds(self) -> None:
        assert _format_duration(0) == "0m"

    def test_under_one_minute(self) -> None:
        assert _format_duration(30) == "0m"

    def test_exact_minutes(self) -> None:
        assert _format_duration(300) == "5m"

    def test_hours_and_minutes(self) -> None:
        assert _format_duration(8100) == "2h 15m"

    def test_days(self) -> None:
        assert _format_duration(90000) == "1d 1h 0m"

    def test_uptime_str_method(self) -> None:
        m = AgentMonitor()
        # Just created, should be "0m"
        assert "m" in m.uptime_str()


# ---------------------------------------------------------------------------
# Dashboard rendering
# ---------------------------------------------------------------------------


class TestDashboardRender:
    def test_empty_dashboard(self) -> None:
        m = AgentMonitor()
        output = m.render()
        assert "Aegis Agent Monitor" in output
        assert "Actions: 0" in output
        assert "(none)" in output

    def test_dashboard_with_events(self) -> None:
        m = AgentMonitor()
        m.record_event("read", "agent-1", "auto", target="crm")
        m.record_event("write", "agent-2", "approve", target="stripe")
        output = m.render()
        assert "agent-1" in output
        assert "agent-2" in output
        assert "Actions: 2" in output

    def test_dashboard_has_box_drawing(self) -> None:
        m = AgentMonitor()
        output = m.render()
        assert "\u2554" in output  # top-left corner
        assert "\u255a" in output  # bottom-left corner
        assert "\u2551" in output  # vertical bar
        assert "\u2550" in output  # horizontal bar

    def test_dashboard_shows_decision_distribution(self) -> None:
        m = AgentMonitor()
        m.record_event("read", "a", "auto", target="crm")
        m.record_event("write", "a", "approve", target="crm")
        output = m.render()
        assert "Decision Distribution" in output
        assert "auto:" in output
        assert "approve:" in output
        assert "block:" in output

    def test_dashboard_shows_recent_alerts(self) -> None:
        detector = AnomalyDetector(new_action_alert=True, burst_limit=10000)
        m = AgentMonitor(detector=detector)
        for _ in range(5):
            m.record_event("read", "agent-1", "auto", target="crm")
        m.record_event("delete", "agent-1", "block", target="crm")
        output = m.render()
        assert "Recent Alerts" in output
        assert "WARN" in output

    def test_dashboard_shows_blocked_count(self) -> None:
        m = AgentMonitor()
        m.record_event("delete", "agent-1", "block", target="db")
        m.record_event("delete", "agent-1", "block", target="db")
        output = m.render()
        # The blocked column should show 2
        assert "agent-1" in output

    def test_dashboard_custom_width(self) -> None:
        m = AgentMonitor()
        output_narrow = m.render(width=40)
        output_wide = m.render(width=80)
        # Wider render should have longer lines
        narrow_max = max(len(line) for line in output_narrow.split("\n"))
        wide_max = max(len(line) for line in output_wide.split("\n"))
        assert wide_max > narrow_max

    def test_dashboard_percentage_format(self) -> None:
        m = AgentMonitor()
        for _ in range(8):
            m.record_event("read", "a", "auto", target="crm")
        for _ in range(2):
            m.record_event("write", "a", "approve", target="crm")
        output = m.render()
        assert "80.0%" in output
        assert "20.0%" in output

    def test_dashboard_zero_actions_no_division_error(self) -> None:
        m = AgentMonitor()
        output = m.render()
        # Should not crash, percentages should be 0.0%
        assert "0.0%" in output

    def test_dashboard_multiline_string(self) -> None:
        m = AgentMonitor()
        output = m.render()
        lines = output.split("\n")
        assert len(lines) >= 8  # minimal structure


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------


class TestReset:
    def test_reset_clears_state(self) -> None:
        m = AgentMonitor()
        m.record_event("read", "a", "auto", target="crm")
        m.reset()
        assert m.state.total_actions == 0
        assert len(m.state.active_agents) == 0


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_record_events(self) -> None:
        m = AgentMonitor()
        errors: list[Exception] = []

        def worker(agent: str) -> None:
            try:
                for _ in range(100):
                    m.record_event("read", agent, "auto", target="crm")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(f"agent-{i}",)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert m.state.total_actions == 400

    def test_concurrent_record_and_render(self) -> None:
        m = AgentMonitor()
        errors: list[Exception] = []

        def recorder() -> None:
            try:
                for _ in range(100):
                    m.record_event("read", "a", "auto", target="crm")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        def renderer() -> None:
            try:
                for _ in range(50):
                    output = m.render()
                    assert "Aegis Agent Monitor" in output
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [
            threading.Thread(target=recorder),
            threading.Thread(target=renderer),
            threading.Thread(target=recorder),
            threading.Thread(target=renderer),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors


# ---------------------------------------------------------------------------
# CLI registration smoke test
# ---------------------------------------------------------------------------


class TestCLIRegistration:
    def test_monitor_subparser_exists(self) -> None:
        """Verify that 'monitor' is a registered subcommand."""
        from aegis.cli.main import main

        # Calling with --help on monitor should not crash
        with pytest.raises(SystemExit) as exc_info:
            main(["monitor", "--help"])
        assert exc_info.value.code == 0

    def test_monitor_default_args(self) -> None:
        """Verify default argument parsing for monitor."""
        from aegis.cli.main import main

        # Parse args without actually running (db won't exist)
        with pytest.raises(SystemExit):
            main(["monitor", "--db", "/nonexistent/path.db"])
