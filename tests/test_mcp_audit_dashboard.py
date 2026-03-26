"""Tests for MCP security audit dashboard."""

from __future__ import annotations

import json
import threading

import pytest

from aegis.core.mcp_audit_dashboard import (
    DashboardState,
    MCPAuditDashboard,
    _format_timestamp,
    _format_uptime,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def dashboard() -> MCPAuditDashboard:
    """Fresh dashboard with default limits."""
    return MCPAuditDashboard()


@pytest.fixture()
def populated_dashboard() -> MCPAuditDashboard:
    """Dashboard pre-populated with representative data."""
    dash = MCPAuditDashboard()
    dash.register_server("filesystem", 4, "L3_VERIFIED")
    dash.register_server("database", 3, "L2_PINNED")
    dash.register_server("slack", 2, "L1_SCANNED")

    dash.record_call("read_file", "filesystem", decision="allowed", risk_level="low")
    dash.record_call("query", "database", decision="allowed", risk_level="medium")
    dash.record_call(
        "send_message",
        "slack",
        decision="blocked",
        risk_level="high",
        findings_count=2,
    )

    dash.record_alert(
        "critical",
        "escalation",
        "filesystem.read -> slack.send",
        server_name="filesystem",
        tool_name="read_file",
    )
    dash.record_alert(
        "high",
        "shadow",
        'duplicate tool "search" on db + filesystem',
        server_name="database",
    )
    dash.record_alert(
        "medium",
        "response_injection",
        "PII detected in database.query output",
        server_name="database",
        tool_name="query",
    )
    return dash


# ---------------------------------------------------------------------------
# Recording: calls
# ---------------------------------------------------------------------------


class TestRecordCall:
    def test_basic_record(self, dashboard: MCPAuditDashboard) -> None:
        dashboard.record_call("read_file", "filesystem")
        state = dashboard.get_state()
        assert state.stats.total_calls == 1
        assert state.stats.total_allowed == 1
        assert state.stats.total_blocked == 0

    def test_blocked_call(self, dashboard: MCPAuditDashboard) -> None:
        dashboard.register_server("slack", 2)
        dashboard.record_call("send", "slack", decision="blocked")
        state = dashboard.get_state()
        assert state.stats.total_blocked == 1
        assert state.stats.block_rate_percent == 100.0
        # Server blocked count incremented
        srv = state.servers.get("slack")
        assert srv is not None
        assert srv.blocked_count == 1

    def test_multiple_decisions(self, dashboard: MCPAuditDashboard) -> None:
        dashboard.record_call("a", "s1", decision="allowed")
        dashboard.record_call("b", "s1", decision="blocked")
        dashboard.record_call("c", "s1", decision="rate_limited")
        dashboard.record_call("d", "s1", decision="consent_required")
        state = dashboard.get_state()
        assert state.stats.total_calls == 4
        assert state.stats.total_allowed == 1
        assert state.stats.total_blocked == 1

    def test_call_record_fields(self, dashboard: MCPAuditDashboard) -> None:
        dashboard.record_call(
            "tool1",
            "srv1",
            decision="blocked",
            risk_level="critical",
            findings_count=3,
            session_id="sess-42",
        )
        state = dashboard.get_state()
        assert len(state.recent_calls) == 1
        call = state.recent_calls[0]
        assert call.tool_name == "tool1"
        assert call.server_name == "srv1"
        assert call.decision == "blocked"
        assert call.risk_level == "critical"
        assert call.findings_count == 3
        assert call.session_id == "sess-42"
        assert call.timestamp > 0

    def test_call_default_values(self, dashboard: MCPAuditDashboard) -> None:
        dashboard.record_call("t", "s")
        state = dashboard.get_state()
        call = state.recent_calls[0]
        assert call.decision == "allowed"
        assert call.risk_level == "low"
        assert call.findings_count == 0
        assert call.session_id == "default"


# ---------------------------------------------------------------------------
# Recording: alerts
# ---------------------------------------------------------------------------


class TestRecordAlert:
    def test_basic_alert(self, dashboard: MCPAuditDashboard) -> None:
        aid = dashboard.record_alert("high", "escalation", "test escalation")
        assert isinstance(aid, str)
        assert len(aid) == 12
        alerts = dashboard.get_alerts()
        assert len(alerts) == 1
        assert alerts[0].alert_id == aid
        assert alerts[0].severity == "high"
        assert alerts[0].category == "escalation"
        assert alerts[0].detail == "test escalation"
        assert alerts[0].resolved is False

    def test_alert_with_context(self, dashboard: MCPAuditDashboard) -> None:
        dashboard.record_alert(
            "critical",
            "rug_pull",
            "tool definition changed",
            server_name="untrusted",
            tool_name="exec",
        )
        alerts = dashboard.get_alerts()
        assert alerts[0].server_name == "untrusted"
        assert alerts[0].tool_name == "exec"

    def test_multiple_alerts(self, dashboard: MCPAuditDashboard) -> None:
        dashboard.record_alert("critical", "escalation", "a")
        dashboard.record_alert("high", "shadow", "b")
        dashboard.record_alert("low", "response_injection", "c")
        assert len(dashboard.get_alerts()) == 3


# ---------------------------------------------------------------------------
# Resolving alerts
# ---------------------------------------------------------------------------


class TestResolveAlert:
    def test_resolve_existing(self, dashboard: MCPAuditDashboard) -> None:
        aid = dashboard.record_alert("high", "escalation", "test")
        assert dashboard.resolve_alert(aid) is True
        # Unresolved only -> empty
        assert len(dashboard.get_alerts(unresolved_only=True)) == 0
        # All alerts -> still there
        assert len(dashboard.get_alerts(unresolved_only=False)) == 1
        assert dashboard.get_alerts(unresolved_only=False)[0].resolved is True

    def test_resolve_nonexistent(self, dashboard: MCPAuditDashboard) -> None:
        assert dashboard.resolve_alert("nonexistent") is False

    def test_resolve_idempotent(self, dashboard: MCPAuditDashboard) -> None:
        aid = dashboard.record_alert("low", "shadow", "dup")
        dashboard.resolve_alert(aid)
        # Second resolve still returns True (found and already resolved)
        assert dashboard.resolve_alert(aid) is True


# ---------------------------------------------------------------------------
# Alert filtering
# ---------------------------------------------------------------------------


class TestGetAlerts:
    def test_filter_by_severity(self, dashboard: MCPAuditDashboard) -> None:
        dashboard.record_alert("critical", "escalation", "a")
        dashboard.record_alert("high", "shadow", "b")
        dashboard.record_alert("critical", "rug_pull", "c")

        crits = dashboard.get_alerts(severity="critical")
        assert len(crits) == 2
        assert all(a.severity == "critical" for a in crits)

    def test_filter_unresolved_only(self, dashboard: MCPAuditDashboard) -> None:
        aid = dashboard.record_alert("high", "escalation", "a")
        dashboard.record_alert("low", "shadow", "b")
        dashboard.resolve_alert(aid)

        unresolved = dashboard.get_alerts(unresolved_only=True)
        assert len(unresolved) == 1
        assert unresolved[0].severity == "low"

    def test_combined_filters(self, dashboard: MCPAuditDashboard) -> None:
        aid = dashboard.record_alert("high", "escalation", "a")
        dashboard.record_alert("high", "shadow", "b")
        dashboard.record_alert("low", "escalation", "c")
        dashboard.resolve_alert(aid)

        result = dashboard.get_alerts(severity="high", unresolved_only=True)
        assert len(result) == 1
        assert result[0].detail == "b"


# ---------------------------------------------------------------------------
# Server registration
# ---------------------------------------------------------------------------


class TestRegisterServer:
    def test_register_new(self, dashboard: MCPAuditDashboard) -> None:
        dashboard.register_server("fs", 4, "L3_VERIFIED")
        srv = dashboard.get_server_stats("fs")
        assert srv is not None
        assert srv.server_name == "fs"
        assert srv.tool_count == 4
        assert srv.trust_level == "L3_VERIFIED"
        assert srv.is_healthy is True

    def test_update_existing(self, dashboard: MCPAuditDashboard) -> None:
        dashboard.register_server("fs", 4, "L1_SCANNED")
        dashboard.register_server("fs", 5, "L3_VERIFIED")
        srv = dashboard.get_server_stats("fs")
        assert srv is not None
        assert srv.tool_count == 5
        assert srv.trust_level == "L3_VERIFIED"

    def test_default_trust_level(self, dashboard: MCPAuditDashboard) -> None:
        dashboard.register_server("unknown", 1)
        srv = dashboard.get_server_stats("unknown")
        assert srv is not None
        assert srv.trust_level == "L0_UNTRUSTED"

    def test_unknown_server_returns_none(self, dashboard: MCPAuditDashboard) -> None:
        assert dashboard.get_server_stats("nonexistent") is None


# ---------------------------------------------------------------------------
# get_state snapshot
# ---------------------------------------------------------------------------


class TestGetState:
    def test_empty_state(self, dashboard: MCPAuditDashboard) -> None:
        state = dashboard.get_state()
        assert isinstance(state, DashboardState)
        assert state.servers == {}
        assert state.recent_calls == []
        assert state.active_alerts == []
        assert state.stats.total_calls == 0
        assert state.stats.uptime_seconds >= 0

    def test_populated_state(self, populated_dashboard: MCPAuditDashboard) -> None:
        state = populated_dashboard.get_state()
        assert len(state.servers) == 3
        assert state.stats.total_calls == 3
        assert state.stats.total_blocked == 1
        assert state.stats.total_allowed == 2
        assert len(state.active_alerts) == 3

    def test_block_rate_calculation(self, dashboard: MCPAuditDashboard) -> None:
        for _ in range(8):
            dashboard.record_call("t", "s", decision="allowed")
        for _ in range(2):
            dashboard.record_call("t", "s", decision="blocked")
        state = dashboard.get_state()
        assert state.stats.block_rate_percent == 20.0

    def test_uptime_positive(self, dashboard: MCPAuditDashboard) -> None:
        state = dashboard.get_state()
        assert state.stats.uptime_seconds >= 0

    def test_escalation_count(self, dashboard: MCPAuditDashboard) -> None:
        dashboard.record_alert("critical", "escalation", "a")
        dashboard.record_alert("high", "escalation", "b")
        dashboard.record_alert("low", "shadow", "c")
        state = dashboard.get_state()
        assert state.stats.escalation_count == 2
        assert state.stats.shadow_count == 1

    def test_response_findings_count(self, dashboard: MCPAuditDashboard) -> None:
        dashboard.record_alert("medium", "response_injection", "pii leak")
        state = dashboard.get_state()
        assert state.stats.response_findings_count == 1

    def test_resolved_alerts_excluded_from_active(
        self, dashboard: MCPAuditDashboard
    ) -> None:
        aid = dashboard.record_alert("high", "escalation", "x")
        dashboard.resolve_alert(aid)
        state = dashboard.get_state()
        assert len(state.active_alerts) == 0
        # But escalation count should also reflect resolved
        assert state.stats.escalation_count == 0

    def test_server_calls_per_minute(self, dashboard: MCPAuditDashboard) -> None:
        dashboard.register_server("fs", 3)
        # All calls are within the last minute
        for _ in range(5):
            dashboard.record_call("read", "fs")
        state = dashboard.get_state()
        srv = state.servers["fs"]
        assert srv.calls_last_minute == 5

    def test_recent_calls_capped_at_50(self, dashboard: MCPAuditDashboard) -> None:
        for i in range(100):
            dashboard.record_call(f"tool_{i}", "srv")
        state = dashboard.get_state()
        assert len(state.recent_calls) == 50


# ---------------------------------------------------------------------------
# render_text output
# ---------------------------------------------------------------------------


class TestRenderText:
    def test_contains_title(self, dashboard: MCPAuditDashboard) -> None:
        output = dashboard.render_text()
        assert "Aegis MCP Security Dashboard" in output

    def test_contains_box_drawing(self, dashboard: MCPAuditDashboard) -> None:
        output = dashboard.render_text()
        assert "\u2554" in output  # top-left corner
        assert "\u2557" in output  # top-right corner
        assert "\u255a" in output  # bottom-left corner
        assert "\u255d" in output  # bottom-right corner

    def test_shows_servers(self, populated_dashboard: MCPAuditDashboard) -> None:
        output = populated_dashboard.render_text()
        assert "filesystem" in output
        assert "database" in output
        assert "slack" in output
        assert "SERVERS" in output

    def test_shows_alerts(self, populated_dashboard: MCPAuditDashboard) -> None:
        output = populated_dashboard.render_text()
        assert "ACTIVE ALERTS" in output
        assert "CRITICAL" in output
        assert "escalation" in output

    def test_shows_recent_calls(self, populated_dashboard: MCPAuditDashboard) -> None:
        output = populated_dashboard.render_text()
        assert "RECENT CALLS" in output
        assert "ALLOWED" in output
        assert "BLOCKED" in output

    def test_shows_stats(self, populated_dashboard: MCPAuditDashboard) -> None:
        output = populated_dashboard.render_text()
        assert "Calls:" in output
        assert "Blocked:" in output
        assert "Uptime:" in output

    def test_empty_dashboard(self, dashboard: MCPAuditDashboard) -> None:
        output = dashboard.render_text()
        assert "no servers registered" in output
        assert "no active alerts" in output
        assert "no calls recorded" in output

    def test_custom_width(self, populated_dashboard: MCPAuditDashboard) -> None:
        output = populated_dashboard.render_text(width=100)
        # All lines should be 100 chars wide
        for line in output.split("\n"):
            assert len(line) == 100

    def test_minimum_width(self, dashboard: MCPAuditDashboard) -> None:
        output = dashboard.render_text(width=30)  # Below minimum
        # Should be clamped to 60
        for line in output.split("\n"):
            assert len(line) == 60

    def test_multiline_string(self, populated_dashboard: MCPAuditDashboard) -> None:
        output = populated_dashboard.render_text()
        lines = output.split("\n")
        assert len(lines) > 10  # Non-trivial output


# ---------------------------------------------------------------------------
# render_compact
# ---------------------------------------------------------------------------


class TestRenderCompact:
    def test_single_line(self, dashboard: MCPAuditDashboard) -> None:
        output = dashboard.render_compact()
        assert "\n" not in output

    def test_contains_metrics(self, populated_dashboard: MCPAuditDashboard) -> None:
        output = populated_dashboard.render_compact()
        assert "[Aegis]" in output
        assert "calls=3" in output
        assert "blocked=1" in output
        assert "alerts=3" in output
        assert "servers=3" in output
        assert "uptime=" in output

    def test_empty_dashboard(self, dashboard: MCPAuditDashboard) -> None:
        output = dashboard.render_compact()
        assert "calls=0" in output
        assert "blocked=0" in output
        assert "alerts=0" in output
        assert "servers=0" in output


# ---------------------------------------------------------------------------
# to_dict serialisation
# ---------------------------------------------------------------------------


class TestToDict:
    def test_serialisable(self, populated_dashboard: MCPAuditDashboard) -> None:
        d = populated_dashboard.to_dict()
        # Must be JSON-serialisable
        serialised = json.dumps(d)
        assert isinstance(serialised, str)
        # Round-trip
        parsed = json.loads(serialised)
        assert parsed["stats"]["total_calls"] == 3

    def test_structure(self, populated_dashboard: MCPAuditDashboard) -> None:
        d = populated_dashboard.to_dict()
        assert "servers" in d
        assert "recent_calls" in d
        assert "active_alerts" in d
        assert "stats" in d

    def test_server_fields(self, populated_dashboard: MCPAuditDashboard) -> None:
        d = populated_dashboard.to_dict()
        fs = d["servers"]["filesystem"]
        assert fs["server_name"] == "filesystem"
        assert fs["tool_count"] == 4
        assert fs["trust_level"] == "L3_VERIFIED"
        assert "calls_last_minute" in fs
        assert "is_healthy" in fs

    def test_call_fields(self, populated_dashboard: MCPAuditDashboard) -> None:
        d = populated_dashboard.to_dict()
        calls = d["recent_calls"]
        assert len(calls) == 3
        assert calls[0]["tool_name"] == "read_file"
        assert calls[0]["decision"] == "allowed"

    def test_alert_fields(self, populated_dashboard: MCPAuditDashboard) -> None:
        d = populated_dashboard.to_dict()
        alerts = d["active_alerts"]
        assert len(alerts) == 3
        assert alerts[0]["severity"] == "critical"
        assert alerts[0]["category"] == "escalation"
        assert "alert_id" in alerts[0]

    def test_stats_fields(self, populated_dashboard: MCPAuditDashboard) -> None:
        d = populated_dashboard.to_dict()
        stats = d["stats"]
        assert stats["total_calls"] == 3
        assert stats["total_blocked"] == 1
        assert stats["total_allowed"] == 2
        assert "block_rate_percent" in stats
        assert "uptime_seconds" in stats

    def test_empty_dashboard(self, dashboard: MCPAuditDashboard) -> None:
        d = dashboard.to_dict()
        assert d["servers"] == {}
        assert d["recent_calls"] == []
        assert d["active_alerts"] == []
        assert d["stats"]["total_calls"] == 0


# ---------------------------------------------------------------------------
# Max history / alerts enforcement
# ---------------------------------------------------------------------------


class TestLimits:
    def test_max_history(self) -> None:
        dash = MCPAuditDashboard(max_history=10)
        for i in range(25):
            dash.record_call(f"tool_{i}", "srv")
        state = dash.get_state()
        assert state.stats.total_calls == 10  # Trimmed to max
        # The most recent calls are kept
        assert state.recent_calls[-1].tool_name == "tool_24"

    def test_max_alerts(self) -> None:
        dash = MCPAuditDashboard(max_alerts=5)
        for i in range(12):
            dash.record_alert("low", "shadow", f"alert_{i}")
        alerts = dash.get_alerts(unresolved_only=False)
        assert len(alerts) == 5
        # Most recent are kept
        assert alerts[-1].detail == "alert_11"

    def test_max_history_one(self) -> None:
        dash = MCPAuditDashboard(max_history=1)
        dash.record_call("a", "s1")
        dash.record_call("b", "s2")
        state = dash.get_state()
        assert state.stats.total_calls == 1
        assert state.recent_calls[0].tool_name == "b"


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_record_calls(self) -> None:
        dash = MCPAuditDashboard()
        barrier = threading.Barrier(4)

        def worker(thread_id: int) -> None:
            barrier.wait()
            for i in range(50):
                dash.record_call(f"tool_{thread_id}_{i}", f"srv_{thread_id}")

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        state = dash.get_state()
        assert state.stats.total_calls == 200  # 4 * 50

    def test_concurrent_alerts(self) -> None:
        dash = MCPAuditDashboard()
        barrier = threading.Barrier(4)
        alert_ids: list[str] = []
        lock = threading.Lock()

        def worker() -> None:
            barrier.wait()
            for i in range(25):
                aid = dash.record_alert("low", "shadow", f"alert_{i}")
                with lock:
                    alert_ids.append(aid)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All 100 alert IDs should be unique
        assert len(alert_ids) == 100
        assert len(set(alert_ids)) == 100

    def test_concurrent_mixed_operations(self) -> None:
        dash = MCPAuditDashboard()
        dash.register_server("srv", 3)
        barrier = threading.Barrier(3)

        def recorder() -> None:
            barrier.wait()
            for _ in range(30):
                dash.record_call("t", "srv", decision="blocked")

        def alerter() -> None:
            barrier.wait()
            for _ in range(30):
                dash.record_alert("low", "shadow", "x")

        def reader() -> None:
            barrier.wait()
            for _ in range(30):
                dash.get_state()
                dash.render_compact()

        threads = [
            threading.Thread(target=recorder),
            threading.Thread(target=alerter),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        state = dash.get_state()
        assert state.stats.total_calls == 30
        assert state.stats.total_blocked == 30


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_state_render(self, dashboard: MCPAuditDashboard) -> None:
        """Empty dashboard should render without errors."""
        text = dashboard.render_text()
        compact = dashboard.render_compact()
        d = dashboard.to_dict()
        assert "Aegis" in text
        assert "[Aegis]" in compact
        assert d["stats"]["total_calls"] == 0

    def test_single_call(self, dashboard: MCPAuditDashboard) -> None:
        dashboard.record_call("read", "fs")
        state = dashboard.get_state()
        assert state.stats.total_calls == 1
        assert state.stats.block_rate_percent == 0.0

    def test_many_servers(self, dashboard: MCPAuditDashboard) -> None:
        for i in range(20):
            dashboard.register_server(f"server_{i}", i + 1)
        state = dashboard.get_state()
        assert len(state.servers) == 20

    def test_unregistered_server_call(self, dashboard: MCPAuditDashboard) -> None:
        """Calls for unregistered servers should still be recorded."""
        dashboard.record_call("tool", "unknown_server")
        state = dashboard.get_state()
        assert state.stats.total_calls == 1

    def test_server_blocked_count_not_incremented_for_unregistered(
        self, dashboard: MCPAuditDashboard
    ) -> None:
        """Blocked calls for unregistered servers should not crash."""
        dashboard.record_call("tool", "unknown", decision="blocked")
        state = dashboard.get_state()
        assert state.stats.total_blocked == 1

    def test_zero_block_rate(self, dashboard: MCPAuditDashboard) -> None:
        """No calls means 0% block rate, not division by zero."""
        state = dashboard.get_state()
        assert state.stats.block_rate_percent == 0.0

    def test_all_blocked(self, dashboard: MCPAuditDashboard) -> None:
        for _ in range(5):
            dashboard.record_call("t", "s", decision="blocked")
        state = dashboard.get_state()
        assert state.stats.block_rate_percent == 100.0

    def test_render_text_consistent_width(
        self, populated_dashboard: MCPAuditDashboard
    ) -> None:
        output = populated_dashboard.render_text(width=80)
        lines = output.split("\n")
        for line in lines:
            assert len(line) == 80, f"Line width mismatch: {len(line)} != 80: {line!r}"


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


class TestFormatUptime:
    def test_seconds_only(self) -> None:
        assert _format_uptime(45) == "45s"

    def test_minutes_and_seconds(self) -> None:
        assert _format_uptime(125) == "2m 5s"

    def test_hours_and_minutes(self) -> None:
        assert _format_uptime(9240) == "2h 34m"

    def test_zero(self) -> None:
        assert _format_uptime(0) == "0s"

    def test_negative_clamped(self) -> None:
        assert _format_uptime(-10) == "0s"


class TestFormatTimestamp:
    def test_basic(self) -> None:
        # Use a known timestamp
        ts = _format_timestamp(0)  # epoch
        # Should be HH:MM:SS format (timezone-dependent)
        parts = ts.split(":")
        assert len(parts) == 3
        assert all(len(p) == 2 for p in parts)
