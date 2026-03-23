"""Tests for agent session replay with security analysis."""

from __future__ import annotations

from aegis.core.session_replay import (
    ReplayReport,
    SessionRecorder,
    SessionReplayer,
    _flatten_to_string,
    _scan_arguments,
)

# ---------------------------------------------------------------------------
# SessionRecorder
# ---------------------------------------------------------------------------


class TestSessionRecorder:
    def test_record_tool_call(self) -> None:
        rec = SessionRecorder("sess-1", agent_id="agent-1")
        event = rec.record_tool_call("read_file", {"path": "/tmp/test.txt"})
        assert event.event_type == "tool_call"
        assert event.tool_name == "read_file"
        assert event.data["arguments"]["path"] == "/tmp/test.txt"
        assert rec.event_count == 1

    def test_record_tool_result(self) -> None:
        rec = SessionRecorder("sess-1")
        event = rec.record_tool_result("read_file", "file contents here")
        assert event.event_type == "tool_result"
        assert "file contents here" in event.data["result"]

    def test_record_policy_decision(self) -> None:
        rec = SessionRecorder("sess-1")
        event = rec.record_policy_decision(
            "delete_file",
            "block",
            rule="no-delete",
            risk_level="high",
        )
        assert event.event_type == "policy_decision"
        assert event.data["decision"] == "block"
        assert event.data["rule"] == "no-delete"

    def test_finalize(self) -> None:
        rec = SessionRecorder("sess-1", agent_id="agent-1")
        rec.record_tool_call("read_file", {"path": "/tmp/test.txt"})
        rec.record_tool_result("read_file", "ok")
        session = rec.finalize()
        assert session.session_id == "sess-1"
        assert session.agent_id == "agent-1"
        assert len(session.events) == 2
        assert session.started_at > 0
        assert session.ended_at > 0
        assert session.ended_at >= session.started_at

    def test_agent_id_inheritance(self) -> None:
        rec = SessionRecorder("sess-1", agent_id="default-agent")
        event = rec.record_tool_call("tool_a", {})
        assert event.agent_id == "default-agent"

    def test_agent_id_override(self) -> None:
        rec = SessionRecorder("sess-1", agent_id="default-agent")
        event = rec.record_tool_call("tool_a", {}, agent_id="override")
        assert event.agent_id == "override"

    def test_metadata(self) -> None:
        rec = SessionRecorder(
            "sess-1",
            metadata={"environment": "production"},
        )
        session = rec.finalize()
        assert session.metadata["environment"] == "production"


# ---------------------------------------------------------------------------
# Scanning helpers
# ---------------------------------------------------------------------------


class TestScanArguments:
    def test_clean_arguments(self) -> None:
        findings = _scan_arguments({"path": "/tmp/safe_file.txt"})
        assert len(findings) == 0

    def test_path_traversal(self) -> None:
        findings = _scan_arguments({"path": "../../etc/passwd"})
        assert any(cat == "path_traversal" for _, cat, _ in findings)

    def test_sensitive_file(self) -> None:
        findings = _scan_arguments({"path": "/etc/passwd"})
        assert any(cat == "sensitive_file_access" for _, cat, _ in findings)

    def test_command_injection(self) -> None:
        findings = _scan_arguments({"cmd": "ls; rm -rf /"})
        assert any(cat == "command_injection" for _, cat, _ in findings)

    def test_code_injection(self) -> None:
        findings = _scan_arguments({"code": "eval(user_input)"})
        assert any(cat == "code_injection" for _, cat, _ in findings)

    def test_sql_injection(self) -> None:
        findings = _scan_arguments({"query": "SELECT * FROM users; DROP TABLE users"})
        assert any(cat == "sql_injection" for _, cat, _ in findings)

    def test_nested_arguments(self) -> None:
        findings = _scan_arguments(
            {
                "nested": {"deep": {"path": "../../../etc/shadow"}},
            }
        )
        assert any(cat == "path_traversal" for _, cat, _ in findings)
        assert any(cat == "sensitive_file_access" for _, cat, _ in findings)


class TestFlattenToString:
    def test_string(self) -> None:
        assert _flatten_to_string("hello") == "hello"

    def test_dict(self) -> None:
        result = _flatten_to_string({"a": "b", "c": "d"})
        assert "b" in result
        assert "d" in result

    def test_list(self) -> None:
        result = _flatten_to_string(["a", "b"])
        assert "a" in result
        assert "b" in result

    def test_depth_limit(self) -> None:
        nested: dict = {"a": {"b": "c"}}
        for _ in range(15):
            nested = {"x": nested}
        result = _flatten_to_string(nested)
        # Should not crash due to depth limit
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# SessionReplayer
# ---------------------------------------------------------------------------


class TestSessionReplayer:
    def test_clean_session(self) -> None:
        rec = SessionRecorder("sess-1")
        rec.record_tool_call("read_file", {"path": "/tmp/safe.txt"})
        rec.record_tool_result("read_file", "ok")
        session = rec.finalize()

        replayer = SessionReplayer()
        report = replayer.replay(session)
        assert report.clean
        assert report.events_scanned == 1
        assert len(report.findings) == 0

    def test_suspicious_session(self) -> None:
        rec = SessionRecorder("sess-1")
        rec.record_tool_call(
            "read_file",
            {"path": "../../etc/passwd"},
        )
        session = rec.finalize()

        replayer = SessionReplayer()
        report = replayer.replay(session)
        assert not report.clean
        assert len(report.findings) >= 1
        assert report.findings[0].category == "path_traversal"
        assert report.findings[0].retroactive is True

    def test_multiple_findings_one_event(self) -> None:
        rec = SessionRecorder("sess-1")
        rec.record_tool_call(
            "shell",
            {"cmd": "cat /etc/passwd; rm -rf /"},
        )
        session = rec.finalize()

        replayer = SessionReplayer()
        report = replayer.replay(session)
        categories = {f.category for f in report.findings}
        assert "sensitive_file_access" in categories
        assert "command_injection" in categories

    def test_only_scans_tool_calls(self) -> None:
        rec = SessionRecorder("sess-1")
        rec.record_tool_call("read", {"path": "/tmp/safe.txt"})
        rec.record_tool_result("read", "../../etc/passwd")  # suspicious result
        rec.record_policy_decision("read", "allow")
        session = rec.finalize()

        replayer = SessionReplayer()
        report = replayer.replay(session)
        # Only tool_call events are scanned
        assert report.events_scanned == 1

    def test_extra_patterns(self) -> None:
        rec = SessionRecorder("sess-1")
        rec.record_tool_call("api_call", {"url": "http://evil-domain.com"})
        session = rec.finalize()

        replayer = SessionReplayer(
            extra_patterns=[("evil-domain", "known_bad_domain", "high")],
        )
        report = replayer.replay(session)
        assert not report.clean
        assert report.findings[0].category == "known_bad_domain"


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------


class TestReportFormatting:
    def test_clean_report(self) -> None:
        report = ReplayReport(session_id="sess-1", events_scanned=5)
        replayer = SessionReplayer()
        text = replayer.format_report(report)
        assert "No security findings" in text

    def test_report_with_findings(self) -> None:
        rec = SessionRecorder("sess-1")
        rec.record_tool_call(
            "read_file",
            {"path": "../../etc/passwd"},
        )
        session = rec.finalize()

        replayer = SessionReplayer()
        report = replayer.replay(session)
        text = replayer.format_report(report)
        assert "HIGH" in text or "CRITICAL" in text
        assert "read_file" in text
        assert "retroactively" in text.lower()
