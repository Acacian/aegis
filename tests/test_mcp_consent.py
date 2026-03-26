"""Tests for aegis.core.mcp_consent — MCP consent protocol."""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

from aegis.core.mcp_consent import (
    AutoDenyHandler,
    CallbackConsentHandler,
    ConsentDecision,
    ConsentRequest,
    ConsentRule,
    MCPConsentManager,
    _matches_pattern,
    _risk_ge,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    """Run an async coroutine in a fresh event loop (test utility)."""
    return asyncio.get_event_loop_policy().new_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# Risk level ordering
# ---------------------------------------------------------------------------


class TestRiskOrdering:
    def test_same_level(self):
        assert _risk_ge("medium", "medium") is True

    def test_higher_level(self):
        assert _risk_ge("critical", "low") is True

    def test_lower_level(self):
        assert _risk_ge("low", "high") is False

    def test_unknown_defaults_zero(self):
        assert _risk_ge("unknown", "low") is True  # both map to 0
        assert _risk_ge("low", "unknown") is True


# ---------------------------------------------------------------------------
# Pattern matching
# ---------------------------------------------------------------------------


class TestPatternMatching:
    def test_wildcard_match(self):
        assert _matches_pattern("delete_user", "*delete*") is True

    def test_wildcard_no_match(self):
        assert _matches_pattern("read_file", "*delete*") is False

    def test_pipe_separated_alternatives(self):
        assert _matches_pattern("remove_row", "*delete*|*remove*|*drop*") is True
        assert _matches_pattern("drop_table", "*delete*|*remove*|*drop*") is True

    def test_case_insensitive(self):
        assert _matches_pattern("DELETE_USER", "*delete*") is True
        assert _matches_pattern("delete_user", "*DELETE*") is True

    def test_exact_wildcard(self):
        assert _matches_pattern("anything", "*") is True

    def test_server_pattern(self):
        assert _matches_pattern("slack-bot", "*slack*") is True
        assert _matches_pattern("my-email-service", "*email*") is True
        assert _matches_pattern("filesystem", "*slack*|*email*") is False


# ---------------------------------------------------------------------------
# AutoDenyHandler
# ---------------------------------------------------------------------------


class TestAutoDenyHandler:
    def test_denies_everything(self):
        handler = AutoDenyHandler()
        request = ConsentRequest(
            request_id="test-1",
            tool_name="delete_all",
            server_name="postgres",
            arguments={"table": "users"},
            risk_level="critical",
            reason="test",
            created_at=time.time(),
            timeout_seconds=30.0,
            context={},
        )
        decision = _run(handler.request_consent(request))
        assert decision.approved is False
        assert decision.decided_by == "auto_deny"
        assert decision.request_id == "test-1"


# ---------------------------------------------------------------------------
# CallbackConsentHandler
# ---------------------------------------------------------------------------


class TestCallbackConsentHandler:
    def test_approves_via_callback(self):
        async def approve(req: ConsentRequest) -> ConsentDecision:
            return ConsentDecision(
                request_id=req.request_id,
                approved=True,
                decided_by="human-alice",
                decided_at=time.time(),
                reason="Looks good",
                conditions={"scope": "this_session"},
            )

        handler = CallbackConsentHandler(approve)
        request = ConsentRequest(
            request_id="cb-1",
            tool_name="send_email",
            server_name="email",
            arguments={"to": "bob@example.com"},
            risk_level="high",
            reason="test",
            created_at=time.time(),
            timeout_seconds=30.0,
            context={},
        )
        decision = _run(handler.request_consent(request))
        assert decision.approved is True
        assert decision.decided_by == "human-alice"
        assert decision.conditions == {"scope": "this_session"}

    def test_denies_via_callback(self):
        async def deny(req: ConsentRequest) -> ConsentDecision:
            return ConsentDecision(
                request_id=req.request_id,
                approved=False,
                decided_by="human-bob",
                decided_at=time.time(),
                reason="Too risky",
                conditions={},
            )

        handler = CallbackConsentHandler(deny)
        request = ConsentRequest(
            request_id="cb-2",
            tool_name="drop_database",
            server_name="postgres",
            arguments={},
            risk_level="critical",
            reason="test",
            created_at=time.time(),
            timeout_seconds=30.0,
            context={},
        )
        decision = _run(handler.request_consent(request))
        assert decision.approved is False
        assert decision.decided_by == "human-bob"


# ---------------------------------------------------------------------------
# MCPConsentManager — needs_consent (dry-run)
# ---------------------------------------------------------------------------


class TestNeedsConsent:
    def setup_method(self):
        self.manager = MCPConsentManager()

    def test_delete_matches(self):
        rule = self.manager.needs_consent("delete_user", "any_server")
        assert rule is not None
        assert rule.name == "delete_operations"

    def test_remove_matches(self):
        rule = self.manager.needs_consent("remove_row", "db_server")
        assert rule is not None
        assert rule.name == "delete_operations"

    def test_drop_matches(self):
        rule = self.manager.needs_consent("drop_table", "postgres")
        assert rule is not None
        assert rule.name == "delete_operations"

    def test_send_on_slack(self):
        rule = self.manager.needs_consent("send_message", "slack-bot")
        assert rule is not None
        assert rule.name == "send_messages"

    def test_post_on_email(self):
        rule = self.manager.needs_consent("post_email", "my-email-service")
        assert rule is not None
        assert rule.name == "send_messages"

    def test_publish_on_discord(self):
        rule = self.manager.needs_consent("publish_alert", "discord-webhook")
        assert rule is not None
        assert rule.name == "send_messages"

    def test_send_on_telegram(self):
        rule = self.manager.needs_consent("send_notification", "telegram-bot")
        assert rule is not None
        assert rule.name == "send_messages"

    def test_financial_pay(self):
        rule = self.manager.needs_consent("pay_invoice", "stripe")
        assert rule is not None
        assert rule.name == "financial"

    def test_financial_transfer(self):
        rule = self.manager.needs_consent("transfer_funds", "bank_api")
        assert rule is not None
        assert rule.name == "financial"

    def test_financial_charge(self):
        rule = self.manager.needs_consent("charge_card", "payment_gateway")
        assert rule is not None
        assert rule.name == "financial"

    def test_code_execution(self):
        rule = self.manager.needs_consent("execute_script", "sandbox")
        assert rule is not None
        assert rule.name == "code_execution"

    def test_eval_code(self):
        rule = self.manager.needs_consent("eval_expression", "repl")
        assert rule is not None
        assert rule.name == "code_execution"

    def test_run_command(self):
        rule = self.manager.needs_consent("run_query", "db")
        assert rule is not None
        assert rule.name == "code_execution"

    def test_system_config(self):
        rule = self.manager.needs_consent("update_config", "settings-server")
        assert rule is not None
        assert rule.name == "system_config"

    def test_setting_modification(self):
        rule = self.manager.needs_consent("change_setting", "admin")
        assert rule is not None
        assert rule.name == "system_config"

    def test_permission_change(self):
        rule = self.manager.needs_consent("grant_permission", "iam")
        assert rule is not None
        assert rule.name == "system_config"

    def test_write_operations_high_risk(self):
        rule = self.manager.needs_consent("write_file", "filesystem", risk_level="high")
        assert rule is not None
        assert rule.name == "write_operations"

    def test_write_operations_medium_risk_no_match(self):
        """write_operations requires risk >= high, so medium should not match."""
        rule = self.manager.needs_consent("write_file", "filesystem", risk_level="medium")
        # write_file does not match delete/send/financial/execute/config patterns,
        # and write_operations has min_risk_level=high, so medium doesn't trigger.
        assert rule is None

    def test_bulk_operations(self):
        rule = self.manager.needs_consent("bulk_insert", "db")
        assert rule is not None
        assert rule.name == "bulk_operations"

    def test_batch_operations(self):
        rule = self.manager.needs_consent("batch_process", "worker")
        assert rule is not None
        assert rule.name == "bulk_operations"

    def test_external_api_high_risk(self):
        rule = self.manager.needs_consent("fetch_data", "api-gateway", risk_level="high")
        assert rule is not None
        assert rule.name == "external_api"

    def test_external_api_medium_no_match(self):
        rule = self.manager.needs_consent("fetch_data", "api-gateway", risk_level="medium")
        assert rule is None

    def test_curl_request(self):
        rule = self.manager.needs_consent("curl_endpoint", "http-client", risk_level="critical")
        assert rule is not None
        assert rule.name == "external_api"

    def test_safe_read_no_consent(self):
        rule = self.manager.needs_consent("read_file", "filesystem")
        assert rule is None

    def test_safe_list_no_consent(self):
        rule = self.manager.needs_consent("list_items", "db")
        assert rule is None


# ---------------------------------------------------------------------------
# MCPConsentManager — risk level threshold
# ---------------------------------------------------------------------------


class TestRiskLevelThreshold:
    def test_below_threshold_no_consent(self):
        """delete_operations requires risk >= medium; low should not match."""
        manager = MCPConsentManager()
        rule = manager.needs_consent("delete_user", "db", risk_level="low")
        assert rule is None

    def test_at_threshold_matches(self):
        manager = MCPConsentManager()
        rule = manager.needs_consent("delete_user", "db", risk_level="medium")
        assert rule is not None

    def test_above_threshold_matches(self):
        manager = MCPConsentManager()
        rule = manager.needs_consent("delete_user", "db", risk_level="critical")
        assert rule is not None


# ---------------------------------------------------------------------------
# MCPConsentManager — check_consent (full flow)
# ---------------------------------------------------------------------------


class TestCheckConsent:
    def test_auto_approve_when_no_rule(self):
        manager = MCPConsentManager()
        decision = _run(
            manager.check_consent("read_file", "filesystem", {"path": "/tmp/x"})
        )
        assert decision.approved is True
        assert decision.decided_by == "system"

    def test_auto_deny_default_handler(self):
        manager = MCPConsentManager()
        decision = _run(
            manager.check_consent("delete_table", "postgres", {"table": "users"})
        )
        assert decision.approved is False
        assert decision.decided_by == "auto_deny"

    def test_custom_handler_approve(self):
        async def approve_all(req: ConsentRequest) -> ConsentDecision:
            return ConsentDecision(
                request_id=req.request_id,
                approved=True,
                decided_by="admin",
                decided_at=time.time(),
                reason="Approved",
                conditions={},
            )

        handler = CallbackConsentHandler(approve_all)
        manager = MCPConsentManager(handler=handler)
        decision = _run(
            manager.check_consent("delete_user", "db", {"user_id": 42})
        )
        assert decision.approved is True
        assert decision.decided_by == "admin"

    def test_context_passed_to_handler(self):
        captured: list[ConsentRequest] = []

        async def capture_handler(req: ConsentRequest) -> ConsentDecision:
            captured.append(req)
            return ConsentDecision(
                request_id=req.request_id,
                approved=False,
                decided_by="test",
                decided_at=time.time(),
                reason="captured",
                conditions={},
            )

        handler = CallbackConsentHandler(capture_handler)
        manager = MCPConsentManager(handler=handler)
        ctx = {"scan_result": "clean", "escalation": "none"}
        _run(
            manager.check_consent(
                "delete_row",
                "db",
                {"id": 1},
                context=ctx,
            )
        )
        assert len(captured) == 1
        assert captured[0].context == ctx
        assert captured[0].tool_name == "delete_row"

    def test_reason_template_formatted(self):
        captured: list[ConsentRequest] = []

        async def capture(req: ConsentRequest) -> ConsentDecision:
            captured.append(req)
            return ConsentDecision(
                request_id=req.request_id,
                approved=False,
                decided_by="test",
                decided_at=time.time(),
                reason="",
                conditions={},
            )

        handler = CallbackConsentHandler(capture)
        manager = MCPConsentManager(handler=handler)
        _run(manager.check_consent("delete_table", "postgres", {}))
        assert "delete_table" in captured[0].reason
        assert "postgres" in captured[0].reason


# ---------------------------------------------------------------------------
# Timeout handling
# ---------------------------------------------------------------------------


class TestTimeout:
    def test_slow_handler_auto_deny(self):
        """When handler exceeds timeout, auto_deny=True produces denial."""

        async def slow_handler(req: ConsentRequest) -> ConsentDecision:
            await asyncio.sleep(10)  # way past timeout
            return ConsentDecision(
                request_id=req.request_id,
                approved=True,
                decided_by="late",
                decided_at=time.time(),
                reason="too slow",
                conditions={},
            )

        # Use a short-timeout rule.
        rule = ConsentRule(
            name="fast_deny",
            tool_pattern="*delete*",
            server_pattern="*",
            min_risk_level="low",
            reason_template="test {tool} {server}",
            timeout_seconds=0.05,
            auto_deny=True,
        )
        handler = CallbackConsentHandler(slow_handler)
        manager = MCPConsentManager(rules=[rule], handler=handler)
        decision = _run(
            manager.check_consent("delete_x", "srv", {}, risk_level="critical")
        )
        assert decision.approved is False
        assert decision.decided_by == "timeout"

    def test_slow_handler_auto_approve(self):
        """When auto_deny=False, timeout produces approval."""

        async def slow_handler(req: ConsentRequest) -> ConsentDecision:
            await asyncio.sleep(10)
            return ConsentDecision(
                request_id=req.request_id,
                approved=False,
                decided_by="late",
                decided_at=time.time(),
                reason="too slow",
                conditions={},
            )

        rule = ConsentRule(
            name="fast_approve",
            tool_pattern="*delete*",
            server_pattern="*",
            min_risk_level="low",
            reason_template="test {tool} {server}",
            timeout_seconds=0.05,
            auto_deny=False,
        )
        handler = CallbackConsentHandler(slow_handler)
        manager = MCPConsentManager(rules=[rule], handler=handler)
        decision = _run(
            manager.check_consent("delete_x", "srv", {}, risk_level="critical")
        )
        assert decision.approved is True
        assert decision.decided_by == "timeout"

    def test_handler_exception_auto_deny(self):
        """Handler crash treated the same as timeout."""

        async def crashing_handler(req: ConsentRequest) -> ConsentDecision:
            raise RuntimeError("boom")

        rule = ConsentRule(
            name="crash_rule",
            tool_pattern="*delete*",
            server_pattern="*",
            min_risk_level="low",
            reason_template="test {tool} {server}",
            timeout_seconds=5.0,
            auto_deny=True,
        )
        handler = CallbackConsentHandler(crashing_handler)
        manager = MCPConsentManager(rules=[rule], handler=handler)
        decision = _run(
            manager.check_consent("delete_y", "srv", {}, risk_level="high")
        )
        assert decision.approved is False
        assert decision.decided_by == "timeout"


# ---------------------------------------------------------------------------
# History recording
# ---------------------------------------------------------------------------


class TestHistory:
    def test_records_auto_approve(self):
        manager = MCPConsentManager()
        _run(manager.check_consent("read_file", "fs", {}))
        history = manager.get_history()
        assert len(history) == 1
        assert history[0].approved is True

    def test_records_deny(self):
        manager = MCPConsentManager()
        _run(manager.check_consent("delete_user", "db", {}))
        history = manager.get_history()
        assert len(history) == 1
        assert history[0].approved is False

    def test_history_order_newest_first(self):
        manager = MCPConsentManager()
        _run(manager.check_consent("read_file", "fs", {}))
        _run(manager.check_consent("delete_user", "db", {}))
        history = manager.get_history()
        assert len(history) == 2
        # Newest (delete → denied) first.
        assert history[0].approved is False
        assert history[1].approved is True

    def test_history_limit(self):
        manager = MCPConsentManager()
        for i in range(10):
            _run(manager.check_consent("read_file", "fs", {"i": i}))
        history = manager.get_history(limit=3)
        assert len(history) == 3

    def test_history_size_cap(self):
        manager = MCPConsentManager(history_size=5)
        for i in range(10):
            _run(manager.check_consent("read_file", "fs", {"i": i}))
        history = manager.get_history(limit=100)
        assert len(history) == 5

    def test_history_thread_safety(self):
        """Concurrent writes to history must not lose entries."""
        manager = MCPConsentManager(history_size=500)
        errors: list[Exception] = []

        def writer():
            loop = asyncio.new_event_loop()
            try:
                for _ in range(50):
                    loop.run_until_complete(
                        manager.check_consent("read_file", "fs", {})
                    )
            except Exception as exc:
                errors.append(exc)
            finally:
                loop.close()

        threads = [threading.Thread(target=writer) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        history = manager.get_history(limit=500)
        assert len(history) == 200  # 4 threads * 50


# ---------------------------------------------------------------------------
# Custom rules
# ---------------------------------------------------------------------------


class TestCustomRules:
    def test_custom_rule_matches(self):
        rule = ConsentRule(
            name="custom_danger",
            tool_pattern="*nuke*",
            server_pattern="*prod*",
            min_risk_level="low",
            reason_template="DANGER: {tool} on {server}",
            timeout_seconds=10.0,
        )
        manager = MCPConsentManager(rules=[rule])
        matched = manager.needs_consent("nuke_cache", "prod-redis", risk_level="medium")
        assert matched is not None
        assert matched.name == "custom_danger"

    def test_custom_rule_no_match_wrong_server(self):
        rule = ConsentRule(
            name="custom_danger",
            tool_pattern="*nuke*",
            server_pattern="*prod*",
            min_risk_level="low",
            reason_template="DANGER: {tool} on {server}",
        )
        manager = MCPConsentManager(rules=[rule])
        assert manager.needs_consent("nuke_cache", "dev-redis") is None

    def test_empty_rules_always_approves(self):
        manager = MCPConsentManager(rules=[])
        decision = _run(
            manager.check_consent("delete_everything", "prod", {}, risk_level="critical")
        )
        assert decision.approved is True

    def test_multiple_custom_rules_first_wins(self):
        rule_a = ConsentRule(
            name="rule_a",
            tool_pattern="*delete*",
            server_pattern="*",
            min_risk_level="low",
            reason_template="A: {tool}",
        )
        rule_b = ConsentRule(
            name="rule_b",
            tool_pattern="*delete*",
            server_pattern="*",
            min_risk_level="low",
            reason_template="B: {tool}",
        )
        manager = MCPConsentManager(rules=[rule_a, rule_b])
        matched = manager.needs_consent("delete_x", "srv")
        assert matched is not None
        assert matched.name == "rule_a"


# ---------------------------------------------------------------------------
# Builtin rules coverage
# ---------------------------------------------------------------------------


class TestBuiltinRules:
    """Verify all 8 builtin rules exist and have correct metadata."""

    def test_eight_builtin_rules(self):
        rules = MCPConsentManager.builtin_rules()
        assert len(rules) == 8

    def test_rule_names(self):
        rules = MCPConsentManager.builtin_rules()
        names = {r.name for r in rules}
        expected = {
            "delete_operations",
            "send_messages",
            "financial",
            "code_execution",
            "system_config",
            "write_operations",
            "bulk_operations",
            "external_api",
        }
        assert names == expected

    def test_all_rules_have_auto_deny(self):
        for rule in MCPConsentManager.builtin_rules():
            assert rule.auto_deny is True, f"Rule {rule.name} should auto_deny"

    def test_all_rules_have_positive_timeout(self):
        for rule in MCPConsentManager.builtin_rules():
            assert rule.timeout_seconds > 0, f"Rule {rule.name} has no timeout"

    def test_financial_has_longer_timeout(self):
        rules = MCPConsentManager.builtin_rules()
        financial = [r for r in rules if r.name == "financial"][0]
        assert financial.timeout_seconds == 60.0


# ---------------------------------------------------------------------------
# Data model immutability
# ---------------------------------------------------------------------------


class TestDataModels:
    def test_consent_request_frozen(self):
        req = ConsentRequest(
            request_id="x",
            tool_name="t",
            server_name="s",
            arguments={},
            risk_level="low",
            reason="r",
            created_at=0.0,
            timeout_seconds=1.0,
            context={},
        )
        with pytest.raises(AttributeError):
            req.tool_name = "other"  # type: ignore[misc]

    def test_consent_decision_frozen(self):
        dec = ConsentDecision(
            request_id="x",
            approved=True,
            decided_by="test",
            decided_at=0.0,
            reason="ok",
            conditions={},
        )
        with pytest.raises(AttributeError):
            dec.approved = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ConsentCallback protocol check
# ---------------------------------------------------------------------------


class TestConsentCallbackProtocol:
    def test_auto_deny_satisfies_protocol(self):
        from aegis.core.mcp_consent import ConsentCallback

        handler = AutoDenyHandler()
        assert isinstance(handler, ConsentCallback)

    def test_callback_handler_satisfies_protocol(self):
        from aegis.core.mcp_consent import ConsentCallback

        async def noop(req: ConsentRequest) -> ConsentDecision:
            return ConsentDecision(
                request_id=req.request_id,
                approved=False,
                decided_by="x",
                decided_at=0,
                reason="",
                conditions={},
            )

        handler = CallbackConsentHandler(noop)
        assert isinstance(handler, ConsentCallback)
