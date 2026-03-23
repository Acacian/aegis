"""Tests for OpenAI Agents SDK native guardrail integration.

Tests AegisToolInputGuardrail, AegisToolOutputGuardrail, and factory functions.
Uses SimpleNamespace to mock SDK data objects (ToolInputGuardrailData,
ToolOutputGuardrailData, ToolContext) without requiring openai-agents installed.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.risk import RiskLevel

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_policy(
    *,
    allow_types: list[str] | None = None,
    block_types: list[str] | None = None,
    approve_types: list[str] | None = None,
) -> Policy:
    """Build a test policy."""
    rules: list[PolicyRule] = []
    for t in allow_types or []:
        rules.append(
            PolicyRule(
                match_type=t,
                approval=Approval.AUTO,
                risk_level=RiskLevel.LOW,
                name=f"allow_{t}",
            )
        )
    for t in block_types or []:
        rules.append(
            PolicyRule(
                match_type=t,
                approval=Approval.BLOCK,
                risk_level=RiskLevel.CRITICAL,
                name=f"block_{t}",
            )
        )
    for t in approve_types or []:
        rules.append(
            PolicyRule(
                match_type=t,
                approval=Approval.APPROVE,
                risk_level=RiskLevel.MEDIUM,
                name=f"approve_{t}",
            )
        )
    return Policy(rules=rules)


def _make_context(
    tool_name: str = "web_search",
    tool_arguments: str | dict | None = '{"query": "test"}',
    tool_call_id: str = "call_123",
) -> SimpleNamespace:
    """Mock a ToolContext-like object."""
    return SimpleNamespace(
        tool_name=tool_name,
        tool_arguments=tool_arguments,
        tool_call_id=tool_call_id,
    )


def _make_input_data(
    tool_name: str = "web_search",
    tool_arguments: str | dict | None = '{"query": "test"}',
    agent: SimpleNamespace | None = None,
) -> SimpleNamespace:
    """Mock a ToolInputGuardrailData-like object."""
    ctx = _make_context(tool_name=tool_name, tool_arguments=tool_arguments)
    return SimpleNamespace(
        context=ctx,
        agent=agent or SimpleNamespace(name="test_agent"),
    )


def _make_output_data(
    tool_name: str = "web_search",
    tool_arguments: str | dict | None = '{"query": "test"}',
    output: str = "search results here",
    agent: SimpleNamespace | None = None,
) -> SimpleNamespace:
    """Mock a ToolOutputGuardrailData-like object."""
    ctx = _make_context(tool_name=tool_name, tool_arguments=tool_arguments)
    return SimpleNamespace(
        context=ctx,
        agent=agent or SimpleNamespace(name="test_agent"),
        output=output,
    )


# ---------------------------------------------------------------------------
# Mock ToolGuardrailFunctionOutput for when SDK is not installed
# ---------------------------------------------------------------------------


class _MockGuardrailOutput:
    """Mock ToolGuardrailFunctionOutput for testing without SDK."""

    def __init__(self, behavior: str, message: str = "", output_info: dict | None = None):
        self.behavior = behavior
        self.message = message
        self.output_info = output_info or {}

    @classmethod
    def allow(cls, output_info: dict | None = None) -> _MockGuardrailOutput:
        return cls("allow", output_info=output_info)

    @classmethod
    def reject_content(cls, message: str, output_info: dict | None = None) -> _MockGuardrailOutput:
        return cls("reject_content", message=message, output_info=output_info)

    @classmethod
    def raise_exception(cls, output_info: dict | None = None) -> _MockGuardrailOutput:
        return cls("raise_exception", output_info=output_info)


@pytest.fixture(autouse=True)
def _mock_agents_module():
    """Provide a mock agents module with ToolGuardrailFunctionOutput."""
    mock_agents = MagicMock()
    mock_agents.ToolGuardrailFunctionOutput = _MockGuardrailOutput
    mock_agents.tool_input_guardrail = None
    mock_agents.tool_output_guardrail = None

    original = sys.modules.get("agents")
    sys.modules["agents"] = mock_agents
    yield mock_agents
    if original is not None:
        sys.modules["agents"] = original
    else:
        sys.modules.pop("agents", None)


# ===========================================================================
# AegisToolInputGuardrail
# ===========================================================================


class TestAegisToolInputGuardrail:
    """Tests for AegisToolInputGuardrail."""

    def test_init_with_policy(self):
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        policy = _make_policy(allow_types=["search"])
        g = AegisToolInputGuardrail(policy=policy)
        assert g.policy is policy
        assert g.fail_closed is True
        assert g.name == "aegis_input_guardrail"

    def test_init_custom_params(self):
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        policy = _make_policy(allow_types=["search"])
        g = AegisToolInputGuardrail(
            policy=policy,
            target="custom",
            fail_closed=False,
            on_tripwire=True,
            name="my_guard",
            session_id="sess-1",
        )
        assert g.fail_closed is False
        assert g.name == "my_guard"

    def test_policy_hot_swap(self):
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        p1 = _make_policy(allow_types=["a"])
        p2 = _make_policy(block_types=["a"])
        g = AegisToolInputGuardrail(policy=p1)
        assert g.policy is p1
        g.policy = p2
        assert g.policy is p2

    def test_evaluate_allowed(self):
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        policy = _make_policy(allow_types=["web_search"])
        g = AegisToolInputGuardrail(policy=policy)
        allow, reason, meta = g.evaluate("web_search", {"query": "test"})
        assert allow is True
        assert "allow_web_search" in reason
        assert meta["risk_level"] == "LOW"

    def test_evaluate_blocked(self):
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        policy = _make_policy(block_types=["delete_file"])
        g = AegisToolInputGuardrail(policy=policy)
        allow, reason, meta = g.evaluate("delete_file", {"path": "/etc"})
        assert allow is False
        assert "block_delete_file" in reason
        assert meta["risk_level"] == "CRITICAL"

    def test_evaluate_approval_required(self):
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        policy = _make_policy(approve_types=["write_db"])
        g = AegisToolInputGuardrail(policy=policy)
        allow, reason, meta = g.evaluate("write_db", {"data": "x"})
        assert allow is False
        assert "approval" in reason.lower()
        assert meta.get("approval_required") == "true"

    def test_evaluate_fail_closed(self):
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        policy = MagicMock()
        policy.evaluate.side_effect = RuntimeError("boom")
        policy.rules = []
        g = AegisToolInputGuardrail(policy=policy, fail_closed=True)
        allow, reason, meta = g.evaluate("any_tool", {})
        assert allow is False
        assert "fail-closed" in reason
        assert meta["error"] == "boom"

    def test_evaluate_fail_open(self):
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        policy = MagicMock()
        policy.evaluate.side_effect = RuntimeError("boom")
        policy.rules = []
        g = AegisToolInputGuardrail(policy=policy, fail_closed=False)
        allow, reason, meta = g.evaluate("any_tool", {})
        assert allow is True
        assert "fail-open" in reason

    def test_evaluate_with_tool_target_map(self):
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        policy = _make_policy(allow_types=["search"])
        g = AegisToolInputGuardrail(
            policy=policy,
            target="default",
            tool_target_map={"search": "external_api"},
        )
        allow, reason, meta = g.evaluate("search", {"q": "test"})
        assert allow is True

    @pytest.mark.asyncio
    async def test_call_allowed(self):
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        policy = _make_policy(allow_types=["web_search"])
        g = AegisToolInputGuardrail(policy=policy)
        data = _make_input_data(tool_name="web_search")
        result = await g(data)
        assert result.behavior == "allow"

    @pytest.mark.asyncio
    async def test_call_blocked_reject_content(self):
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        policy = _make_policy(block_types=["dangerous"])
        g = AegisToolInputGuardrail(policy=policy)
        data = _make_input_data(tool_name="dangerous")
        result = await g(data)
        assert result.behavior == "reject_content"
        assert "block_dangerous" in result.message

    @pytest.mark.asyncio
    async def test_call_blocked_tripwire(self):
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        policy = _make_policy(block_types=["dangerous"])
        g = AegisToolInputGuardrail(policy=policy, on_tripwire=True)
        data = _make_input_data(tool_name="dangerous")
        result = await g(data)
        assert result.behavior == "raise_exception"

    @pytest.mark.asyncio
    async def test_call_with_dict_arguments(self):
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        policy = _make_policy(allow_types=["tool"])
        g = AegisToolInputGuardrail(policy=policy)
        data = _make_input_data(tool_name="tool", tool_arguments={"key": "value"})
        result = await g(data)
        assert result.behavior == "allow"

    @pytest.mark.asyncio
    async def test_call_with_plain_string_arguments(self):
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        policy = _make_policy(allow_types=["tool"])
        g = AegisToolInputGuardrail(policy=policy)
        data = _make_input_data(tool_name="tool", tool_arguments="plain text")
        result = await g(data)
        assert result.behavior == "allow"

    @pytest.mark.asyncio
    async def test_call_with_none_arguments(self):
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        policy = _make_policy(allow_types=["tool"])
        g = AegisToolInputGuardrail(policy=policy)
        data = _make_input_data(tool_name="tool", tool_arguments=None)
        result = await g(data)
        assert result.behavior == "allow"

    @pytest.mark.asyncio
    async def test_call_with_missing_context(self):
        """Should handle data with no context gracefully."""
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        policy = _make_policy(allow_types=[""])
        g = AegisToolInputGuardrail(policy=policy)
        data = SimpleNamespace()  # No context
        result = await g(data)
        # Should still produce a result (allow or deny based on policy)
        assert result.behavior in ("allow", "reject_content")

    def test_evaluate_audit_logging(self):
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        policy = _make_policy(block_types=["bad"])
        mock_audit = MagicMock()
        g = AegisToolInputGuardrail(policy=policy, audit_logger=mock_audit, session_id="s1")
        g.evaluate("bad", {"x": 1})
        mock_audit.log.assert_called_once()
        call_args = mock_audit.log.call_args
        assert call_args[0][0] == "s1"  # session_id

    def test_health_check(self):
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        policy = _make_policy(allow_types=["a", "b"])
        g = AegisToolInputGuardrail(policy=policy, on_tripwire=True)
        health = g.health_check()
        assert health["status"] == "healthy"
        assert health["type"] == "input"
        assert health["policy_rules"] == 2
        assert health["fail_closed"] is True
        assert health["on_tripwire"] is True


# ===========================================================================
# AegisToolOutputGuardrail
# ===========================================================================


class TestAegisToolOutputGuardrail:
    """Tests for AegisToolOutputGuardrail."""

    def test_init_with_policy(self):
        from aegis.adapters.openai_agents import AegisToolOutputGuardrail

        policy = _make_policy(allow_types=["search:output"])
        g = AegisToolOutputGuardrail(policy=policy)
        assert g.policy is policy
        assert g.fail_closed is True
        assert g.name == "aegis_output_guardrail"

    def test_policy_hot_swap(self):
        from aegis.adapters.openai_agents import AegisToolOutputGuardrail

        p1 = _make_policy(allow_types=["a:output"])
        p2 = _make_policy(block_types=["a:output"])
        g = AegisToolOutputGuardrail(policy=p1)
        g.policy = p2
        assert g.policy is p2

    def test_evaluate_allowed(self):
        from aegis.adapters.openai_agents import AegisToolOutputGuardrail

        policy = _make_policy(allow_types=["search:output"])
        g = AegisToolOutputGuardrail(policy=policy)
        allow, reason, meta = g.evaluate("search", {"q": "test"}, "results")
        assert allow is True
        assert "allow_search:output" in reason

    def test_evaluate_blocked(self):
        from aegis.adapters.openai_agents import AegisToolOutputGuardrail

        policy = _make_policy(block_types=["leak:output"])
        g = AegisToolOutputGuardrail(policy=policy)
        allow, reason, meta = g.evaluate("leak", {}, "sensitive data")
        assert allow is False
        assert "block_leak:output" in reason

    def test_evaluate_fail_closed(self):
        from aegis.adapters.openai_agents import AegisToolOutputGuardrail

        policy = MagicMock()
        policy.evaluate.side_effect = RuntimeError("fail")
        policy.rules = []
        g = AegisToolOutputGuardrail(policy=policy, fail_closed=True)
        allow, reason, meta = g.evaluate("t", {}, "out")
        assert allow is False
        assert "fail-closed" in reason

    def test_evaluate_fail_open(self):
        from aegis.adapters.openai_agents import AegisToolOutputGuardrail

        policy = MagicMock()
        policy.evaluate.side_effect = RuntimeError("fail")
        policy.rules = []
        g = AegisToolOutputGuardrail(policy=policy, fail_closed=False)
        allow, reason, meta = g.evaluate("t", {}, "out")
        assert allow is True
        assert "fail-open" in reason

    @pytest.mark.asyncio
    async def test_call_allowed(self):
        from aegis.adapters.openai_agents import AegisToolOutputGuardrail

        policy = _make_policy(allow_types=["web_search:output"])
        g = AegisToolOutputGuardrail(policy=policy)
        data = _make_output_data(tool_name="web_search", output="results")
        result = await g(data)
        assert result.behavior == "allow"

    @pytest.mark.asyncio
    async def test_call_blocked_reject_content(self):
        from aegis.adapters.openai_agents import AegisToolOutputGuardrail

        policy = _make_policy(block_types=["leak:output"])
        g = AegisToolOutputGuardrail(policy=policy)
        data = _make_output_data(tool_name="leak", output="secrets")
        result = await g(data)
        assert result.behavior == "reject_content"

    @pytest.mark.asyncio
    async def test_call_blocked_tripwire(self):
        from aegis.adapters.openai_agents import AegisToolOutputGuardrail

        policy = _make_policy(block_types=["leak:output"])
        g = AegisToolOutputGuardrail(policy=policy, on_tripwire=True)
        data = _make_output_data(tool_name="leak", output="secrets")
        result = await g(data)
        assert result.behavior == "raise_exception"

    @pytest.mark.asyncio
    async def test_call_with_none_output(self):
        from aegis.adapters.openai_agents import AegisToolOutputGuardrail

        policy = _make_policy(allow_types=["tool:output"])
        g = AegisToolOutputGuardrail(policy=policy)
        data = _make_output_data(tool_name="tool", output=None)
        # output=None on SimpleNamespace
        data.output = None
        result = await g(data)
        assert result.behavior == "allow"

    def test_evaluate_audit_logging(self):
        from aegis.adapters.openai_agents import AegisToolOutputGuardrail

        policy = _make_policy(block_types=["bad:output"])
        mock_audit = MagicMock()
        g = AegisToolOutputGuardrail(policy=policy, audit_logger=mock_audit, session_id="s2")
        g.evaluate("bad", {}, "output")
        mock_audit.log.assert_called_once()

    def test_health_check(self):
        from aegis.adapters.openai_agents import AegisToolOutputGuardrail

        policy = _make_policy(allow_types=["a:output", "b:output"])
        g = AegisToolOutputGuardrail(policy=policy, on_tripwire=False)
        health = g.health_check()
        assert health["status"] == "healthy"
        assert health["type"] == "output"
        assert health["policy_rules"] == 2
        assert health["on_tripwire"] is False


# ===========================================================================
# Factory functions
# ===========================================================================


class TestCreateAegisInputGuardrail:
    """Tests for create_aegis_input_guardrail factory."""

    def test_returns_guardrail_without_sdk(self):
        """Without SDK, returns the raw AegisToolInputGuardrail."""
        # Remove mock agents so import fails inside factory
        original = sys.modules.pop("agents", None)
        try:
            from aegis.adapters.openai_agents import (
                AegisToolInputGuardrail,
                create_aegis_input_guardrail,
            )

            policy = _make_policy(allow_types=["search"])
            g = create_aegis_input_guardrail(policy=policy)
            assert isinstance(g, AegisToolInputGuardrail)
        finally:
            if original is not None:
                sys.modules["agents"] = original

    def test_returns_wrapped_with_sdk(self, _mock_agents_module):
        """With SDK installed, wraps via @tool_input_guardrail."""

        # Set up mock decorator
        def mock_decorator(name: str = ""):
            def wrapper(fn):
                fn._is_guardrail = True
                fn._name = name
                return fn

            return wrapper

        _mock_agents_module.tool_input_guardrail = mock_decorator

        from aegis.adapters.openai_agents import create_aegis_input_guardrail

        policy = _make_policy(allow_types=["search"])
        g = create_aegis_input_guardrail(policy=policy, name="my_guard")
        # Should have the decorator applied
        assert hasattr(g, "_is_guardrail")
        assert g._is_guardrail is True
        assert g._name == "my_guard"
        # Should expose _aegis_guardrail for introspection
        assert hasattr(g, "_aegis_guardrail")

    def test_custom_parameters(self):
        from aegis.adapters.openai_agents import (
            AegisToolInputGuardrail,
            create_aegis_input_guardrail,
        )

        # Remove SDK so we get the raw guardrail
        original = sys.modules.pop("agents", None)
        try:
            policy = _make_policy(allow_types=["x"])
            g = create_aegis_input_guardrail(
                policy=policy,
                target="custom",
                fail_closed=False,
                on_tripwire=True,
                session_id="sess",
                name="custom_guard",
            )
            assert isinstance(g, AegisToolInputGuardrail)
            assert g.fail_closed is False
            assert g.name == "custom_guard"
        finally:
            if original is not None:
                sys.modules["agents"] = original


class TestCreateAegisOutputGuardrail:
    """Tests for create_aegis_output_guardrail factory."""

    def test_returns_guardrail_without_sdk(self):
        original = sys.modules.pop("agents", None)
        try:
            from aegis.adapters.openai_agents import (
                AegisToolOutputGuardrail,
                create_aegis_output_guardrail,
            )

            policy = _make_policy(allow_types=["s:output"])
            g = create_aegis_output_guardrail(policy=policy)
            assert isinstance(g, AegisToolOutputGuardrail)
        finally:
            if original is not None:
                sys.modules["agents"] = original

    def test_returns_wrapped_with_sdk(self, _mock_agents_module):
        def mock_decorator(name: str = ""):
            def wrapper(fn):
                fn._is_guardrail = True
                fn._name = name
                return fn

            return wrapper

        _mock_agents_module.tool_output_guardrail = mock_decorator

        from aegis.adapters.openai_agents import create_aegis_output_guardrail

        policy = _make_policy(allow_types=["s:output"])
        g = create_aegis_output_guardrail(policy=policy, name="out_guard")
        assert hasattr(g, "_is_guardrail")
        assert g._aegis_guardrail is not None


# ===========================================================================
# Argument parsing edge cases
# ===========================================================================


class TestArgumentParsing:
    """Tests for _parse_tool_arguments edge cases."""

    def test_json_string_parsed(self):
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        g = AegisToolInputGuardrail(policy=_make_policy(allow_types=["t"]))
        result = g._parse_tool_arguments('{"key": "val"}')
        assert result == {"key": "val"}

    def test_dict_passthrough(self):
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        g = AegisToolInputGuardrail(policy=_make_policy(allow_types=["t"]))
        result = g._parse_tool_arguments({"a": 1})
        assert result == {"a": 1}

    def test_plain_string_wrapped(self):
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        g = AegisToolInputGuardrail(policy=_make_policy(allow_types=["t"]))
        result = g._parse_tool_arguments("not json")
        assert result == {"input": "not json"}

    def test_none_returns_empty(self):
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        g = AegisToolInputGuardrail(policy=_make_policy(allow_types=["t"]))
        result = g._parse_tool_arguments(None)
        assert result == {}

    def test_json_array_wrapped(self):
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        g = AegisToolInputGuardrail(policy=_make_policy(allow_types=["t"]))
        result = g._parse_tool_arguments("[1, 2, 3]")
        assert result == {"input": "[1, 2, 3]"}

    def test_integer_returns_empty(self):
        from aegis.adapters.openai_agents import AegisToolInputGuardrail

        g = AegisToolInputGuardrail(policy=_make_policy(allow_types=["t"]))
        result = g._parse_tool_arguments(42)
        assert result == {}
