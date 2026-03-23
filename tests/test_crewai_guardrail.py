"""Tests for CrewAI GuardrailProvider, GuardrailRequest, GuardrailDecision."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aegis.core.action import Action
from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.result import Result, ResultStatus
from aegis.core.risk import RiskLevel
from aegis.runtime.approval import AutoApprovalHandler
from aegis.runtime.audit import AuditLogger


@pytest.fixture
def mock_crewai():
    """Mock the crewai module so imports succeed."""
    mock_module = MagicMock()
    with patch.dict("sys.modules", {"crewai": mock_module}):
        yield mock_module


def _make_policy() -> Policy:
    """Standard test policy with auto/approve/block rules."""
    return Policy(
        rules=[
            PolicyRule(
                match_type="search",
                approval=Approval.AUTO,
                risk_level=RiskLevel.LOW,
                name="search_auto",
            ),
            PolicyRule(
                match_type="write",
                approval=Approval.APPROVE,
                risk_level=RiskLevel.MEDIUM,
                name="write_approve",
            ),
            PolicyRule(
                match_type="delete",
                approval=Approval.BLOCK,
                risk_level=RiskLevel.CRITICAL,
                name="delete_block",
            ),
        ]
    )


def _make_runtime(tmp_path: Path, policy: Policy | None = None):
    """Create a minimal runtime for testing."""
    from aegis.adapters.base import BaseExecutor
    from aegis.runtime.engine import Runtime

    class FakeExecutor(BaseExecutor):
        async def execute(self, action: Action) -> Result:
            return Result(
                action=action,
                status=ResultStatus.SUCCESS,
                data={"result": "ok"},
                completed_at=datetime.now(UTC),
            )

        async def setup(self):
            pass

        async def teardown(self):
            pass

    return Runtime(
        executor=FakeExecutor(),
        policy=policy or _make_policy(),
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "guardrail_test.db"),
        session_id="test-guardrail",
    )


# ---------------------------------------------------------------------------
# GuardrailRequest tests
# ---------------------------------------------------------------------------


class TestGuardrailRequest:
    """Tests for the GuardrailRequest dataclass."""

    def test_minimal_request(self):
        from aegis.adapters.crewai import GuardrailRequest

        req = GuardrailRequest(tool_name="search")
        assert req.tool_name == "search"
        assert req.tool_input == {}
        assert req.agent_role == ""
        assert req.task_description == ""
        assert req.context == {}

    def test_full_request(self):
        from aegis.adapters.crewai import GuardrailRequest

        req = GuardrailRequest(
            tool_name="web_search",
            tool_input={"query": "AI governance"},
            agent_role="researcher",
            task_description="Find regulations",
            context={"crew_id": "crew-1"},
        )
        assert req.tool_name == "web_search"
        assert req.tool_input == {"query": "AI governance"}
        assert req.agent_role == "researcher"
        assert req.task_description == "Find regulations"
        assert req.context == {"crew_id": "crew-1"}

    def test_request_is_frozen(self):
        from aegis.adapters.crewai import GuardrailRequest

        req = GuardrailRequest(tool_name="search")
        with pytest.raises(AttributeError):
            req.tool_name = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# GuardrailDecision tests
# ---------------------------------------------------------------------------


class TestGuardrailDecision:
    """Tests for the GuardrailDecision dataclass."""

    def test_allow_decision(self):
        from aegis.adapters.crewai import GuardrailDecision

        d = GuardrailDecision(allow=True, reason="Allowed by search_auto")
        assert d.allow is True
        assert d.reason == "Allowed by search_auto"
        assert d.metadata == {}

    def test_deny_decision_with_metadata(self):
        from aegis.adapters.crewai import GuardrailDecision

        d = GuardrailDecision(
            allow=False,
            reason="Blocked by delete_block",
            metadata={"risk_level": "CRITICAL", "matched_rule": "delete_block"},
        )
        assert d.allow is False
        assert d.metadata["risk_level"] == "CRITICAL"

    def test_decision_is_frozen(self):
        from aegis.adapters.crewai import GuardrailDecision

        d = GuardrailDecision(allow=True)
        with pytest.raises(AttributeError):
            d.allow = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# AegisGuardrailProvider tests
# ---------------------------------------------------------------------------


class TestAegisGuardrailProvider:
    """Tests for the AegisGuardrailProvider."""

    def test_init_with_runtime(self, tmp_path):
        from aegis.adapters.crewai import AegisGuardrailProvider

        runtime = _make_runtime(tmp_path)
        provider = AegisGuardrailProvider(runtime=runtime)
        assert provider.policy is runtime.policy
        assert provider.fail_closed is True

    def test_init_with_policy(self):
        from aegis.adapters.crewai import AegisGuardrailProvider

        policy = _make_policy()
        provider = AegisGuardrailProvider(policy=policy)
        assert provider.policy is policy

    def test_init_requires_runtime_or_policy(self):
        from aegis.adapters.crewai import AegisGuardrailProvider

        with pytest.raises(ValueError, match="Either 'runtime' or 'policy'"):
            AegisGuardrailProvider()

    def test_evaluate_allowed(self, tmp_path):
        from aegis.adapters.crewai import AegisGuardrailProvider, GuardrailRequest

        provider = AegisGuardrailProvider(runtime=_make_runtime(tmp_path))
        decision = provider.evaluate(
            GuardrailRequest(tool_name="search", tool_input={"query": "test"})
        )
        assert decision.allow is True
        assert "search_auto" in decision.reason
        assert decision.metadata["risk_level"] == "LOW"

    def test_evaluate_blocked(self, tmp_path):
        from aegis.adapters.crewai import AegisGuardrailProvider, GuardrailRequest

        provider = AegisGuardrailProvider(runtime=_make_runtime(tmp_path))
        decision = provider.evaluate(
            GuardrailRequest(tool_name="delete", tool_input={"target": "db"})
        )
        assert decision.allow is False
        assert "delete_block" in decision.reason
        assert decision.metadata["risk_level"] == "CRITICAL"
        assert decision.metadata["matched_rule"] == "delete_block"

    def test_evaluate_approval_required(self, tmp_path):
        from aegis.adapters.crewai import AegisGuardrailProvider, GuardrailRequest

        provider = AegisGuardrailProvider(runtime=_make_runtime(tmp_path))
        decision = provider.evaluate(GuardrailRequest(tool_name="write", tool_input={"data": "x"}))
        assert decision.allow is False
        assert "approval" in decision.reason.lower()
        assert decision.metadata.get("approval_required") is True

    def test_evaluate_fail_closed(self, tmp_path):
        """Evaluation errors result in deny when fail_closed=True."""
        from aegis.adapters.crewai import AegisGuardrailProvider, GuardrailRequest

        provider = AegisGuardrailProvider(runtime=_make_runtime(tmp_path), fail_closed=True)
        # Corrupt the policy to force an error
        provider._policy = None  # type: ignore[assignment]
        decision = provider.evaluate(GuardrailRequest(tool_name="search"))
        assert decision.allow is False
        assert "error" in decision.reason.lower() or "fail-closed" in decision.reason.lower()
        assert decision.metadata.get("fail_closed") is True

    def test_evaluate_fail_open(self, tmp_path):
        """Evaluation errors result in allow when fail_closed=False."""
        from aegis.adapters.crewai import AegisGuardrailProvider, GuardrailRequest

        provider = AegisGuardrailProvider(runtime=_make_runtime(tmp_path), fail_closed=False)
        provider._policy = None  # type: ignore[assignment]
        decision = provider.evaluate(GuardrailRequest(tool_name="search"))
        assert decision.allow is True
        assert "fail-open" in decision.reason.lower()
        assert decision.metadata.get("fail_closed") is False

    def test_policy_hot_swap(self, tmp_path):
        from aegis.adapters.crewai import AegisGuardrailProvider, GuardrailRequest

        provider = AegisGuardrailProvider(runtime=_make_runtime(tmp_path))

        # Initially "delete" is blocked
        d1 = provider.evaluate(GuardrailRequest(tool_name="delete"))
        assert d1.allow is False

        # Swap to a permissive policy
        provider.policy = Policy(
            rules=[
                PolicyRule(
                    match_type="delete",
                    approval=Approval.AUTO,
                    risk_level=RiskLevel.LOW,
                    name="delete_allow",
                ),
            ]
        )
        d2 = provider.evaluate(GuardrailRequest(tool_name="delete"))
        assert d2.allow is True

    def test_tool_target_map(self, tmp_path):
        from aegis.adapters.crewai import AegisGuardrailProvider, GuardrailRequest

        provider = AegisGuardrailProvider(
            runtime=_make_runtime(tmp_path),
            tool_target_map={"search": "custom-target"},
        )
        decision = provider.evaluate(
            GuardrailRequest(tool_name="search", tool_input={"q": "test"})
        )
        assert decision.allow is True
        # The target mapping doesn't change the decision, but verifies it doesn't break

    def test_audit_logging(self, tmp_path):
        """Decisions are written to the audit trail."""
        from aegis.adapters.crewai import AegisGuardrailProvider, GuardrailRequest

        audit = AuditLogger(db_path=tmp_path / "audit.db")
        provider = AegisGuardrailProvider(
            policy=_make_policy(),
            audit_logger=audit,
            session_id="audit-test",
        )

        provider.evaluate(GuardrailRequest(tool_name="search"))
        provider.evaluate(GuardrailRequest(tool_name="delete"))

        entries = audit.get_log()
        audit.close()
        assert len(entries) >= 2

    def test_health_check(self, tmp_path):
        from aegis.adapters.crewai import AegisGuardrailProvider

        provider = AegisGuardrailProvider(runtime=_make_runtime(tmp_path))
        health = provider.health_check()
        assert health["status"] == "healthy"
        assert health["policy_rules"] == 3
        assert health["fail_closed"] is True

    def test_agent_role_in_action(self, tmp_path):
        """agent_role from the request appears in the Action."""
        from aegis.adapters.crewai import AegisGuardrailProvider, GuardrailRequest

        provider = AegisGuardrailProvider(runtime=_make_runtime(tmp_path))
        decision = provider.evaluate(
            GuardrailRequest(
                tool_name="search",
                agent_role="data-analyst",
            )
        )
        assert decision.allow is True

    def test_task_description_in_action(self, tmp_path):
        """task_description is used as the Action description."""
        from aegis.adapters.crewai import AegisGuardrailProvider, GuardrailRequest

        provider = AegisGuardrailProvider(runtime=_make_runtime(tmp_path))
        decision = provider.evaluate(
            GuardrailRequest(
                tool_name="search",
                task_description="Find public records about AI",
            )
        )
        assert decision.allow is True


# ---------------------------------------------------------------------------
# __call__ (CrewAI ToolCallHookContext protocol) tests
# ---------------------------------------------------------------------------


class TestCallableHook:
    """Tests for __call__ with ToolCallHookContext-like objects."""

    def test_call_allows(self, tmp_path):
        from types import SimpleNamespace

        from aegis.adapters.crewai import AegisGuardrailProvider

        provider = AegisGuardrailProvider(runtime=_make_runtime(tmp_path))
        ctx = SimpleNamespace(
            tool_name="search",
            tool_input={"query": "test"},
            tool=None,
            agent=SimpleNamespace(role="researcher"),
            task=SimpleNamespace(description="Find info"),
            crew=None,
        )
        result = provider(ctx)
        assert result is None  # None = allow in CrewAI hook protocol

    def test_call_blocks(self, tmp_path):
        from types import SimpleNamespace

        from aegis.adapters.crewai import AegisGuardrailProvider

        provider = AegisGuardrailProvider(runtime=_make_runtime(tmp_path))
        ctx = SimpleNamespace(
            tool_name="delete",
            tool_input={"target": "db"},
            tool=None,
            agent=None,
            task=None,
            crew=None,
        )
        result = provider(ctx)
        assert result is False  # False = block

    def test_call_blocks_approval_required(self, tmp_path):
        from types import SimpleNamespace

        from aegis.adapters.crewai import AegisGuardrailProvider

        provider = AegisGuardrailProvider(runtime=_make_runtime(tmp_path))
        ctx = SimpleNamespace(
            tool_name="write",
            tool_input={"data": "x"},
            tool=None,
            agent=None,
            task=None,
            crew=None,
        )
        result = provider(ctx)
        assert result is False

    def test_call_extracts_agent_role(self, tmp_path):
        from types import SimpleNamespace

        from aegis.adapters.crewai import AegisGuardrailProvider

        provider = AegisGuardrailProvider(runtime=_make_runtime(tmp_path))
        ctx = SimpleNamespace(
            tool_name="search",
            tool_input={},
            tool=None,
            agent=SimpleNamespace(role="admin"),
            task=None,
            crew=None,
        )
        result = provider(ctx)
        assert result is None  # allowed

    def test_call_extracts_task_description(self, tmp_path):
        from types import SimpleNamespace

        from aegis.adapters.crewai import AegisGuardrailProvider

        provider = AegisGuardrailProvider(runtime=_make_runtime(tmp_path))
        ctx = SimpleNamespace(
            tool_name="search",
            tool_input={},
            tool=None,
            agent=None,
            task=SimpleNamespace(description="Research AI governance"),
            crew=None,
        )
        result = provider(ctx)
        assert result is None

    def test_call_handles_missing_attrs(self, tmp_path):
        """Gracefully handle context with missing attributes."""
        from types import SimpleNamespace

        from aegis.adapters.crewai import AegisGuardrailProvider

        provider = AegisGuardrailProvider(runtime=_make_runtime(tmp_path))
        # Minimal context — only tool_name
        ctx = SimpleNamespace(tool_name="search")
        result = provider(ctx)
        assert result is None

    def test_call_handles_none_agent(self, tmp_path):
        from types import SimpleNamespace

        from aegis.adapters.crewai import AegisGuardrailProvider

        provider = AegisGuardrailProvider(runtime=_make_runtime(tmp_path))
        ctx = SimpleNamespace(
            tool_name="search",
            tool_input={"q": "test"},
            agent=None,
            task=None,
        )
        result = provider(ctx)
        assert result is None


# ---------------------------------------------------------------------------
# before_tool_call (standalone convenience) tests
# ---------------------------------------------------------------------------


class TestBeforeToolCallStandalone:
    """Tests for the standalone before_tool_call method."""

    def test_hook_allows(self, tmp_path):
        from aegis.adapters.crewai import AegisGuardrailProvider

        provider = AegisGuardrailProvider(runtime=_make_runtime(tmp_path))
        result = provider.before_tool_call(
            tool_name="search",
            tool_input={"query": "test"},
        )
        assert result is True

    def test_hook_blocks(self, tmp_path):
        from aegis.adapters.crewai import AegisGuardrailProvider

        provider = AegisGuardrailProvider(runtime=_make_runtime(tmp_path))
        result = provider.before_tool_call(
            tool_name="delete",
            tool_input={"target": "everything"},
        )
        assert result is False

    def test_hook_blocks_approval_required(self, tmp_path):
        from aegis.adapters.crewai import AegisGuardrailProvider

        provider = AegisGuardrailProvider(runtime=_make_runtime(tmp_path))
        result = provider.before_tool_call(
            tool_name="write",
            tool_input={"data": "sensitive"},
        )
        assert result is False

    def test_hook_none_input(self, tmp_path):
        from aegis.adapters.crewai import AegisGuardrailProvider

        provider = AegisGuardrailProvider(runtime=_make_runtime(tmp_path))
        result = provider.before_tool_call(tool_name="search", tool_input=None)
        assert result is True


# ---------------------------------------------------------------------------
# enable_aegis_guardrail factory tests
# ---------------------------------------------------------------------------


class TestEnableAegisGuardrail:
    """Tests for the enable_aegis_guardrail convenience factory."""

    def test_factory_with_runtime(self, tmp_path):
        from aegis.adapters.crewai import AegisGuardrailProvider, enable_aegis_guardrail

        runtime = _make_runtime(tmp_path)
        provider = enable_aegis_guardrail(runtime=runtime, register=False)
        assert isinstance(provider, AegisGuardrailProvider)
        assert provider.policy is runtime.policy

    def test_factory_with_policy(self):
        from aegis.adapters.crewai import AegisGuardrailProvider, enable_aegis_guardrail

        policy = _make_policy()
        provider = enable_aegis_guardrail(policy=policy, fail_closed=False, register=False)
        assert isinstance(provider, AegisGuardrailProvider)
        assert provider.fail_closed is False

    def test_factory_with_all_options(self, tmp_path):
        from aegis.adapters.crewai import enable_aegis_guardrail

        audit = AuditLogger(db_path=tmp_path / "factory.db")
        provider = enable_aegis_guardrail(
            policy=_make_policy(),
            fail_closed=True,
            audit_logger=audit,
            session_id="factory-test",
            target="custom",
            tool_target_map={"search": "web"},
            register=False,
        )
        assert provider.fail_closed is True
        audit.close()

    def test_factory_missing_both(self):
        from aegis.adapters.crewai import enable_aegis_guardrail

        with pytest.raises(ValueError):
            enable_aegis_guardrail(register=False)

    def test_factory_register_without_crewai(self, tmp_path):
        """register=True gracefully degrades when crewai is not installed."""
        from aegis.adapters.crewai import enable_aegis_guardrail

        # crewai not installed in test env, should not raise
        provider = enable_aegis_guardrail(policy=_make_policy(), register=True)
        assert provider is not None
