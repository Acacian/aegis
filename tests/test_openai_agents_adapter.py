"""Tests for the OpenAI Agents SDK adapter."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis.core.action import Action
from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.result import Result, ResultStatus
from aegis.core.risk import RiskLevel
from aegis.runtime.approval import AutoApprovalHandler
from aegis.runtime.approval_callback import CallbackApprovalHandler
from aegis.runtime.audit import AuditLogger


def _make_runtime(tmp_path: Path, policy: Policy | None = None):
    """Create a runtime for testing."""
    from aegis.adapters.base import BaseExecutor
    from aegis.runtime.engine import Runtime

    class FakeExecutor(BaseExecutor):
        async def execute(self, action: Action) -> Result:
            return Result(
                action=action,
                status=ResultStatus.SUCCESS,
                data={"ok": True},
                completed_at=datetime.now(UTC),
            )

        async def setup(self):
            pass

        async def teardown(self):
            pass

    return Runtime(
        executor=FakeExecutor(),
        policy=policy
        or Policy(
            rules=[
                PolicyRule(match_type="search", approval=Approval.AUTO, risk_level=RiskLevel.LOW),
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
        ),
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "openai_test.db"),
        session_id="test-openai",
    )


class TestGovernedTool:
    """Tests for the governed_tool decorator."""

    @pytest.mark.asyncio
    async def test_allowed_sync_function(self, tmp_path):
        """Should execute an allowed sync function."""
        from aegis.adapters.openai_agents import governed_tool

        runtime = _make_runtime(tmp_path)

        @governed_tool(runtime=runtime, action_type="search", action_target="web")
        def search(query: str) -> str:
            """Search the web."""
            return f"results for {query}"

        result = await search(query="test")
        assert "results for test" in result

    @pytest.mark.asyncio
    async def test_allowed_async_function(self, tmp_path):
        """Should execute an allowed async function."""
        from aegis.adapters.openai_agents import governed_tool

        runtime = _make_runtime(tmp_path)

        @governed_tool(runtime=runtime, action_type="search", action_target="web")
        async def async_search(query: str) -> str:
            """Search the web."""
            return f"async results for {query}"

        result = await async_search(query="test")
        assert "async results for test" in result

    @pytest.mark.asyncio
    async def test_blocked_action(self, tmp_path):
        """Should return blocked message for blocked actions."""
        from aegis.adapters.openai_agents import governed_tool

        runtime = _make_runtime(tmp_path)

        @governed_tool(runtime=runtime, action_type="delete", action_target="db")
        def delete_all() -> str:
            """Delete everything."""
            return "deleted"

        result = await delete_all()
        assert "AEGIS BLOCKED" in result
        assert "delete_block" in result

    @pytest.mark.asyncio
    async def test_approved_action(self, tmp_path):
        """Should request approval and proceed when approved."""
        from aegis.adapters.openai_agents import governed_tool

        runtime = _make_runtime(tmp_path)
        # AutoApprovalHandler always approves

        @governed_tool(runtime=runtime, action_type="write", action_target="db")
        def write_data(data: str) -> str:
            """Write data."""
            return f"wrote: {data}"

        result = await write_data(data="hello")
        assert "wrote: hello" in result

    @pytest.mark.asyncio
    async def test_denied_action(self, tmp_path):
        """Should return denied message when approval is denied."""
        from aegis.adapters.openai_agents import governed_tool

        runtime = _make_runtime(tmp_path)
        runtime.approval = CallbackApprovalHandler(lambda d: False)

        @governed_tool(runtime=runtime, action_type="write", action_target="db")
        def write_data(data: str) -> str:
            """Write data."""
            return f"wrote: {data}"

        result = await write_data(data="hello")
        assert "AEGIS DENIED" in result

    @pytest.mark.asyncio
    async def test_function_exception(self, tmp_path):
        """Should catch exceptions and return error message."""
        from aegis.adapters.openai_agents import governed_tool

        runtime = _make_runtime(tmp_path)

        @governed_tool(runtime=runtime, action_type="search", action_target="web")
        def broken_search(query: str) -> str:
            """Search."""
            raise ValueError("search failed")

        result = await broken_search(query="test")
        assert "AEGIS ERROR" in result
        assert "search failed" in result

    @pytest.mark.asyncio
    async def test_custom_description(self, tmp_path):
        """Should use custom description over docstring."""
        from aegis.adapters.openai_agents import governed_tool

        runtime = _make_runtime(tmp_path)

        @governed_tool(
            runtime=runtime,
            action_type="search",
            action_target="web",
            description="Custom desc",
        )
        def my_func(q: str) -> str:
            """Docstring here."""
            return q

        result = await my_func(q="hello")
        assert "hello" in result

    @pytest.mark.asyncio
    async def test_no_docstring_uses_name(self, tmp_path):
        """Should use function name when no docstring or description."""
        from aegis.adapters.openai_agents import governed_tool

        runtime = _make_runtime(tmp_path)

        @governed_tool(runtime=runtime, action_type="search", action_target="web")
        def my_func_name(q: str) -> str:
            return q

        # The function name should be used as description
        result = await my_func_name(q="test")
        assert "test" in result


def test_openai_agents_import_guard():
    """_require_openai_agents should raise ImportError with helpful message."""
    original = sys.modules.pop("agents", None)
    sys.modules["agents"] = None  # type: ignore[assignment]
    try:
        from aegis.adapters.openai_agents import _require_openai_agents

        with pytest.raises(ImportError, match="openai-agents"):
            _require_openai_agents()
    finally:
        if original:
            sys.modules["agents"] = original
        else:
            sys.modules.pop("agents", None)
