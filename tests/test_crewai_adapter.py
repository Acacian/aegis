"""Tests for the CrewAI adapter with mocked crewai dependency."""

from __future__ import annotations

import sys
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


def _make_runtime(tmp_path: Path, policy: Policy | None = None):
    """Create a minimal runtime for CrewAI testing."""
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
        audit_logger=AuditLogger(db_path=tmp_path / "crewai_test.db"),
        session_id="test-crewai",
    )


class TestAegisCrewAITool:
    """Tests for AegisCrewAITool."""

    def test_init(self, mock_crewai, tmp_path):
        """Tool should initialize with all required attributes."""
        from aegis.adapters.crewai import AegisCrewAITool

        runtime = _make_runtime(tmp_path)
        tool = AegisCrewAITool(
            runtime=runtime,
            name="test_tool",
            description="A test tool",
            action_type="search",
            action_target="web",
            fn=lambda q: f"result: {q}",
        )

        assert tool.name == "test_tool"
        assert tool.description == "A test tool"
        assert tool.action_type == "search"
        assert tool.action_target == "web"

    def test_call_sync_fn(self, mock_crewai, tmp_path):
        """__call__ should execute a sync function through governance."""
        from aegis.adapters.crewai import AegisCrewAITool

        runtime = _make_runtime(tmp_path)
        tool = AegisCrewAITool(
            runtime=runtime,
            name="search_tool",
            description="Search things",
            action_type="search",
            action_target="web",
            fn=lambda *args, **kwargs: f"found: {args[0] if args else kwargs.get('input', '')}",
        )

        # __call__ runs the event loop synchronously
        import asyncio

        result = asyncio.run(tool._run("test query"))
        assert "found" in result

    @pytest.mark.asyncio
    async def test_run_allowed_action(self, mock_crewai, tmp_path):
        """_run should execute when policy allows."""
        from aegis.adapters.crewai import AegisCrewAITool

        runtime = _make_runtime(tmp_path)
        tool = AegisCrewAITool(
            runtime=runtime,
            name="search_tool",
            description="Search",
            action_type="search",
            action_target="web",
            fn=lambda *args, **kwargs: f"result: {args} {kwargs}",
        )

        result = await tool._run("query")
        assert "result" in result

    @pytest.mark.asyncio
    async def test_run_blocked_action(self, mock_crewai, tmp_path):
        """_run should return blocked message when policy blocks."""
        from aegis.adapters.crewai import AegisCrewAITool

        runtime = _make_runtime(tmp_path)
        tool = AegisCrewAITool(
            runtime=runtime,
            name="delete_tool",
            description="Delete things",
            action_type="delete",
            action_target="db",
            fn=lambda **kwargs: "deleted",
        )

        result = await tool._run()
        assert "AEGIS BLOCKED" in result
        assert "delete_block" in result

    @pytest.mark.asyncio
    async def test_run_approved_action(self, mock_crewai, tmp_path):
        """_run should request approval for approve-required actions."""
        from aegis.adapters.crewai import AegisCrewAITool

        runtime = _make_runtime(tmp_path)
        # AutoApprovalHandler always approves
        tool = AegisCrewAITool(
            runtime=runtime,
            name="write_tool",
            description="Write things",
            action_type="write",
            action_target="db",
            fn=lambda **kwargs: "written",
        )

        result = await tool._run()
        assert "written" in result

    @pytest.mark.asyncio
    async def test_run_denied_action(self, mock_crewai, tmp_path):
        """_run should return denied message when approval is denied."""
        from aegis.adapters.crewai import AegisCrewAITool
        from aegis.runtime.approval_callback import CallbackApprovalHandler

        runtime = _make_runtime(tmp_path)
        runtime.approval = CallbackApprovalHandler(lambda d: False)

        tool = AegisCrewAITool(
            runtime=runtime,
            name="write_tool",
            description="Write things",
            action_type="write",
            action_target="db",
            fn=lambda **kwargs: "written",
        )

        result = await tool._run()
        assert "AEGIS DENIED" in result

    @pytest.mark.asyncio
    async def test_run_fn_exception(self, mock_crewai, tmp_path):
        """_run should catch exceptions and return error message."""
        from aegis.adapters.crewai import AegisCrewAITool

        runtime = _make_runtime(tmp_path)

        def failing_fn(*args, **kwargs):
            raise ValueError("Something broke")

        tool = AegisCrewAITool(
            runtime=runtime,
            name="search_tool",
            description="Search",
            action_type="search",
            action_target="web",
            fn=failing_fn,
        )

        result = await tool._run("query")
        assert "AEGIS ERROR" in result
        assert "Something broke" in result

    @pytest.mark.asyncio
    async def test_run_async_fn(self, mock_crewai, tmp_path):
        """_run should handle async functions."""
        from aegis.adapters.crewai import AegisCrewAITool

        runtime = _make_runtime(tmp_path)

        async def async_search(*args, **kwargs):
            return f"async result: {args} {kwargs}"

        tool = AegisCrewAITool(
            runtime=runtime,
            name="async_tool",
            description="Async search",
            action_type="search",
            action_target="web",
            fn=async_search,
        )

        result = await tool._run("query")
        assert "async result" in result

    @pytest.mark.asyncio
    async def test_run_with_kwargs(self, mock_crewai, tmp_path):
        """_run should pass kwargs to the function."""
        from aegis.adapters.crewai import AegisCrewAITool

        runtime = _make_runtime(tmp_path)

        def fn_with_kwargs(**kwargs):
            return f"got: {kwargs}"

        tool = AegisCrewAITool(
            runtime=runtime,
            name="tool",
            description="Test",
            action_type="search",
            action_target="web",
            fn=fn_with_kwargs,
        )

        result = await tool._run(key="value")
        assert "value" in result

    def test_call_invokes_run(self, mock_crewai, tmp_path):
        """__call__ should invoke _run synchronously."""
        from aegis.adapters.crewai import AegisCrewAITool

        runtime = _make_runtime(tmp_path)
        tool = AegisCrewAITool(
            runtime=runtime,
            name="tool",
            description="Test",
            action_type="search",
            action_target="web",
            fn=lambda *args, **kwargs: "sync_result",
        )

        # __call__ uses asyncio.get_event_loop().run_until_complete
        # This works in a sync context (no running loop)
        result = tool("query")
        assert "sync_result" in result


def test_crewai_import_guard_message():
    """_require_crewai should raise ImportError with helpful message."""
    original = sys.modules.pop("crewai", None)
    sys.modules["crewai"] = None  # type: ignore[assignment]
    try:
        from aegis.adapters.crewai import _require_crewai

        with pytest.raises(ImportError, match="crewai"):
            _require_crewai()
    finally:
        if original:
            sys.modules["crewai"] = original
        else:
            sys.modules.pop("crewai", None)
