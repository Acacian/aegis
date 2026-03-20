"""Tests for the Anthropic Claude adapter."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aegis.core.action import Action
from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.result import Result, ResultStatus
from aegis.core.risk import RiskLevel
from aegis.runtime.approval import AutoApprovalHandler
from aegis.runtime.audit import AuditLogger


@pytest.fixture
def mock_runtime(tmp_path):
    """Create a minimal runtime-like object for testing."""
    from aegis.adapters.base import BaseExecutor
    from aegis.runtime.engine import Runtime

    class FakeExecutor(BaseExecutor):
        async def execute(self, action: Action) -> Result:
            return Result(
                action=action,
                status=ResultStatus.SUCCESS,
                data={"tool_result": "success"},
                completed_at=datetime.now(UTC),
            )

        async def setup(self):
            pass

        async def teardown(self):
            pass

    return Runtime(
        executor=FakeExecutor(),
        policy=Policy(
            rules=[
                PolicyRule(match_type="*", approval=Approval.AUTO, risk_level=RiskLevel.LOW),
            ]
        ),
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "anthropic_test.db"),
        session_id="test-anthropic",
    )


@pytest.mark.asyncio
async def test_govern_tool_call(mock_runtime):
    """govern_tool_call should create an Action, plan, and execute."""
    from aegis.adapters.anthropic import govern_tool_call

    result = await govern_tool_call(
        runtime=mock_runtime,
        tool_name="search",
        tool_input={"query": "AI governance"},
        target="web",
    )

    assert result.ok
    assert result.status == ResultStatus.SUCCESS
    assert result.data == {"tool_result": "success"}


@pytest.mark.asyncio
async def test_govern_tool_call_default_description(mock_runtime):
    """govern_tool_call should generate a default description when not provided."""
    from aegis.adapters.anthropic import govern_tool_call

    result = await govern_tool_call(
        runtime=mock_runtime,
        tool_name="search",
        tool_input={"query": "test"},
    )

    assert result.ok


@pytest.mark.asyncio
async def test_govern_tool_call_custom_description(mock_runtime):
    """govern_tool_call should use a custom description when provided."""
    from aegis.adapters.anthropic import govern_tool_call

    result = await govern_tool_call(
        runtime=mock_runtime,
        tool_name="search",
        tool_input={"query": "test"},
        description="Custom search description",
    )

    assert result.ok


def test_tool_results_to_api_format_success():
    """Successful results should convert to tool_result format."""
    from aegis.adapters.anthropic import tool_results_to_api_format

    results = [
        Result(
            action=Action("search", "web"),
            status=ResultStatus.SUCCESS,
            data={"answer": "42"},
        ),
    ]

    api_results = tool_results_to_api_format(results)

    assert len(api_results) == 1
    assert api_results[0]["type"] == "tool_result"
    assert api_results[0]["is_error"] is False
    assert "42" in api_results[0]["content"]


def test_tool_results_to_api_format_failure():
    """Failed results should be marked as errors."""
    from aegis.adapters.anthropic import tool_results_to_api_format

    results = [
        Result(
            action=Action("search", "web"),
            status=ResultStatus.FAILED,
            error="Something went wrong",
        ),
    ]

    api_results = tool_results_to_api_format(results)

    assert len(api_results) == 1
    assert api_results[0]["type"] == "tool_result"
    assert api_results[0]["is_error"] is True
    assert "Something went wrong" in api_results[0]["content"]
    assert "FAILED" in api_results[0]["content"]


def test_tool_results_to_api_format_blocked():
    """Blocked results should be marked as errors."""
    from aegis.adapters.anthropic import tool_results_to_api_format

    results = [
        Result(
            action=Action("delete", "db"),
            status=ResultStatus.BLOCKED,
            error="Blocked by policy",
        ),
    ]

    api_results = tool_results_to_api_format(results)

    assert api_results[0]["is_error"] is True


def test_tool_results_to_api_format_multiple():
    """Multiple results should all be converted."""
    from aegis.adapters.anthropic import tool_results_to_api_format

    results = [
        Result(action=Action("read", "web"), status=ResultStatus.SUCCESS, data="data1"),
        Result(action=Action("write", "db"), status=ResultStatus.FAILED, error="oops"),
        Result(action=Action("delete", "db"), status=ResultStatus.DENIED, error="denied"),
    ]

    api_results = tool_results_to_api_format(results)

    assert len(api_results) == 3
    assert api_results[0]["is_error"] is False
    assert api_results[1]["is_error"] is True
    assert api_results[2]["is_error"] is True
