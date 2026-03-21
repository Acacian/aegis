"""Tests for MCP adapter."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis.adapters.mcp import AegisMCPToolFilter, govern_mcp_tool_call
from aegis.core.action import Action
from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.result import Result, ResultStatus
from aegis.core.risk import RiskLevel
from aegis.runtime.approval import AutoApprovalHandler
from aegis.runtime.audit import AuditLogger
from aegis.runtime.engine import Runtime


class FakeExecutor:
    def __init__(self) -> None:
        self.executed: list[Action] = []

    async def execute(self, action: Action) -> Result:
        self.executed.append(action)
        return Result(action=action, status=ResultStatus.SUCCESS, data={"tool_result": "ok"})

    async def verify(self, action: Action, result: Result) -> bool:
        return result.ok

    async def setup(self) -> None:
        pass

    async def teardown(self) -> None:
        pass


@pytest.fixture()
def policy() -> Policy:
    return Policy(
        rules=[
            PolicyRule(
                match_type="read*",
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
                name="read_auto",
            ),
            PolicyRule(
                match_type="delete*",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
                name="delete_block",
            ),
        ]
    )


@pytest.fixture()
def runtime(tmp_path: Path, policy: Policy) -> Runtime:
    return Runtime(
        executor=FakeExecutor(),
        policy=policy,
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "test.db"),
    )


# -- govern_mcp_tool_call ---------------------------------------------------


async def test_govern_mcp_tool_call_allowed(runtime: Runtime) -> None:
    result = await govern_mcp_tool_call(
        runtime=runtime,
        tool_name="read_file",
        arguments={"path": "/data.csv"},
        server_name="filesystem",
    )
    assert result.status == ResultStatus.SUCCESS
    assert result.data == {"tool_result": "ok"}


async def test_govern_mcp_tool_call_blocked(runtime: Runtime) -> None:
    result = await govern_mcp_tool_call(
        runtime=runtime,
        tool_name="delete_file",
        arguments={"path": "/important.txt"},
        server_name="filesystem",
    )
    assert result.status == ResultStatus.BLOCKED


async def test_govern_mcp_tool_call_default_server(runtime: Runtime) -> None:
    result = await govern_mcp_tool_call(
        runtime=runtime,
        tool_name="read_data",
    )
    assert result.status == ResultStatus.SUCCESS


async def test_govern_mcp_tool_call_custom_description(
    runtime: Runtime,
) -> None:
    result = await govern_mcp_tool_call(
        runtime=runtime,
        tool_name="read_config",
        server_name="settings",
        description="Read application config",
    )
    assert result.status == ResultStatus.SUCCESS


# -- AegisMCPToolFilter.check -----------------------------------------------


async def test_tool_filter_check_allowed(runtime: Runtime) -> None:
    tool_filter = AegisMCPToolFilter(runtime=runtime)
    result = await tool_filter.check(
        server="filesystem",
        tool="read_file",
        arguments={"path": "/data.csv"},
    )
    assert result.status == ResultStatus.SUCCESS
    assert result.data.get("dry_run") is True


async def test_tool_filter_check_blocked(runtime: Runtime) -> None:
    tool_filter = AegisMCPToolFilter(runtime=runtime)
    result = await tool_filter.check(
        server="filesystem",
        tool="delete_file",
    )
    assert result.status == ResultStatus.BLOCKED


# -- AegisMCPToolFilter.call_tool -------------------------------------------


async def test_tool_filter_call_tool(runtime: Runtime) -> None:
    tool_filter = AegisMCPToolFilter(runtime=runtime)
    result = await tool_filter.call_tool(
        server="filesystem",
        tool="read_file",
        arguments={"path": "/data.csv"},
    )
    assert result.status == ResultStatus.SUCCESS


async def test_tool_filter_call_tool_blocked(runtime: Runtime) -> None:
    tool_filter = AegisMCPToolFilter(runtime=runtime)
    result = await tool_filter.call_tool(
        server="filesystem",
        tool="delete_file",
    )
    assert result.status == ResultStatus.BLOCKED


# -- Action mapping ----------------------------------------------------------


async def test_mcp_action_mapping(runtime: Runtime) -> None:
    """Verify MCP tool calls are correctly mapped to Aegis actions."""
    executor = runtime.executor
    await govern_mcp_tool_call(
        runtime=runtime,
        tool_name="read_file",
        arguments={"path": "/test.txt", "encoding": "utf-8"},
        server_name="fs_server",
    )
    assert len(executor.executed) == 1
    action = executor.executed[0]
    assert action.type == "read_file"
    assert action.target == "fs_server"
    assert action.params == {"path": "/test.txt", "encoding": "utf-8"}
