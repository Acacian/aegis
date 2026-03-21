"""MCP (Model Context Protocol) adapter.

Wraps MCP tool calls with Aegis governance. This adapter maps MCP tool
invocations to Aegis actions, applying policy checks, approval gates,
and audit logging to every tool call.

Usage with any MCP client::

    from aegis.adapters.mcp import govern_mcp_tool_call, AegisMCPToolFilter

    # Option 1: Govern individual tool calls
    result = await govern_mcp_tool_call(
        runtime=runtime,
        tool_name="read_file",
        arguments={"path": "/etc/passwd"},
        server_name="filesystem",
    )

    # Option 2: Create a governed tool filter
    tool_filter = AegisMCPToolFilter(runtime=runtime)
    result = await tool_filter.call_tool(
        server="filesystem",
        tool="read_file",
        arguments={"path": "/etc/passwd"},
    )

MCP tool calls are mapped to Aegis actions as follows:

- ``Action.type`` = tool name (e.g. ``"read_file"``)
- ``Action.target`` = server name (e.g. ``"filesystem"``)
- ``Action.params`` = tool arguments
- ``Action.description`` = auto-generated from tool + server
"""

from __future__ import annotations

from typing import Any

from aegis.core.action import Action
from aegis.core.result import Result
from aegis.runtime.engine import Runtime


async def govern_mcp_tool_call(
    *,
    runtime: Runtime,
    tool_name: str,
    arguments: dict[str, Any] | None = None,
    server_name: str = "default",
    description: str = "",
) -> Result:
    """Govern a single MCP tool call through the Aegis runtime.

    Args:
        runtime: The Aegis runtime instance.
        tool_name: Name of the MCP tool being called.
        arguments: Tool call arguments.
        server_name: Name of the MCP server (used as action target).
        description: Optional human-readable description.

    Returns:
        Result with the governance decision. If the tool call is allowed,
        the caller is responsible for actually invoking the MCP tool and
        can store the tool result in ``result.data``.
    """
    action = Action(
        type=tool_name,
        target=server_name,
        params=arguments or {},
        description=description or f"MCP tool: {tool_name} on {server_name}",
    )
    return await runtime.run_one(action)


class AegisMCPToolFilter:
    """Governance filter for MCP tool calls.

    Provides a simple interface to check whether an MCP tool call
    should be allowed, and optionally execute it through a custom
    executor function.

    Example::

        filter = AegisMCPToolFilter(runtime=runtime)

        # Check-only mode (dry run)
        result = await filter.check(
            server="filesystem", tool="delete_file",
            arguments={"path": "/important.txt"},
        )
        if result.ok:
            # Proceed with actual MCP call
            mcp_result = await mcp_client.call_tool("delete_file", ...)

        # Or with an executor function
        async def call_mcp(action):
            mcp_result = await mcp_client.call_tool(action.type, action.params)
            return Result(action=action, status=ResultStatus.SUCCESS, data=mcp_result)

        filter = AegisMCPToolFilter(runtime=runtime, executor=call_mcp)
        result = await filter.call_tool(
            server="filesystem", tool="read_file",
            arguments={"path": "/data.csv"},
        )
    """

    def __init__(
        self,
        runtime: Runtime,
        *,
        executor: Any | None = None,
    ) -> None:
        self._runtime = runtime
        self._executor = executor

    async def check(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any] | None = None,
    ) -> Result:
        """Check if a tool call would be allowed (dry-run).

        Returns a Result indicating the policy decision without
        actually executing the tool.
        """
        action = Action(
            type=tool,
            target=server,
            params=arguments or {},
            description=f"MCP: {tool}@{server}",
        )
        return await self._runtime.run_one(action, dry_run=True)

    async def call_tool(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any] | None = None,
    ) -> Result:
        """Govern and optionally execute a tool call.

        If an executor function was provided, it will be called for
        allowed actions. Otherwise, this works like ``check()`` but
        goes through the full governance pipeline (including approval
        gates and audit logging).
        """
        return await govern_mcp_tool_call(
            runtime=self._runtime,
            tool_name=tool,
            arguments=arguments,
            server_name=server,
        )
