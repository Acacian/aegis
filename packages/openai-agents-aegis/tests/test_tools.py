"""Tests for openai-agents-aegis governance wrappers."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest
from aegis import Policy

from openai_agents_aegis import GovernedFunctionTool, govern_tools, governed_tool

# ---------------------------------------------------------------------------
# Policy fixtures
# ---------------------------------------------------------------------------

ALLOW_ALL_YAML = """\
version: "1"
defaults:
  risk_level: low
  approval: auto
rules: []
"""

BLOCK_DELETE_YAML = """\
version: "1"
defaults:
  risk_level: low
  approval: auto
rules:
  - name: block_delete
    match:
      type: "delete_*"
    risk_level: critical
    approval: block
"""


@pytest.fixture
def allow_policy(tmp_path):
    p = tmp_path / "allow.yaml"
    p.write_text(ALLOW_ALL_YAML)
    return Policy.from_yaml(str(p))


@pytest.fixture
def block_delete_policy(tmp_path):
    p = tmp_path / "block.yaml"
    p.write_text(BLOCK_DELETE_YAML)
    return Policy.from_yaml(str(p))


# ---------------------------------------------------------------------------
# Mock FunctionTool — mimics the OpenAI Agents SDK FunctionTool interface
# ---------------------------------------------------------------------------


class MockFunctionTool:
    """Minimal mock of ``agents.FunctionTool``."""

    def __init__(self, name: str, description: str, handler: Any = None) -> None:
        self.name = name
        self.description = description
        self.params_json_schema: dict[str, Any] = {
            "type": "object",
            "properties": {"query": {"type": "string"}},
        }
        self._handler = handler or AsyncMock(return_value="tool result")

    async def on_invoke_tool(self, ctx: Any, input_str: str) -> str:
        return await self._handler(ctx, input_str)


# ---------------------------------------------------------------------------
# Tests: GovernedFunctionTool
# ---------------------------------------------------------------------------


class TestGovernedFunctionTool:
    @pytest.mark.asyncio
    async def test_allowed_action_passes_through(self, allow_policy):
        inner = MockFunctionTool("web_search", "Search the web")
        inner._handler = AsyncMock(return_value="search results")
        tool = GovernedFunctionTool(inner, allow_policy)

        result = await tool.on_invoke_tool(None, '{"query": "AI governance"}')
        assert result == "search results"
        inner._handler.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_blocked_action_returns_message(self, block_delete_policy):
        inner = MockFunctionTool("delete_records", "Delete records")
        tool = GovernedFunctionTool(inner, block_delete_policy)

        result = await tool.on_invoke_tool(None, '{"record_id": "123"}')
        assert "[BLOCKED by Aegis]" in result
        assert "critical" in result
        inner._handler.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_preserves_tool_name(self, allow_policy):
        inner = MockFunctionTool("web_search", "Search the web")
        tool = GovernedFunctionTool(inner, allow_policy)
        assert tool.name == "web_search"

    @pytest.mark.asyncio
    async def test_preserves_tool_description(self, allow_policy):
        inner = MockFunctionTool("web_search", "Search the web")
        tool = GovernedFunctionTool(inner, allow_policy)
        assert tool.description == "Search the web"

    @pytest.mark.asyncio
    async def test_preserves_params_schema(self, allow_policy):
        inner = MockFunctionTool("web_search", "Search the web")
        tool = GovernedFunctionTool(inner, allow_policy)
        assert "query" in tool.params_json_schema["properties"]

    @pytest.mark.asyncio
    async def test_handles_invalid_json_input(self, allow_policy):
        inner = MockFunctionTool("web_search", "Search the web")
        inner._handler = AsyncMock(return_value="ok")
        tool = GovernedFunctionTool(inner, allow_policy)

        result = await tool.on_invoke_tool(None, "not-json")
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_handles_empty_input(self, allow_policy):
        inner = MockFunctionTool("web_search", "Search the web")
        inner._handler = AsyncMock(return_value="ok")
        tool = GovernedFunctionTool(inner, allow_policy)

        result = await tool.on_invoke_tool(None, "")
        assert result == "ok"

    def test_repr(self, allow_policy):
        inner = MockFunctionTool("web_search", "Search the web")
        tool = GovernedFunctionTool(inner, allow_policy)
        assert "GovernedFunctionTool" in repr(tool)
        assert "web_search" in repr(tool)


# ---------------------------------------------------------------------------
# Tests: governed_tool decorator
# ---------------------------------------------------------------------------


class TestGovernedToolDecorator:
    @pytest.mark.asyncio
    async def test_allowed_action_passes_through(self, allow_policy):
        @governed_tool(policy=allow_policy)
        async def web_search(query: str) -> str:
            """Search the web."""
            return f"Results for: {query}"

        result = await web_search(query="AI governance")
        assert "Results for: AI governance" in result

    @pytest.mark.asyncio
    async def test_blocked_action_returns_message(self, block_delete_policy):
        @governed_tool(policy=block_delete_policy)
        async def delete_records(record_id: str) -> str:
            """Delete records."""
            return f"Deleted: {record_id}"

        result = await delete_records(record_id="123")
        assert "[BLOCKED by Aegis]" in result
        assert "critical" in result

    @pytest.mark.asyncio
    async def test_preserves_function_name(self, allow_policy):
        @governed_tool(policy=allow_policy)
        async def my_custom_tool(x: int) -> str:
            """Custom tool."""
            return str(x)

        assert my_custom_tool.__name__ == "my_custom_tool"

    @pytest.mark.asyncio
    async def test_preserves_function_docstring(self, allow_policy):
        @governed_tool(policy=allow_policy)
        async def my_tool(x: int) -> str:
            """This is a custom docstring."""
            return str(x)

        assert my_tool.__doc__ == "This is a custom docstring."

    @pytest.mark.asyncio
    async def test_wraps_sync_function(self, allow_policy):
        @governed_tool(policy=allow_policy)
        def sync_tool(value: str) -> str:
            """A sync tool."""
            return f"sync: {value}"

        result = await sync_tool(value="test")
        assert "sync: test" in result

    @pytest.mark.asyncio
    async def test_custom_action_target(self, allow_policy):
        @governed_tool(policy=allow_policy, action_target="custom_system")
        async def my_tool(x: int) -> str:
            return str(x)

        # Should execute successfully — allow_policy allows everything
        result = await my_tool(x=42)
        assert "42" in result

    @pytest.mark.asyncio
    async def test_policy_from_yaml_path(self, tmp_path):
        p = tmp_path / "policy.yaml"
        p.write_text(ALLOW_ALL_YAML)

        @governed_tool(policy=str(p))
        async def my_tool(x: int) -> str:
            return str(x)

        result = await my_tool(x=1)
        assert "1" in result

    @pytest.mark.asyncio
    async def test_policy_from_dict(self):
        policy_dict = {
            "version": "1",
            "defaults": {"risk_level": "low", "approval": "auto"},
            "rules": [],
        }

        @governed_tool(policy=policy_dict)
        async def my_tool(x: int) -> str:
            return str(x)

        result = await my_tool(x=5)
        assert "5" in result


# ---------------------------------------------------------------------------
# Tests: govern_tools (batch)
# ---------------------------------------------------------------------------


class TestGovernTools:
    def test_wraps_multiple_tools(self, allow_policy):
        tools = govern_tools(
            [
                MockFunctionTool("search", "Search"),
                MockFunctionTool("delete_records", "Delete"),
            ],
            policy=allow_policy,
        )
        assert len(tools) == 2
        assert all(isinstance(t, GovernedFunctionTool) for t in tools)

    def test_shares_policy_instance(self, allow_policy):
        tools = govern_tools(
            [
                MockFunctionTool("search", "Search"),
                MockFunctionTool("delete", "Delete"),
            ],
            policy=allow_policy,
        )
        assert tools[0].aegis_policy is tools[1].aegis_policy

    @pytest.mark.asyncio
    async def test_selective_blocking(self, block_delete_policy):
        search = MockFunctionTool("web_search", "Search")
        search._handler = AsyncMock(return_value="search results")
        delete = MockFunctionTool("delete_records", "Delete")

        governed_search, governed_delete = govern_tools(
            [search, delete],
            policy=block_delete_policy,
        )

        search_result = await governed_search.on_invoke_tool(None, '{"query": "test"}')
        delete_result = await governed_delete.on_invoke_tool(None, '{"record_id": "123"}')

        assert "search results" in search_result
        assert "[BLOCKED by Aegis]" in delete_result

    def test_custom_action_target(self, allow_policy):
        tools = govern_tools(
            [MockFunctionTool("search", "Search")],
            policy=allow_policy,
            action_target="custom",
        )
        assert tools[0].action_target == "custom"

    def test_policy_from_yaml_path(self, tmp_path):
        p = tmp_path / "policy.yaml"
        p.write_text(ALLOW_ALL_YAML)
        tools = govern_tools(
            [MockFunctionTool("search", "Search")],
            policy=str(p),
        )
        assert len(tools) == 1
        assert isinstance(tools[0], GovernedFunctionTool)
