"""Tests for langchain-aegis governance wrappers."""

from __future__ import annotations

import pytest
from aegis import Policy
from langchain_core.callbacks import (
    AsyncCallbackManagerForToolRun,
    CallbackManagerForToolRun,
)
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

from langchain_aegis import GovernedTool, govern_tool, govern_tools

# ---------------------------------------------------------------------------
# Fixtures
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


class SearchInput(BaseModel):
    query: str = Field(description="Search query")


class FakeSearchTool(BaseTool):
    name: str = "web_search"
    description: str = "Search the web"
    args_schema: type[BaseModel] | None = SearchInput

    def _run(
        self,
        query: str,
        run_manager: CallbackManagerForToolRun | None = None,
    ) -> str:
        return f"Results for: {query}"

    async def _arun(
        self,
        query: str,
        run_manager: AsyncCallbackManagerForToolRun | None = None,
    ) -> str:
        return f"Async results for: {query}"


class FakeDeleteTool(BaseTool):
    name: str = "delete_records"
    description: str = "Delete records from database"

    def _run(
        self,
        record_id: str = "",
        run_manager: CallbackManagerForToolRun | None = None,
    ) -> str:
        return f"Deleted: {record_id}"

    async def _arun(
        self,
        record_id: str = "",
        run_manager: AsyncCallbackManagerForToolRun | None = None,
    ) -> str:
        return f"Async deleted: {record_id}"


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
# Tests: govern_tool
# ---------------------------------------------------------------------------


class TestGovernTool:
    def test_allowed_action_passes_through(self, allow_policy):
        tool = govern_tool(FakeSearchTool(), policy=allow_policy)
        result = tool.invoke({"query": "AI governance"})
        assert "Results for: AI governance" in result

    def test_blocked_action_returns_message(self, block_delete_policy):
        tool = govern_tool(FakeDeleteTool(), policy=block_delete_policy)
        result = tool.invoke({"record_id": "123"})
        assert "[BLOCKED by Aegis]" in result
        assert "critical" in result

    def test_preserves_tool_name(self, allow_policy):
        tool = govern_tool(FakeSearchTool(), policy=allow_policy)
        assert tool.name == "web_search"

    def test_preserves_tool_description(self, allow_policy):
        tool = govern_tool(FakeSearchTool(), policy=allow_policy)
        assert tool.description == "Search the web"

    def test_preserves_args_schema(self, allow_policy):
        tool = govern_tool(FakeSearchTool(), policy=allow_policy)
        # args_schema is forwarded via get_input_schema / args
        schema = tool.get_input_schema()
        assert "query" in schema.model_fields

    def test_policy_from_yaml_path(self, tmp_path):
        p = tmp_path / "policy.yaml"
        p.write_text(ALLOW_ALL_YAML)
        tool = govern_tool(FakeSearchTool(), policy=str(p))
        result = tool.invoke({"query": "test"})
        assert "Results for: test" in result

    def test_returns_governed_tool_type(self, allow_policy):
        tool = govern_tool(FakeSearchTool(), policy=allow_policy)
        assert isinstance(tool, GovernedTool)


# ---------------------------------------------------------------------------
# Tests: govern_tools (bulk)
# ---------------------------------------------------------------------------


class TestGovernTools:
    def test_wraps_multiple_tools(self, allow_policy):
        tools = govern_tools(
            [FakeSearchTool(), FakeDeleteTool()],
            policy=allow_policy,
        )
        assert len(tools) == 2
        assert all(isinstance(t, GovernedTool) for t in tools)

    def test_shares_policy_instance(self, allow_policy):
        tools = govern_tools(
            [FakeSearchTool(), FakeDeleteTool()],
            policy=allow_policy,
        )
        assert tools[0].aegis_policy is tools[1].aegis_policy

    def test_selective_blocking(self, block_delete_policy):
        search, delete = govern_tools(
            [FakeSearchTool(), FakeDeleteTool()],
            policy=block_delete_policy,
        )
        search_result = search.invoke({"query": "test"})
        delete_result = delete.invoke({"record_id": "123"})

        assert "Results for: test" in search_result
        assert "[BLOCKED by Aegis]" in delete_result


# ---------------------------------------------------------------------------
# Tests: async
# ---------------------------------------------------------------------------


class TestAsync:
    @pytest.mark.asyncio
    async def test_allowed_async(self, allow_policy):
        tool = govern_tool(FakeSearchTool(), policy=allow_policy)
        result = await tool.ainvoke({"query": "async test"})
        assert "results for: async test" in result.lower()

    @pytest.mark.asyncio
    async def test_blocked_async(self, block_delete_policy):
        tool = govern_tool(FakeDeleteTool(), policy=block_delete_policy)
        result = await tool.ainvoke({"record_id": "456"})
        assert "[BLOCKED by Aegis]" in result


# ---------------------------------------------------------------------------
# Tests: custom action_target
# ---------------------------------------------------------------------------


class TestActionTarget:
    def test_custom_target(self, allow_policy):
        tool = govern_tool(
            FakeSearchTool(),
            policy=allow_policy,
            action_target="custom_system",
        )
        assert tool.action_target == "custom_system"
