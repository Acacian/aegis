"""Tests for the LangChain adapter with mocked langchain dependency."""

from __future__ import annotations

import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aegis.core.action import Action
from aegis.core.result import ResultStatus


@pytest.fixture
def mock_langchain():
    """Mock langchain-core so imports succeed."""
    mock_lc_core = MagicMock()
    mock_lc_tools = MagicMock()
    mock_lc_core.tools = mock_lc_tools

    # Create a mock BaseTool class
    class MockBaseTool:
        def __init__(self, name="mock_tool"):
            self.name = name

        async def ainvoke(self, tool_input):
            return f"result for {tool_input}"

    mock_lc_tools.BaseTool = MockBaseTool

    # Create a mock StructuredTool
    mock_structured = MagicMock()
    mock_structured.from_function = MagicMock(side_effect=lambda **kwargs: MagicMock(**kwargs))
    mock_lc_tools.StructuredTool = mock_structured

    with patch.dict(
        "sys.modules",
        {
            "langchain_core": mock_lc_core,
            "langchain_core.tools": mock_lc_tools,
        },
    ):
        yield MockBaseTool, mock_structured


class TestLangChainExecutor:
    """Tests for LangChainExecutor."""

    def test_init_with_tools(self, mock_langchain):
        """Should register tools by name."""
        MockBaseTool, _ = mock_langchain
        from aegis.adapters.langchain import LangChainExecutor

        tool1 = MockBaseTool(name="search")
        tool2 = MockBaseTool(name="calculator")

        executor = LangChainExecutor(tools=[tool1, tool2])

        assert executor.tool_names == ["search", "calculator"]

    def test_init_empty(self, mock_langchain):
        """Should initialize with no tools."""
        from aegis.adapters.langchain import LangChainExecutor

        executor = LangChainExecutor(tools=[])
        assert executor.tool_names == []

    def test_init_none(self, mock_langchain):
        """Should initialize with None tools list."""
        from aegis.adapters.langchain import LangChainExecutor

        executor = LangChainExecutor(tools=None)
        assert executor.tool_names == []

    def test_register_tool(self, mock_langchain):
        """register_tool should add a tool."""
        MockBaseTool, _ = mock_langchain
        from aegis.adapters.langchain import LangChainExecutor

        executor = LangChainExecutor(tools=[])
        tool = MockBaseTool(name="new_tool")
        executor.register_tool(tool)

        assert "new_tool" in executor.tool_names

    @pytest.mark.asyncio
    async def test_execute_success(self, mock_langchain):
        """Should execute a matching tool successfully."""
        MockBaseTool, _ = mock_langchain
        from aegis.adapters.langchain import LangChainExecutor

        tool = MockBaseTool(name="search")
        tool.ainvoke = AsyncMock(return_value="search result")

        executor = LangChainExecutor(tools=[tool])
        action = Action("search", "web", params={"query": "test"})
        result = await executor.execute(action)

        assert result.status == ResultStatus.SUCCESS
        assert result.data == "search result"
        tool.ainvoke.assert_called_once_with({"query": "test"})

    @pytest.mark.asyncio
    async def test_execute_with_description_fallback(self, mock_langchain):
        """Should use action description when params is empty."""
        MockBaseTool, _ = mock_langchain
        from aegis.adapters.langchain import LangChainExecutor

        tool = MockBaseTool(name="search")
        tool.ainvoke = AsyncMock(return_value="result")

        executor = LangChainExecutor(tools=[tool])
        action = Action("search", "web", params={}, description="find stuff")
        result = await executor.execute(action)

        assert result.status == ResultStatus.SUCCESS
        tool.ainvoke.assert_called_once_with("find stuff")

    @pytest.mark.asyncio
    async def test_execute_unknown_tool(self, mock_langchain):
        """Should return FAILED for unregistered tools."""
        from aegis.adapters.langchain import LangChainExecutor

        executor = LangChainExecutor(tools=[])
        action = Action("unknown_tool", "test")
        result = await executor.execute(action)

        assert result.status == ResultStatus.FAILED
        assert "No LangChain tool registered" in result.error
        assert "unknown_tool" in result.error

    @pytest.mark.asyncio
    async def test_execute_tool_raises(self, mock_langchain):
        """Should catch exceptions from tool execution."""
        MockBaseTool, _ = mock_langchain
        from aegis.adapters.langchain import LangChainExecutor

        tool = MockBaseTool(name="broken")
        tool.ainvoke = AsyncMock(side_effect=RuntimeError("Tool crashed"))

        executor = LangChainExecutor(tools=[tool])
        action = Action("broken", "test", params={"key": "value"})
        result = await executor.execute(action)

        assert result.status == ResultStatus.FAILED
        assert "Tool crashed" in result.error


class TestAegisTool:
    """Tests for AegisTool.from_runtime (LangChain tool wrapper)."""

    def test_from_runtime(self, mock_langchain):
        """from_runtime should create a StructuredTool."""
        _, mock_structured = mock_langchain
        from aegis.adapters.langchain import AegisTool

        runtime = MagicMock()

        AegisTool.from_runtime(
            runtime=runtime,
            name="governed_search",
            description="Search with governance",
            action_type="search",
            action_target="web",
        )

        mock_structured.from_function.assert_called_once()
        call_kwargs = mock_structured.from_function.call_args[1]
        assert call_kwargs["name"] == "governed_search"
        assert call_kwargs["description"] == "Search with governance"
        assert call_kwargs["coroutine"] is not None


def test_langchain_import_guard_message():
    """_require_langchain should raise ImportError with helpful message."""
    original = sys.modules.pop("langchain_core", None)
    sys.modules["langchain_core"] = None  # type: ignore[assignment]
    try:
        from aegis.adapters.langchain import _require_langchain

        with pytest.raises(ImportError, match="langchain-core"):
            _require_langchain()
    finally:
        if original:
            sys.modules["langchain_core"] = original
        else:
            sys.modules.pop("langchain_core", None)
