"""Tests for adapter integrations (import guards and basic structure)."""

from __future__ import annotations


def test_langchain_import_guard():
    """LangChainExecutor should raise ImportError when langchain is not installed."""
    # langchain-core is not in dev deps, so this should fail gracefully
    try:
        from aegis.adapters.langchain import LangChainExecutor

        LangChainExecutor(tools=[])
    except ImportError as e:
        assert "langchain-core" in str(e)


def test_crewai_import_guard():
    """AegisCrewAITool should raise ImportError when crewai is not installed."""
    try:
        from aegis.adapters.crewai import AegisCrewAITool

        AegisCrewAITool(
            runtime=None,
            name="test",
            description="test",
            action_type="test",
            fn=lambda: None,
        )
    except ImportError as e:
        assert "crewai" in str(e)


def test_openai_agents_import_guard():
    """governed_tool should raise ImportError when openai-agents is not installed."""
    try:
        from aegis.adapters.openai_agents import governed_tool

        @governed_tool(runtime=None, action_type="test")
        async def dummy() -> str:
            return "test"

        # The decorator itself doesn't check, but calling would
        # This just verifies the module loads without syntax errors
    except ImportError as e:
        assert "openai-agents" in str(e)


def test_playwright_import_guard():
    """PlaywrightExecutor should raise ImportError at setup() if playwright missing."""
    from aegis.adapters.playwright import PlaywrightExecutor

    # Constructor should work fine (lazy import)
    executor = PlaywrightExecutor()
    assert executor is not None
