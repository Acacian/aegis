"""Tests for crewai-aegis governance wrappers."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from aegis import Policy

from crewai_aegis import GovernedCrewAITool, govern_tools, register_aegis_hooks

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


class FakeCrewAITool:
    """Minimal mock of a CrewAI BaseTool for testing without crewai installed."""

    def __init__(self, name: str = "web_search", description: str = "Search the web") -> None:
        self.name = name
        self.description = description

    def _run(self, **kwargs: Any) -> str:
        return f"Result: {kwargs}"


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
# Tests: GovernedCrewAITool
# ---------------------------------------------------------------------------


class TestGovernedCrewAITool:
    def test_allowed_action_passes_through(self, allow_policy):
        inner = FakeCrewAITool(name="web_search")
        tool = GovernedCrewAITool(
            inner_tool=inner,
            aegis_policy=allow_policy,
            name="web_search",
            description="Search the web",
        )
        result = tool._run(query="AI governance")
        assert "AI governance" in str(result)

    def test_blocked_action_returns_message(self, block_delete_policy):
        inner = FakeCrewAITool(name="delete_records", description="Delete records")
        tool = GovernedCrewAITool(
            inner_tool=inner,
            aegis_policy=block_delete_policy,
            name="delete_records",
            description="Delete records",
        )
        result = tool._run(record_id="123")
        assert "[BLOCKED by Aegis]" in result
        assert "critical" in result

    def test_preserves_tool_name(self, allow_policy):
        inner = FakeCrewAITool(name="web_search")
        tool = GovernedCrewAITool(
            inner_tool=inner,
            aegis_policy=allow_policy,
            name="web_search",
            description="Search the web",
        )
        assert tool.name == "web_search"

    def test_preserves_tool_description(self, allow_policy):
        inner = FakeCrewAITool(name="web_search", description="Search the web")
        tool = GovernedCrewAITool(
            inner_tool=inner,
            aegis_policy=allow_policy,
            name="web_search",
            description="Search the web",
        )
        assert tool.description == "Search the web"

    def test_string_input_handled(self, allow_policy):
        inner = FakeCrewAITool(name="web_search")
        tool = GovernedCrewAITool(
            inner_tool=inner,
            aegis_policy=allow_policy,
            name="web_search",
            description="Search the web",
        )
        # _check_policy handles string input by wrapping it
        result = tool._check_policy("raw string input")
        assert result is None  # allowed

    def test_policy_from_yaml_path(self, tmp_path):
        p = tmp_path / "policy.yaml"
        p.write_text(ALLOW_ALL_YAML)
        policy = Policy.from_yaml(str(p))
        inner = FakeCrewAITool(name="web_search")
        tool = GovernedCrewAITool(
            inner_tool=inner,
            aegis_policy=policy,
            name="web_search",
            description="Search the web",
        )
        result = tool._run(query="test")
        assert "test" in str(result)


# ---------------------------------------------------------------------------
# Tests: govern_tools (bulk)
# ---------------------------------------------------------------------------


class TestGovernTools:
    @patch("crewai_aegis.tools.BaseTool", FakeCrewAITool)
    def test_wraps_multiple_tools(self, allow_policy):
        tools = govern_tools(
            [FakeCrewAITool(), FakeCrewAITool(name="calculator", description="Calculate")],
            policy=allow_policy,
        )
        assert len(tools) == 2
        assert all(isinstance(t, GovernedCrewAITool) for t in tools)

    @patch("crewai_aegis.tools.BaseTool", FakeCrewAITool)
    def test_shares_policy_instance(self, allow_policy):
        tools = govern_tools(
            [FakeCrewAITool(), FakeCrewAITool(name="calculator", description="Calculate")],
            policy=allow_policy,
        )
        assert tools[0].aegis_policy is tools[1].aegis_policy

    @patch("crewai_aegis.tools.BaseTool", FakeCrewAITool)
    def test_selective_blocking(self, block_delete_policy):
        search, delete = govern_tools(
            [
                FakeCrewAITool(name="web_search", description="Search"),
                FakeCrewAITool(name="delete_records", description="Delete"),
            ],
            policy=block_delete_policy,
        )
        search_result = search._run(query="test")
        delete_result = delete._run(record_id="123")

        assert "test" in str(search_result)
        assert "[BLOCKED by Aegis]" in delete_result


# ---------------------------------------------------------------------------
# Tests: register_aegis_hooks
# ---------------------------------------------------------------------------


class TestRegisterAegisHooks:
    @patch("crewai_aegis.tools.register_before_tool_call_hook")
    def test_registers_hook(self, mock_register, allow_policy):
        crew = MagicMock()
        register_aegis_hooks(crew, policy=allow_policy)
        mock_register.assert_called_once()

    @patch("crewai_aegis.tools.register_before_tool_call_hook")
    def test_hook_allows_safe_tool(self, mock_register, allow_policy):
        crew = MagicMock()
        register_aegis_hooks(crew, policy=allow_policy)

        # Extract the hook that was registered
        hook = mock_register.call_args[0][0]

        # Create a mock context
        context = MagicMock()
        context.tool_name = "web_search"
        context.tool_input = {"query": "test"}

        result = hook(context)
        assert result is None  # None means allow

    @patch("crewai_aegis.tools.register_before_tool_call_hook")
    def test_hook_blocks_denied_tool(self, mock_register, block_delete_policy):
        crew = MagicMock()
        register_aegis_hooks(crew, policy=block_delete_policy)

        hook = mock_register.call_args[0][0]

        context = MagicMock()
        context.tool_name = "delete_records"
        context.tool_input = {"record_id": "123"}

        result = hook(context)
        assert result is False  # False means block

    @patch("crewai_aegis.tools.register_before_tool_call_hook")
    def test_hook_with_string_input(self, mock_register, allow_policy):
        crew = MagicMock()
        register_aegis_hooks(crew, policy=allow_policy)

        hook = mock_register.call_args[0][0]

        context = MagicMock()
        context.tool_name = "web_search"
        context.tool_input = "raw string query"

        result = hook(context)
        assert result is None  # allowed

    @patch("crewai_aegis.tools.register_before_tool_call_hook")
    def test_policy_from_dict(self, mock_register):
        crew = MagicMock()
        policy_dict = {
            "version": "1",
            "defaults": {"risk_level": "low", "approval": "auto"},
            "rules": [],
        }
        register_aegis_hooks(crew, policy=policy_dict)
        mock_register.assert_called_once()

    @patch("crewai_aegis.tools.register_before_tool_call_hook")
    def test_policy_from_yaml_path(self, mock_register, tmp_path):
        crew = MagicMock()
        p = tmp_path / "policy.yaml"
        p.write_text(ALLOW_ALL_YAML)
        register_aegis_hooks(crew, policy=str(p))
        mock_register.assert_called_once()


# ---------------------------------------------------------------------------
# Tests: custom action_target
# ---------------------------------------------------------------------------


class TestActionTarget:
    def test_custom_target_on_tool(self, allow_policy):
        inner = FakeCrewAITool(name="web_search")
        tool = GovernedCrewAITool(
            inner_tool=inner,
            aegis_policy=allow_policy,
            action_target="custom_system",
            name="web_search",
            description="Search the web",
        )
        assert tool.action_target == "custom_system"

    @patch("crewai_aegis.tools.register_before_tool_call_hook")
    def test_custom_target_on_hook(self, mock_register, allow_policy):
        crew = MagicMock()
        register_aegis_hooks(crew, policy=allow_policy, action_target="custom_system")

        hook = mock_register.call_args[0][0]
        assert hook._action_target == "custom_system"
