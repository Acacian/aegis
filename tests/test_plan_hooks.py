"""Tests for plan-level hooks in the instrumentation layer."""

from __future__ import annotations

from unittest.mock import MagicMock

from aegis.core.policy import Policy
from aegis.instrument._state import InstrumentationState


class TestInstrumentationStatePolicy:
    def setup_method(self) -> None:
        InstrumentationState.reset()

    def teardown_method(self) -> None:
        InstrumentationState.reset()

    def test_policy_default_none(self) -> None:
        s = InstrumentationState.get()
        assert s.policy is None

    def test_configure_with_policy(self) -> None:
        policy = Policy.from_dict(
            {
                "rules": [],
                "plan_rules": {
                    "sequence_patterns": [
                        {"name": "test", "steps": ["read_*", "send_*"]},
                    ],
                },
            }
        )
        s = InstrumentationState.get()
        s.configure(policy=policy)
        assert s.policy is not None
        assert s.policy.plan_rules is not None

    def test_configure_without_policy(self) -> None:
        s = InstrumentationState.get()
        s.configure(guardrail_engine=MagicMock())
        assert s.policy is None


class TestCrewAIPlanExtraction:
    def test_extract_crew_plan(self) -> None:
        from aegis.instrument._crewai import _extract_crew_plan

        # Create mock tasks
        task1 = MagicMock()
        task1.name = "read_data"
        task1.description = "Read customer data"
        task1.tools = []

        task2 = MagicMock()
        task2.name = "send_report"
        task2.description = "Send the report"
        task2.tools = []

        actions = _extract_crew_plan([task1, task2])
        assert len(actions) == 2
        assert actions[0].type == "read_data"
        assert actions[0].target == "crewai"
        assert actions[1].type == "send_report"

    def test_extract_crew_plan_fallback_name(self) -> None:
        from aegis.instrument._crewai import _extract_crew_plan

        task = MagicMock(spec=[])  # No attributes
        task.name = ""
        task.description = "Do something"
        task.tools = None

        actions = _extract_crew_plan([task])
        assert len(actions) == 1
        assert actions[0].type == "crew_task"  # fallback


class TestOpenAIAgentsPlanExtraction:
    def test_extract_agent_plan(self) -> None:
        from aegis.instrument._openai_agents import _extract_agent_plan

        agent = MagicMock()
        tool1 = MagicMock()
        tool1.name = "read_file"
        tool2 = MagicMock()
        tool2.name = "send_email"
        agent.tools = [tool1, tool2]

        actions = _extract_agent_plan(agent, "analyze this data")
        assert len(actions) == 3  # 2 tools + 1 input
        assert actions[0].type == "read_file"
        assert actions[1].type == "send_email"
        assert actions[2].type == "agent_input"

    def test_extract_agent_plan_no_tools(self) -> None:
        from aegis.instrument._openai_agents import _extract_agent_plan

        agent = MagicMock()
        agent.tools = []

        actions = _extract_agent_plan(agent, "hello")
        assert len(actions) == 1
        assert actions[0].type == "agent_input"

    def test_extract_agent_plan_no_input(self) -> None:
        from aegis.instrument._openai_agents import _extract_agent_plan

        agent = MagicMock()
        tool = MagicMock()
        tool.name = "search"
        agent.tools = [tool]

        actions = _extract_agent_plan(agent, "")
        assert len(actions) == 1
        assert actions[0].type == "search"
