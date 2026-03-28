"""Aegis governance integration for OpenAI Agents SDK.

Add policy enforcement to any OpenAI Agents SDK tool with one function call::

    from openai_agents_aegis import govern_tools

    governed = govern_tools(tools, policy="policy.yaml")
    agent = Agent(name="my_agent", tools=governed)
"""

from openai_agents_aegis.tools import GovernedFunctionTool, govern_tools, governed_tool

__all__ = ["GovernedFunctionTool", "governed_tool", "govern_tools"]
__version__ = "0.1.0"
