"""Aegis governance integration for LangChain.

Add policy enforcement to any LangChain tool with one function call::

    from langchain_aegis import govern_tools

    governed = govern_tools(tools, policy="policy.yaml")
    agent = create_react_agent(model, governed)
"""

from langchain_aegis.tools import GovernedTool, govern_tool, govern_tools

__all__ = ["GovernedTool", "govern_tool", "govern_tools"]
__version__ = "0.1.1"
