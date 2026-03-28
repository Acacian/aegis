"""Aegis governance integration for CrewAI.

Add policy enforcement to any CrewAI tool with one function call::

    from crewai_aegis import govern_tools

    governed = govern_tools(tools, policy="policy.yaml")
    crew = Crew(agents=[agent], tasks=[task])

Or register a hook on the Crew itself::

    from crewai_aegis import register_aegis_hooks

    register_aegis_hooks(crew, policy="policy.yaml")
"""

from crewai_aegis.tools import GovernedCrewAITool, govern_tools, register_aegis_hooks

__all__ = ["GovernedCrewAITool", "govern_tools", "register_aegis_hooks"]
__version__ = "0.1.0"
