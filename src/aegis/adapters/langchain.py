"""LangChain integration: wrap any LangChain tool with Aegis governance.

This adapter lets you run LangChain tools through the Aegis policy engine,
adding risk assessment, approval gates, and audit logging to every tool call.

Requires: ``pip install agent-aegis[langchain]``

Example::

    from langchain_community.tools import DuckDuckGoSearchRun
    from aegis import Policy, Runtime
    from aegis.adapters.langchain import LangChainExecutor

    executor = LangChainExecutor(tools=[DuckDuckGoSearchRun()])
    runtime = Runtime(executor=executor, policy=Policy.from_yaml("policy.yaml"))

    plan = runtime.plan([
        Action("DuckDuckGoSearchRun", target="web", params={"query": "AI governance"}),
    ])
    results = await runtime.execute(plan)
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from aegis.adapters.base import BaseExecutor
from aegis.core.action import Action
from aegis.core.result import Result, ResultStatus

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool


def _require_langchain() -> None:
    try:
        import langchain_core  # noqa: F401
    except ImportError:
        raise ImportError(
            "langchain-core is required for LangChainExecutor. "
            "Install it with: pip install 'agent-aegis[langchain]'"
        ) from None


class LangChainExecutor(BaseExecutor):
    """Executes LangChain tools through the Aegis governance pipeline.

    Maps Aegis ``Action.type`` to LangChain tool names. When an action's type
    matches a registered tool name, that tool is invoked with ``Action.params``
    as the tool input.

    Args:
        tools: List of LangChain BaseTool instances to make available.
    """

    def __init__(self, tools: list[BaseTool] | None = None) -> None:
        _require_langchain()
        self._tools: dict[str, BaseTool] = {}
        for tool in tools or []:
            self._tools[tool.name] = tool

    def register_tool(self, tool: BaseTool) -> None:
        """Register an additional LangChain tool."""
        self._tools[tool.name] = tool

    @property
    def tool_names(self) -> list[str]:
        """Return the names of all registered tools."""
        return list(self._tools.keys())

    async def execute(self, action: Action) -> Result:
        """Execute a LangChain tool call.

        The ``action.type`` is matched against registered tool names.
        ``action.params`` is passed as the tool input.
        """
        tool = self._tools.get(action.type)
        if not tool:
            return Result(
                action=action,
                status=ResultStatus.FAILED,
                error=(
                    f"No LangChain tool registered with name '{action.type}'. "
                    f"Available: {self.tool_names}"
                ),
                completed_at=datetime.now(UTC),
            )

        try:
            # Use ainvoke for async execution
            tool_input = action.params if action.params else action.description
            output = await tool.ainvoke(tool_input)
            return Result(
                action=action,
                status=ResultStatus.SUCCESS,
                data=output,
                completed_at=datetime.now(UTC),
            )
        except Exception as e:
            return Result(
                action=action,
                status=ResultStatus.FAILED,
                error=str(e),
                completed_at=datetime.now(UTC),
            )


class AegisTool:
    """Wraps an Aegis Runtime as a LangChain-compatible tool.

    This lets LangChain agents use Aegis-governed actions as if they were
    regular LangChain tools, with policy checks and approval gates applied
    transparently.

    Example::

        from aegis import Action, Policy, Runtime
        from aegis.adapters.langchain import AegisTool

        runtime = Runtime(executor=my_executor, policy=my_policy)
        tool = AegisTool.from_runtime(
            runtime=runtime,
            name="governed_search",
            description="Search with governance",
            action_type="search",
            action_target="web",
        )
        # Use `tool` in a LangChain agent
    """

    @staticmethod
    def from_runtime(
        *,
        runtime: Any,
        name: str,
        description: str,
        action_type: str,
        action_target: str = "default",
    ) -> BaseTool:
        """Create a LangChain BaseTool that routes through Aegis.

        Args:
            runtime: An Aegis Runtime instance.
            name: Tool name visible to the LangChain agent.
            description: Tool description for the agent.
            action_type: The Aegis action type to use.
            action_target: The Aegis action target to use.

        Returns:
            A LangChain BaseTool instance.
        """
        _require_langchain()
        from langchain_core.tools import StructuredTool

        async def _run_governed(**kwargs: Any) -> str:
            action = Action(
                type=action_type,
                target=action_target,
                params=kwargs,
                description=description,
            )
            plan = runtime.plan([action])
            results = await runtime.execute(plan)
            result = results[0]
            if result.ok:
                return str(result.data)
            return f"[AEGIS {result.status.value.upper()}] {result.error}"

        return StructuredTool.from_function(
            coroutine=_run_governed,
            name=name,
            description=description,
        )
