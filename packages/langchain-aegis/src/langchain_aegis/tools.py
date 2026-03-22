"""Governance wrappers for LangChain tools.

Provides :func:`govern_tool` and :func:`govern_tools` to add Aegis
policy enforcement to any LangChain tool.  Blocked actions return a
governance message instead of executing the underlying tool.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from aegis import Action, Policy
from aegis.core.policy import Approval, PolicyDecision
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import BaseTool
from pydantic import ConfigDict, Field


class GovernedTool(BaseTool):
    """A LangChain tool wrapped with Aegis governance.

    Every invocation is evaluated against an Aegis :class:`~aegis.Policy`
    before the underlying tool executes.  If the policy blocks the action,
    a human-readable governance message is returned instead.

    Use the convenience helpers :func:`govern_tool` / :func:`govern_tools`
    rather than constructing this class directly.
    """

    inner_tool: Any = Field(exclude=True)
    aegis_policy: Any = Field(exclude=True)
    action_target: str = "langchain"

    model_config = ConfigDict(arbitrary_types_allowed=True)

    # ---- LangChain interface: intercept at invoke level ------------------

    @property
    def args(self) -> dict:  # type: ignore[override]
        """Forward the inner tool's argument schema."""
        return self.inner_tool.args  # type: ignore[no-any-return]

    def get_input_schema(self, config: Any = None) -> Any:
        """Forward the inner tool's input schema for agent compatibility."""
        return self.inner_tool.get_input_schema(config)

    def invoke(
        self,
        input: Any,  # noqa: A002
        config: RunnableConfig | None = None,
        **kwargs: Any,
    ) -> Any:
        """Governed synchronous invocation."""
        block_msg = self._check_policy(input)
        if block_msg is not None:
            return block_msg
        return self.inner_tool.invoke(input, config=config, **kwargs)

    async def ainvoke(
        self,
        input: Any,  # noqa: A002
        config: RunnableConfig | None = None,
        **kwargs: Any,
    ) -> Any:
        """Governed asynchronous invocation."""
        block_msg = self._check_policy(input)
        if block_msg is not None:
            return block_msg
        return await self.inner_tool.ainvoke(input, config=config, **kwargs)

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """Fallback — delegates to inner tool."""
        return self.inner_tool._run(*args, **kwargs)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        """Fallback — delegates to inner tool."""
        return await self.inner_tool._arun(*args, **kwargs)

    # ---- internal --------------------------------------------------------

    def _check_policy(self, tool_input: Any) -> str | None:
        """Evaluate the action against the Aegis policy.

        Returns a block message string if the action is denied,
        or ``None`` if execution should proceed.
        """
        if isinstance(tool_input, dict):
            params = tool_input
        elif isinstance(tool_input, str):
            params = {"input": tool_input}
        else:
            params = {"input": str(tool_input)}

        action = Action(type=self.name, target=self.action_target, params=params)
        decision: PolicyDecision = self.aegis_policy.evaluate(action)

        if decision.approval == Approval.BLOCK:
            reason = decision.matched_rule or "Denied by policy"
            return f"[BLOCKED by Aegis] {reason} (risk: {decision.risk_level.name.lower()})"
        return None


# --------------------------------------------------------------------------
# Public helpers
# --------------------------------------------------------------------------


def govern_tool(
    tool: BaseTool,
    policy: Policy | str | Path | dict,
    *,
    action_target: str = "langchain",
) -> GovernedTool:
    """Wrap a LangChain tool with Aegis governance.

    Args:
        tool: Any LangChain :class:`~langchain_core.tools.BaseTool`.
        policy: An :class:`~aegis.Policy` instance **or** a path to a
            YAML policy file.
        action_target: Value used for ``Action.target`` when evaluating.
            Defaults to ``"langchain"``.

    Returns:
        A :class:`GovernedTool` that enforces the policy on every call.

    Example::

        from langchain_community.tools import DuckDuckGoSearchRun
        from langchain_aegis import govern_tool

        search = govern_tool(DuckDuckGoSearchRun(), policy="policy.yaml")
        result = search.invoke({"query": "AI governance"})
    """
    policy_obj = _resolve_policy(policy)
    return GovernedTool(
        inner_tool=tool,
        aegis_policy=policy_obj,
        action_target=action_target,
        name=tool.name,
        description=tool.description,
    )


def govern_tools(
    tools: Sequence[BaseTool],
    policy: Policy | str | Path | dict,
    *,
    action_target: str = "langchain",
) -> list[GovernedTool]:
    """Wrap multiple LangChain tools with the same Aegis policy.

    Args:
        tools: Sequence of LangChain tools to govern.
        policy: An :class:`~aegis.Policy` instance or YAML path.
        action_target: Value used for ``Action.target``.

    Returns:
        List of :class:`GovernedTool` instances.

    Example::

        from langchain_aegis import govern_tools

        governed = govern_tools(
            [search_tool, calculator_tool, delete_tool],
            policy="policy.yaml",
        )
        agent = create_react_agent(model, governed)
    """
    policy_obj = _resolve_policy(policy)
    return [
        GovernedTool(
            inner_tool=t,
            aegis_policy=policy_obj,
            action_target=action_target,
            name=t.name,
            description=t.description,
        )
        for t in tools
    ]


def _resolve_policy(policy: Policy | str | Path | dict) -> Policy:
    """Convert a string/Path/dict to a Policy object if needed."""
    if isinstance(policy, dict):
        return Policy.from_dict(policy)
    if isinstance(policy, (str, Path)):
        return Policy.from_yaml(str(policy))
    return policy
