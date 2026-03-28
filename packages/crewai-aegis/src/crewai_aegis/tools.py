"""Governance wrappers for CrewAI tools.

Provides :class:`GovernedCrewAITool`, :func:`govern_tools`, and
:func:`register_aegis_hooks` to add Aegis policy enforcement to
CrewAI tools and crews.  Blocked actions return a governance message
instead of executing the underlying tool.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from aegis import Action, Policy
from aegis.core.policy import Approval, PolicyDecision
from crewai.tools import BaseTool

logger = logging.getLogger("crewai_aegis")


class GovernedCrewAITool(BaseTool):
    """A CrewAI tool wrapped with Aegis governance.

    Every invocation is evaluated against an Aegis :class:`~aegis.Policy`
    before the underlying tool executes.  If the policy blocks the action,
    a human-readable governance message is returned instead.

    Use the convenience helpers :func:`govern_tools` rather than
    constructing this class directly.
    """

    name: str = ""
    description: str = ""
    inner_tool: Any = None
    aegis_policy: Any = None
    action_target: str = "crewai"

    def _run(self, **kwargs: Any) -> Any:
        """Governed synchronous invocation."""
        block_msg = self._check_policy(kwargs)
        if block_msg is not None:
            return block_msg
        return self.inner_tool._run(**kwargs)

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


def govern_tools(
    tools: Sequence[BaseTool],
    policy: Policy | str | Path | dict,
    *,
    action_target: str = "crewai",
) -> list[GovernedCrewAITool]:
    """Wrap multiple CrewAI tools with the same Aegis policy.

    Args:
        tools: Sequence of CrewAI tools to govern.
        policy: An :class:`~aegis.Policy` instance or YAML path.
        action_target: Value used for ``Action.target``.

    Returns:
        List of :class:`GovernedCrewAITool` instances.

    Example::

        from crewai_aegis import govern_tools

        governed = govern_tools(
            [search_tool, calculator_tool, delete_tool],
            policy="policy.yaml",
        )
    """
    policy_obj = _resolve_policy(policy)
    return [
        GovernedCrewAITool(
            inner_tool=t,
            aegis_policy=policy_obj,
            action_target=action_target,
            name=t.name,
            description=t.description,
        )
        for t in tools
    ]


class _AegisPolicyHook:
    """Before-tool-call hook that checks Aegis policy.

    Implements the ``__call__(context) -> bool | None`` protocol
    expected by CrewAI's ``BeforeToolCallHook``.

    Returns ``False`` to block a tool call, or ``None`` to allow.
    """

    def __init__(self, policy: Policy, action_target: str = "crewai") -> None:
        self._policy = policy
        self._action_target = action_target

    def __call__(self, context: Any) -> bool | None:
        tool_name = getattr(context, "tool_name", "")
        tool_input = getattr(context, "tool_input", {})

        if isinstance(tool_input, dict):
            params = tool_input
        elif isinstance(tool_input, str):
            params = {"input": tool_input}
        else:
            params = {"input": str(tool_input)}

        action = Action(type=tool_name, target=self._action_target, params=params)
        decision: PolicyDecision = self._policy.evaluate(action)

        if decision.approval == Approval.BLOCK:
            reason = decision.matched_rule or "Denied by policy"
            logger.warning(
                "[BLOCKED by Aegis] tool=%s reason=%s risk=%s",
                tool_name,
                reason,
                decision.risk_level.name.lower(),
            )
            return False  # Block the tool call

        return None  # Allow


def register_aegis_hooks(
    crew: Any,
    policy: Policy | str | Path | dict,
    *,
    action_target: str = "crewai",
) -> None:
    """Register Aegis governance hooks on a CrewAI Crew.

    Registers a ``BeforeToolCallHook`` that evaluates each tool call
    against the given policy before execution.

    Args:
        crew: A :class:`crewai.Crew` instance.
        policy: An :class:`~aegis.Policy` instance or YAML path.
        action_target: Value used for ``Action.target``.

    Example::

        from crewai import Crew
        from crewai_aegis import register_aegis_hooks

        crew = Crew(agents=[agent], tasks=[task])
        register_aegis_hooks(crew, policy="policy.yaml")
        result = crew.kickoff()
    """
    from crewai.hooks.tool_hooks import register_before_tool_call_hook

    policy_obj = _resolve_policy(policy)
    hook = _AegisPolicyHook(policy=policy_obj, action_target=action_target)
    register_before_tool_call_hook(hook)
    logger.info("Aegis hook registered on Crew (policy=%s)", type(policy_obj).__name__)


def _resolve_policy(policy: Policy | str | Path | dict) -> Policy:
    """Convert a string/Path/dict to a Policy object if needed."""
    if isinstance(policy, dict):
        return Policy.from_dict(policy)
    if isinstance(policy, str | Path):
        return Policy.from_yaml(str(policy))
    return policy
