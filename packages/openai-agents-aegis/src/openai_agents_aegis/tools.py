"""Governance wrappers for OpenAI Agents SDK tools.

Provides :func:`governed_tool`, :class:`GovernedFunctionTool`, and
:func:`govern_tools` to add Aegis policy enforcement to any OpenAI Agents
SDK tool.  Blocked actions return a governance message instead of executing
the underlying tool.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from aegis import Action, Policy
from aegis.core.policy import Approval, PolicyDecision

# ---------------------------------------------------------------------------
# GovernedFunctionTool — wraps an existing FunctionTool instance
# ---------------------------------------------------------------------------


class GovernedFunctionTool:
    """An OpenAI Agents SDK tool wrapped with Aegis governance.

    Every invocation is evaluated against an Aegis :class:`~aegis.Policy`
    before the underlying tool executes.  If the policy blocks the action,
    a human-readable governance message is returned instead.

    Use the convenience helpers :func:`governed_tool` / :func:`govern_tools`
    rather than constructing this class directly.
    """

    def __init__(
        self,
        inner_tool: Any,
        policy: Policy,
        *,
        action_target: str = "openai_agents",
    ) -> None:
        self._inner = inner_tool
        self._policy = policy
        self._action_target = action_target

        # Expose attributes the SDK expects on a tool object
        self.name: str = getattr(inner_tool, "name", "")
        self.description: str = getattr(inner_tool, "description", "")

    @property
    def inner_tool(self) -> Any:
        """The original unwrapped tool."""
        return self._inner

    @property
    def aegis_policy(self) -> Policy:
        """The Aegis policy used for governance."""
        return self._policy

    @property
    def action_target(self) -> str:
        """The action target used in policy evaluation."""
        return self._action_target

    @property
    def params_json_schema(self) -> dict[str, Any]:
        """Forward the inner tool's JSON schema for the SDK."""
        return getattr(self._inner, "params_json_schema", {})  # type: ignore[no-any-return]

    def _check_policy(self, tool_input: dict[str, Any]) -> str | None:
        """Evaluate the action against the Aegis policy.

        Returns a block message string if the action is denied,
        or ``None`` if execution should proceed.
        """
        action = Action(type=self.name, target=self._action_target, params=tool_input)
        decision: PolicyDecision = self._policy.evaluate(action)

        if decision.approval == Approval.BLOCK:
            reason = decision.matched_rule or "Denied by policy"
            return f"[BLOCKED by Aegis] {reason} (risk: {decision.risk_level.name.lower()})"
        return None

    async def on_invoke_tool(self, ctx: Any, input_str: str) -> str:
        """Governed tool invocation — matches the FunctionTool protocol.

        The OpenAI Agents SDK calls ``tool.on_invoke_tool(ctx, input_str)``
        for each tool execution.
        """
        import json

        try:
            params = json.loads(input_str) if input_str else {}
        except (json.JSONDecodeError, TypeError):
            params = {"input": input_str}

        if not isinstance(params, dict):
            params = {"input": str(params)}

        block_msg = self._check_policy(params)
        if block_msg is not None:
            return block_msg

        return await self._inner.on_invoke_tool(ctx, input_str)

    def __repr__(self) -> str:
        return f"GovernedFunctionTool(name={self.name!r}, target={self._action_target!r})"


# ---------------------------------------------------------------------------
# governed_tool decorator
# ---------------------------------------------------------------------------


def governed_tool(
    fn: Callable[..., Any] | None = None,
    *,
    policy: Policy | str | Path | dict[str, Any],
    action_target: str = "openai_agents",
) -> Any:
    """Decorator that wraps a function with Aegis governance.

    Can be used with or without parentheses::

        @governed_tool(policy="policy.yaml")
        async def web_search(query: str) -> str:
            ...

    The decorated function preserves its original metadata (name, docstring,
    signature) so the OpenAI Agents SDK ``@function_tool`` decorator can be
    applied on top::

        from agents import function_tool
        from openai_agents_aegis import governed_tool

        @function_tool
        @governed_tool(policy="policy.yaml")
        async def search(query: str) -> str:
            ...

    Args:
        fn: The function to wrap (supplied automatically when used without
            parentheses).
        policy: An :class:`~aegis.Policy` instance **or** a path to a
            YAML policy file, or a policy dict.
        action_target: Value used for ``Action.target`` when evaluating.
            Defaults to ``"openai_agents"``.

    Returns:
        A wrapped function that checks Aegis policy before execution.
    """
    policy_obj = _resolve_policy(policy)

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> str:
            sig = inspect.signature(func)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            params = dict(bound.arguments)

            action = Action(
                type=func.__name__,
                target=action_target,
                params=params,
                description=func.__doc__ or func.__name__,
            )
            decision: PolicyDecision = policy_obj.evaluate(action)

            if decision.approval == Approval.BLOCK:
                reason = decision.matched_rule or "Denied by policy"
                return f"[BLOCKED by Aegis] {reason} (risk: {decision.risk_level.name.lower()})"

            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            return str(result)

        return wrapper

    if fn is not None:
        return decorator(fn)
    return decorator


# ---------------------------------------------------------------------------
# govern_tools — batch wrapper
# ---------------------------------------------------------------------------


def govern_tools(
    tools: Sequence[Any],
    policy: Policy | str | Path | dict[str, Any],
    *,
    action_target: str = "openai_agents",
) -> list[GovernedFunctionTool]:
    """Wrap multiple OpenAI Agents SDK tools with the same Aegis policy.

    Args:
        tools: Sequence of OpenAI Agents SDK ``FunctionTool`` instances.
        policy: An :class:`~aegis.Policy` instance or YAML path or dict.
        action_target: Value used for ``Action.target``.

    Returns:
        List of :class:`GovernedFunctionTool` instances.

    Example::

        from openai_agents_aegis import govern_tools

        governed = govern_tools(
            [search_tool, calculator_tool, delete_tool],
            policy="policy.yaml",
        )
        agent = Agent(name="assistant", tools=governed)
    """
    policy_obj = _resolve_policy(policy)
    return [GovernedFunctionTool(t, policy_obj, action_target=action_target) for t in tools]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_policy(policy: Policy | str | Path | dict[str, Any]) -> Policy:
    """Convert a string/Path/dict to a Policy object if needed."""
    if isinstance(policy, dict):
        return Policy.from_dict(policy)
    if isinstance(policy, str | Path):
        return Policy.from_yaml(str(policy))
    return policy
