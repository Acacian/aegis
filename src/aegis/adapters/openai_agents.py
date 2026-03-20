"""OpenAI Agents SDK integration: govern agent tool calls with Aegis.

Wraps Aegis governance around OpenAI Agents SDK function tools,
adding policy checks, approval gates, and audit logging.

Requires: ``pip install agent-aegis[openai-agents]``

Example::

    from agents import Agent, Runner
    from aegis import Action, Policy, Runtime
    from aegis.adapters.openai_agents import governed_tool

    runtime = Runtime(
        executor=my_executor,
        policy=Policy.from_yaml("policy.yaml"),
    )

    @governed_tool(runtime=runtime, action_type="search", action_target="web")
    async def web_search(query: str) -> str:
        \"\"\"Search the web.\"\"\"
        return await do_actual_search(query)

    agent = Agent(name="researcher", tools=[web_search])
    result = await Runner.run(agent, "Find info about AI governance")
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from collections.abc import Callable
from typing import Any

from aegis.core.action import Action


def _require_openai_agents() -> None:
    try:
        import agents  # noqa: F401
    except ImportError:
        raise ImportError(
            "openai-agents is required for OpenAI Agents SDK integration. "
            "Install it with: pip install 'agent-aegis[openai-agents]'"
        ) from None


def governed_tool(
    *,
    runtime: Any,
    action_type: str,
    action_target: str = "default",
    description: str | None = None,
) -> Callable[..., Any]:
    """Decorator that wraps a function tool with Aegis governance.

    The decorated function becomes an OpenAI Agents SDK-compatible tool
    that goes through Aegis policy checks before execution.

    Args:
        runtime: An Aegis Runtime instance.
        action_type: The Aegis action type for policy evaluation.
        action_target: The Aegis action target for policy evaluation.
        description: Override the function's docstring for the action description.

    Returns:
        A decorator that wraps the function with governance.

    Example::

        @governed_tool(runtime=runtime, action_type="write", action_target="crm")
        async def update_contact(name: str, email: str) -> str:
            \"\"\"Update a contact in the CRM.\"\"\"
            ...
    """

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        fn_desc = description or fn.__doc__ or fn.__name__

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> str:
            # Build an Action from the function call
            # Combine positional and keyword args into params
            sig = inspect.signature(fn)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            params = dict(bound.arguments)

            action = Action(
                type=action_type,
                target=action_target,
                params=params,
                description=fn_desc,
            )

            plan = runtime.plan([action])
            decision = plan.decisions[0]

            # Check policy without full execute cycle for blocked actions
            if not decision.is_allowed:
                return f"[AEGIS BLOCKED] Action blocked by policy rule: {decision.matched_rule}"

            # For approved actions, request approval
            from aegis.core.policy import Approval

            if decision.approval == Approval.APPROVE:
                approved = await runtime.approval.request_approval(decision)
                if not approved:
                    return "[AEGIS DENIED] Action denied by human operator"

            # Execute the actual function
            try:
                if asyncio.iscoroutinefunction(fn):
                    result = await fn(*args, **kwargs)
                else:
                    result = fn(*args, **kwargs)

                # Log success to audit
                from aegis.core.result import Result, ResultStatus

                audit_result = Result(action=action, status=ResultStatus.SUCCESS, data=result)
                runtime.audit.log(
                    runtime.session_id,
                    decision,
                    result=audit_result,
                    human_decision="approved" if decision.approval == Approval.APPROVE else None,
                )

                return str(result)
            except Exception as e:
                from aegis.core.result import Result, ResultStatus

                audit_result = Result(action=action, status=ResultStatus.FAILED, error=str(e))
                runtime.audit.log(runtime.session_id, decision, result=audit_result)
                return f"[AEGIS ERROR] {e}"

        return wrapper

    return decorator
