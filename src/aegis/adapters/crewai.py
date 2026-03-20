"""CrewAI integration: govern CrewAI tool calls with Aegis.

Wraps Aegis governance around CrewAI tools, adding policy checks,
approval gates, and audit logging to every tool invocation.

Requires: ``pip install agent-aegis[crewai]``

Example::

    from crewai import Agent, Task, Crew
    from aegis import Policy, Runtime
    from aegis.adapters.crewai import AegisCrewAITool

    runtime = Runtime(executor=my_executor, policy=my_policy)

    governed_search = AegisCrewAITool(
        runtime=runtime,
        name="governed_search",
        description="Search with governance",
        action_type="search",
        action_target="web",
        fn=lambda query: do_search(query),
    )

    agent = Agent(role="researcher", tools=[governed_search])
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from aegis.core.action import Action


def _require_crewai() -> None:
    try:
        import crewai  # noqa: F401
    except ImportError:
        raise ImportError(
            "crewai is required for CrewAI integration. "
            "Install it with: pip install 'agent-aegis[crewai]'"
        ) from None


class AegisCrewAITool:
    """A CrewAI-compatible tool that routes through Aegis governance.

    Implements the interface that CrewAI expects for custom tools:
    a callable with ``name`` and ``description`` attributes.

    Args:
        runtime: An Aegis Runtime instance.
        name: Tool name visible to the CrewAI agent.
        description: Tool description for the agent.
        action_type: The Aegis action type for policy evaluation.
        action_target: The Aegis action target.
        fn: The actual function to execute after governance checks pass.
    """

    def __init__(
        self,
        *,
        runtime: Any,
        name: str,
        description: str,
        action_type: str,
        action_target: str = "default",
        fn: Callable[..., Any],
    ) -> None:
        _require_crewai()
        self.runtime = runtime
        self.name = name
        self.description = description
        self.action_type = action_type
        self.action_target = action_target
        self._fn = fn

    def __call__(self, *args: Any, **kwargs: Any) -> str:
        """Execute the tool through Aegis governance."""
        return asyncio.get_event_loop().run_until_complete(self._run(*args, **kwargs))

    async def _run(self, *args: Any, **kwargs: Any) -> str:
        action = Action(
            type=self.action_type,
            target=self.action_target,
            params=kwargs if kwargs else {"input": args[0] if args else ""},
            description=self.description,
        )

        plan = self.runtime.plan([action])
        decision = plan.decisions[0]

        if not decision.is_allowed:
            return f"[AEGIS BLOCKED] Blocked by policy rule: {decision.matched_rule}"

        from aegis.core.policy import Approval

        if decision.approval == Approval.APPROVE:
            approved = await self.runtime.approval.request_approval(decision)
            if not approved:
                return "[AEGIS DENIED] Denied by human operator"

        try:
            if asyncio.iscoroutinefunction(self._fn):
                result = await self._fn(*args, **kwargs)
            else:
                result = self._fn(*args, **kwargs)

            from aegis.core.result import Result, ResultStatus

            audit_result = Result(action=action, status=ResultStatus.SUCCESS, data=result)
            self.runtime.audit.log(
                self.runtime.session_id,
                decision,
                result=audit_result,
                human_decision="approved" if decision.approval == Approval.APPROVE else None,
            )
            return str(result)
        except Exception as e:
            from aegis.core.result import Result, ResultStatus

            audit_result = Result(action=action, status=ResultStatus.FAILED, error=str(e))
            self.runtime.audit.log(self.runtime.session_id, decision, result=audit_result)
            return f"[AEGIS ERROR] {e}"
