"""CrewAI integration: govern CrewAI tool calls with Aegis.

Provides two integration modes:

1. **Tool mode** (``AegisCrewAITool``): Wraps individual functions as
   CrewAI-compatible tools with governance built in.
2. **GuardrailProvider mode** (``AegisGuardrailProvider``): Implements the
   ``GuardrailProvider`` / ``BeforeToolCallHook`` protocol proposed in
   `CrewAI #4877 <https://github.com/crewAIInc/crewAI/issues/4877>`_ to
   automatically govern *all* tool calls across a Crew.

Requires: ``pip install agent-aegis[crewai]``

Tool example::

    from aegis import Policy, Runtime
    from aegis.adapters.crewai import AegisCrewAITool

    runtime = Runtime(executor=my_executor, policy=my_policy)
    governed_search = AegisCrewAITool(
        runtime=runtime, name="search", description="Search",
        action_type="search", fn=lambda q: do_search(q),
    )
    agent = Agent(role="researcher", tools=[governed_search])

GuardrailProvider example::

    from aegis.adapters.crewai import AegisGuardrailProvider, GuardrailRequest

    provider = AegisGuardrailProvider(runtime=my_runtime, fail_closed=True)
    decision = provider.evaluate(GuardrailRequest(
        tool_name="web_search",
        tool_input={"query": "sensitive"},
        agent_role="researcher",
    ))
    if not decision.allow:
        print(decision.reason)
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from aegis.core.action import Action
from aegis.core.policy import Approval, Policy, PolicyDecision
from aegis.core.result import Result, ResultStatus

logger = logging.getLogger(__name__)


def _require_crewai() -> None:
    try:
        import crewai  # noqa: F401
    except ImportError:
        raise ImportError(
            "crewai is required for CrewAI integration. "
            "Install it with: pip install 'agent-aegis[crewai]'"
        ) from None


# ---------------------------------------------------------------------------
# Tool mode (existing)
# ---------------------------------------------------------------------------


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

        if decision.approval == Approval.APPROVE:
            approved = await self.runtime.approval.request_approval(decision)
            if not approved:
                return "[AEGIS DENIED] Denied by human operator"

        try:
            if asyncio.iscoroutinefunction(self._fn):
                result = await self._fn(*args, **kwargs)
            else:
                result = self._fn(*args, **kwargs)

            audit_result = Result(action=action, status=ResultStatus.SUCCESS, data=result)
            self.runtime.audit.log(
                self.runtime.session_id,
                decision,
                result=audit_result,
                human_decision="approved" if decision.approval == Approval.APPROVE else None,
            )
            return str(result)
        except Exception as e:
            audit_result = Result(action=action, status=ResultStatus.FAILED, error=str(e))
            self.runtime.audit.log(self.runtime.session_id, decision, result=audit_result)
            return f"[AEGIS ERROR] {e}"


# ---------------------------------------------------------------------------
# GuardrailProvider mode (CrewAI #4877)
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class GuardrailRequest:
    """Typed request for guardrail evaluation.

    Maps to the ``GuardrailRequest`` protocol proposed in CrewAI #4877.

    Attributes:
        tool_name: Name of the tool being invoked.
        tool_input: Arguments passed to the tool.
        agent_role: Role of the agent making the call (optional).
        task_description: Description of the current task (optional).
        context: Arbitrary additional context (optional).
    """

    tool_name: str
    tool_input: dict[str, Any] = dataclasses.field(default_factory=dict)
    agent_role: str = ""
    task_description: str = ""
    context: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class GuardrailDecision:
    """Typed response from guardrail evaluation.

    Maps to the ``GuardrailDecision`` protocol proposed in CrewAI #4877.

    Attributes:
        allow: Whether the tool call is permitted.
        reason: Human-readable explanation of the decision.
        metadata: Additional details (risk_level, matched_rule, etc.).
    """

    allow: bool
    reason: str = ""
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)


class AegisGuardrailProvider:
    """Guardrail provider that evaluates CrewAI tool calls against Aegis policy.

    Implements the ``GuardrailProvider`` protocol from CrewAI #4877.
    Evaluates each tool call against the configured Aegis policy and returns
    a typed :class:`GuardrailDecision`.

    Args:
        runtime: An Aegis Runtime instance. When provided, uses the
            runtime's policy, audit logger, and session_id.
        policy: An Aegis Policy. Used when *runtime* is not provided.
        fail_closed: If ``True`` (default), errors during evaluation result
            in a deny decision. If ``False``, errors result in an allow.
        audit_logger: Optional audit logger for recording decisions.
        session_id: Session ID for audit grouping.
        target: Default Aegis action target.
        tool_target_map: Optional mapping of tool names to Aegis targets.

    Example::

        provider = AegisGuardrailProvider(runtime=my_runtime, fail_closed=True)

        decision = provider.evaluate(GuardrailRequest(
            tool_name="web_search",
            tool_input={"query": "sensitive data"},
            agent_role="researcher",
        ))
        if not decision.allow:
            print(decision.reason)
    """

    def __init__(
        self,
        *,
        runtime: Any | None = None,
        policy: Policy | None = None,
        fail_closed: bool = True,
        audit_logger: Any | None = None,
        session_id: str = "",
        target: str = "default",
        tool_target_map: dict[str, str] | None = None,
    ) -> None:
        if runtime is not None:
            self._policy: Policy = runtime.policy
            self._audit = getattr(runtime, "audit", audit_logger)
            self._session_id = getattr(runtime, "session_id", session_id) or session_id
        elif policy is not None:
            self._policy = policy
            self._audit = audit_logger
            self._session_id = session_id
        else:
            raise ValueError("Either 'runtime' or 'policy' must be provided")

        self._fail_closed = fail_closed
        self._target = target
        self._tool_target_map = tool_target_map or {}

    # -- Properties ---------------------------------------------------------

    @property
    def policy(self) -> Policy:
        """The active Aegis policy."""
        return self._policy

    @policy.setter
    def policy(self, value: Policy) -> None:
        """Hot-swap the policy."""
        self._policy = value

    @property
    def fail_closed(self) -> bool:
        """Whether errors result in deny (True) or allow (False)."""
        return self._fail_closed

    # -- Core evaluation ----------------------------------------------------

    def _build_action(self, request: GuardrailRequest) -> Action:
        """Map a GuardrailRequest to an Aegis Action."""
        target = self._tool_target_map.get(request.tool_name, self._target)
        return Action(
            type=request.tool_name,
            target=target,
            params=request.tool_input,
            description=request.task_description or f"CrewAI tool call: {request.tool_name}",
            agent_id=request.agent_role,
        )

    def evaluate(self, request: GuardrailRequest) -> GuardrailDecision:
        """Evaluate a tool call against Aegis policy.

        Args:
            request: The guardrail request describing the tool call.

        Returns:
            A :class:`GuardrailDecision` indicating allow/deny with reason.
        """
        try:
            action = self._build_action(request)
            decision: PolicyDecision = self._policy.evaluate(action)

            # Log the decision
            self._log_decision(action, decision)

            if not decision.is_allowed:
                return GuardrailDecision(
                    allow=False,
                    reason=f"Blocked by policy rule: {decision.matched_rule}",
                    metadata={
                        "risk_level": decision.risk_level.name,
                        "matched_rule": decision.matched_rule,
                        "approval": decision.approval.value,
                    },
                )

            if decision.approval == Approval.APPROVE:
                return GuardrailDecision(
                    allow=False,
                    reason=f"Requires human approval (rule: {decision.matched_rule})",
                    metadata={
                        "risk_level": decision.risk_level.name,
                        "matched_rule": decision.matched_rule,
                        "approval": decision.approval.value,
                        "approval_required": True,
                    },
                )

            return GuardrailDecision(
                allow=True,
                reason=f"Allowed by policy rule: {decision.matched_rule}",
                metadata={
                    "risk_level": decision.risk_level.name,
                    "matched_rule": decision.matched_rule,
                    "approval": decision.approval.value,
                },
            )

        except Exception as exc:
            logger.exception("Aegis guardrail evaluation error: %s", exc)
            if self._fail_closed:
                return GuardrailDecision(
                    allow=False,
                    reason=f"Evaluation error (fail-closed): {exc}",
                    metadata={"error": str(exc), "fail_closed": True},
                )
            return GuardrailDecision(
                allow=True,
                reason=f"Evaluation error (fail-open): {exc}",
                metadata={"error": str(exc), "fail_closed": False},
            )

    def _log_decision(self, action: Action, decision: PolicyDecision) -> None:
        """Log a decision to the audit trail."""
        if decision.is_allowed:
            logger.debug(
                "Aegis ALLOW %s -> %s (rule=%s, risk=%s)",
                action.type,
                action.target,
                decision.matched_rule,
                decision.risk_level.name,
            )
        else:
            logger.warning(
                "Aegis BLOCK %s -> %s (rule=%s, risk=%s)",
                action.type,
                action.target,
                decision.matched_rule,
                decision.risk_level.name,
            )
        if self._audit is not None:
            result = None
            if not decision.is_allowed:
                result = Result(
                    action=action,
                    status=ResultStatus.BLOCKED,
                    error=f"Blocked by policy rule: {decision.matched_rule}",
                    completed_at=datetime.now(UTC),
                )
            self._audit.log(self._session_id, decision, result=result)

    # -- BeforeToolCallHook protocol ----------------------------------------

    def before_tool_call(
        self,
        tool_name: str,
        tool_input: dict[str, Any] | None = None,
        agent_role: str = "",
        task_description: str = "",
        **context: Any,
    ) -> bool:
        """CrewAI ``BeforeToolCallHook`` protocol implementation.

        Returns ``True`` to allow, ``False`` to block. This method is called
        by CrewAI before each tool invocation when the provider is registered.

        Args:
            tool_name: Name of the tool being called.
            tool_input: Arguments being passed to the tool.
            agent_role: Role of the calling agent.
            task_description: Description of the current task.
            **context: Additional context from CrewAI.

        Returns:
            ``True`` if the tool call is allowed, ``False`` otherwise.
        """
        request = GuardrailRequest(
            tool_name=tool_name,
            tool_input=tool_input or {},
            agent_role=agent_role,
            task_description=task_description,
            context=context,
        )
        decision = self.evaluate(request)
        return decision.allow

    # -- Health check -------------------------------------------------------

    def health_check(self) -> dict[str, Any]:
        """Return provider health status.

        Returns:
            A dict with ``status``, ``policy_rules``, ``fail_closed``.
        """
        return {
            "status": "healthy",
            "policy_rules": len(self._policy.rules),
            "fail_closed": self._fail_closed,
        }


# ---------------------------------------------------------------------------
# One-liner activation
# ---------------------------------------------------------------------------


def enable_aegis_guardrail(
    *,
    runtime: Any | None = None,
    policy: Policy | None = None,
    fail_closed: bool = True,
    audit_logger: Any | None = None,
    session_id: str = "",
    target: str = "default",
    tool_target_map: dict[str, str] | None = None,
) -> AegisGuardrailProvider:
    """Create and return an :class:`AegisGuardrailProvider`.

    This is a convenience factory for one-liner activation::

        from aegis.adapters.crewai import enable_aegis_guardrail
        provider = enable_aegis_guardrail(runtime=my_runtime)
        # Register provider with CrewAI when the hook API lands.

    All parameters are forwarded to :class:`AegisGuardrailProvider`.

    Returns:
        A configured :class:`AegisGuardrailProvider` instance.
    """
    return AegisGuardrailProvider(
        runtime=runtime,
        policy=policy,
        fail_closed=fail_closed,
        audit_logger=audit_logger,
        session_id=session_id,
        target=target,
        tool_target_map=tool_target_map,
    )
