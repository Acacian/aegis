"""OpenAI Agents SDK integration: govern agent tool calls with Aegis.

Provides three integration modes:

1. **Decorator mode** (``governed_tool``): Wraps individual functions with
   Aegis governance before they become SDK tools.
2. **Input guardrail mode** (``AegisToolInputGuardrail``): Implements the
   SDK's ``@tool_input_guardrail`` protocol to evaluate tool arguments
   against Aegis policy *before* tool execution.
3. **Output guardrail mode** (``AegisToolOutputGuardrail``): Implements the
   SDK's ``@tool_output_guardrail`` protocol to evaluate tool results
   against Aegis policy *after* tool execution.

Requires: ``pip install agent-aegis[openai-agents]``

Decorator example::

    from agents import Agent, Runner
    from aegis import Policy, Runtime
    from aegis.adapters.openai_agents import governed_tool

    runtime = Runtime(executor=my_executor, policy=my_policy)

    @governed_tool(runtime=runtime, action_type="search", action_target="web")
    async def web_search(query: str) -> str:
        return await do_actual_search(query)

    agent = Agent(name="researcher", tools=[web_search])

Guardrail example::

    from agents import Agent, function_tool
    from aegis import Policy
    from aegis.adapters.openai_agents import (
        create_aegis_input_guardrail,
        create_aegis_output_guardrail,
    )

    policy = Policy.from_yaml("policy.yaml")
    input_guard = create_aegis_input_guardrail(policy=policy)
    output_guard = create_aegis_output_guardrail(policy=policy)

    @function_tool(
        tool_input_guardrails=[input_guard],
        tool_output_guardrails=[output_guard],
    )
    def web_search(query: str) -> str:
        return do_search(query)
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from aegis.core.action import Action
from aegis.core.policy import Approval, Policy, PolicyDecision
from aegis.core.result import Result, ResultStatus

logger = logging.getLogger(__name__)


def _require_openai_agents() -> None:
    try:
        import agents  # noqa: F401
    except ImportError:
        raise ImportError(
            "openai-agents is required for OpenAI Agents SDK integration. "
            "Install it with: pip install 'agent-aegis[openai-agents]'"
        ) from None


# ---------------------------------------------------------------------------
# Mode 1: governed_tool decorator (existing, unchanged)
# ---------------------------------------------------------------------------


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

            if not decision.is_allowed:
                return f"[AEGIS BLOCKED] Action blocked by policy rule: {decision.matched_rule}"

            if decision.approval == Approval.APPROVE:
                approved = await runtime.approval.request_approval(decision)
                if not approved:
                    return "[AEGIS DENIED] Action denied by human operator"

            try:
                if asyncio.iscoroutinefunction(fn):
                    result = await fn(*args, **kwargs)
                else:
                    result = fn(*args, **kwargs)

                audit_result = Result(action=action, status=ResultStatus.SUCCESS, data=result)
                runtime.audit.log(
                    runtime.session_id,
                    decision,
                    result=audit_result,
                    human_decision="approved" if decision.approval == Approval.APPROVE else None,
                )
                return str(result)
            except Exception as e:
                audit_result = Result(action=action, status=ResultStatus.FAILED, error=str(e))
                runtime.audit.log(runtime.session_id, decision, result=audit_result)
                return f"[AEGIS ERROR] {e}"

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# Mode 2 & 3: Native guardrail protocol (tool_input / tool_output)
# ---------------------------------------------------------------------------


class AegisToolInputGuardrail:
    """Evaluates tool inputs against Aegis policy before execution.

    Implements the OpenAI Agents SDK ``tool_input_guardrail`` protocol.
    When attached to a ``FunctionTool`` via ``tool_input_guardrails``,
    the SDK calls this guardrail with ``ToolInputGuardrailData`` before
    the tool runs.

    Behavior mapping:
    - Policy **BLOCK** → ``reject_content`` (tool call denied)
    - Policy **APPROVE** (requires human approval) → ``reject_content``
      (async approval not available in guardrail context)
    - Policy **AUTO** + allowed → ``allow``
    - Evaluation error + ``fail_closed=True`` → ``reject_content``
    - Evaluation error + ``fail_closed=False`` → ``allow``

    Args:
        policy: Aegis Policy to evaluate tool calls against.
        target: Default Aegis action target.
        tool_target_map: Optional tool name → Aegis target mapping.
        fail_closed: If ``True`` (default), errors result in deny.
        audit_logger: Optional audit logger for recording decisions.
        session_id: Session ID for audit grouping.
        on_tripwire: If ``True``, blocked calls raise an exception
            (tripwire) instead of returning reject_content.
        name: Guardrail name reported to the SDK.
    """

    def __init__(
        self,
        *,
        policy: Policy,
        target: str = "default",
        tool_target_map: dict[str, str] | None = None,
        fail_closed: bool = True,
        audit_logger: Any | None = None,
        session_id: str = "",
        on_tripwire: bool = False,
        name: str = "aegis_input_guardrail",
    ) -> None:
        self._policy = policy
        self._target = target
        self._tool_target_map = tool_target_map or {}
        self._fail_closed = fail_closed
        self._audit = audit_logger
        self._session_id = session_id
        self._on_tripwire = on_tripwire
        self.name = name

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

    def _build_action(self, tool_name: str, tool_args: dict[str, Any]) -> Action:
        """Map tool call data to an Aegis Action."""
        target = self._tool_target_map.get(tool_name, self._target)
        return Action(
            type=tool_name,
            target=target,
            params=tool_args,
            description=f"OpenAI Agents SDK tool call: {tool_name}",
        )

    def _parse_tool_arguments(self, raw_args: Any) -> dict[str, Any]:
        """Parse tool arguments from various formats."""
        if isinstance(raw_args, dict):
            return raw_args
        if isinstance(raw_args, str):
            try:
                parsed = json.loads(raw_args)
                if isinstance(parsed, dict):
                    return parsed
            except (json.JSONDecodeError, TypeError):
                pass
            return {"input": raw_args}
        return {}

    def _log_decision(self, action: Action, decision: PolicyDecision) -> None:
        """Log a decision to audit trail."""
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

    def evaluate(
        self, tool_name: str, tool_args: dict[str, Any]
    ) -> tuple[bool, str, dict[str, Any]]:
        """Evaluate tool input against policy.

        Returns:
            Tuple of (allow, reason, metadata).
        """
        try:
            action = self._build_action(tool_name, tool_args)
            decision: PolicyDecision = self._policy.evaluate(action)
            self._log_decision(action, decision)

            metadata = {
                "risk_level": decision.risk_level.name,
                "matched_rule": decision.matched_rule,
                "approval": decision.approval.value,
            }

            if not decision.is_allowed:
                return (
                    False,
                    f"Blocked by policy rule: {decision.matched_rule}",
                    metadata,
                )

            if decision.approval == Approval.APPROVE:
                metadata["approval_required"] = "true"
                return (
                    False,
                    f"Requires human approval (rule: {decision.matched_rule})",
                    metadata,
                )

            return (True, f"Allowed by policy rule: {decision.matched_rule}", metadata)

        except Exception as exc:
            logger.exception("Aegis input guardrail evaluation error: %s", exc)
            if self._fail_closed:
                return (
                    False,
                    "Evaluation error (fail-closed): internal governance error",
                    {"error": "Internal governance error", "fail_closed": True},
                )
            return (
                True,
                "Evaluation error (fail-open): internal governance error",
                {"error": "Internal governance error", "fail_closed": False},
            )

    async def __call__(self, data: Any) -> Any:
        """OpenAI Agents SDK ``tool_input_guardrail`` protocol.

        Receives ``ToolInputGuardrailData`` with ``context`` and ``agent``.
        The ``context`` has ``tool_name``, ``tool_arguments`` (raw JSON string),
        and ``tool_call_id``.

        Returns a ``ToolGuardrailFunctionOutput``.
        """
        from agents import ToolGuardrailFunctionOutput

        ctx = getattr(data, "context", None)
        tool_name: str = getattr(ctx, "tool_name", "") if ctx else ""
        raw_args = getattr(ctx, "tool_arguments", "") if ctx else ""
        tool_args = self._parse_tool_arguments(raw_args)

        allow, reason, metadata = self.evaluate(tool_name, tool_args)

        if allow:
            return ToolGuardrailFunctionOutput.allow(output_info=metadata)
        if self._on_tripwire:
            return ToolGuardrailFunctionOutput.raise_exception(
                output_info={"reason": reason, **metadata}
            )

        return ToolGuardrailFunctionOutput.reject_content(reason, output_info=metadata)

    def health_check(self) -> dict[str, Any]:
        """Return guardrail health status."""
        return {
            "status": "healthy",
            "type": "input",
            "policy_rules": len(self._policy.rules),
            "fail_closed": self._fail_closed,
            "on_tripwire": self._on_tripwire,
        }


class AegisToolOutputGuardrail:
    """Evaluates tool outputs against Aegis policy after execution.

    Implements the OpenAI Agents SDK ``tool_output_guardrail`` protocol.
    When attached to a ``FunctionTool`` via ``tool_output_guardrails``,
    the SDK calls this guardrail with ``ToolOutputGuardrailData`` after
    the tool runs. The ``data.output`` contains the tool result.

    Args:
        policy: Aegis Policy to evaluate tool outputs against.
        target: Default Aegis action target.
        tool_target_map: Optional tool name → Aegis target mapping.
        fail_closed: If ``True`` (default), errors result in deny.
        audit_logger: Optional audit logger for recording decisions.
        session_id: Session ID for audit grouping.
        on_tripwire: If ``True``, blocked outputs raise an exception.
        name: Guardrail name reported to the SDK.
    """

    def __init__(
        self,
        *,
        policy: Policy,
        target: str = "default",
        tool_target_map: dict[str, str] | None = None,
        fail_closed: bool = True,
        audit_logger: Any | None = None,
        session_id: str = "",
        on_tripwire: bool = False,
        name: str = "aegis_output_guardrail",
    ) -> None:
        self._policy = policy
        self._target = target
        self._tool_target_map = tool_target_map or {}
        self._fail_closed = fail_closed
        self._audit = audit_logger
        self._session_id = session_id
        self._on_tripwire = on_tripwire
        self.name = name

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

    def _build_action(self, tool_name: str, tool_args: dict[str, Any], output: Any) -> Action:
        """Map tool output data to an Aegis Action for post-execution eval."""
        target = self._tool_target_map.get(tool_name, self._target)
        params = {**tool_args, "_output": str(output) if output is not None else ""}
        return Action(
            type=f"{tool_name}:output",
            target=target,
            params=params,
            description=f"OpenAI Agents SDK tool output: {tool_name}",
        )

    def _parse_tool_arguments(self, raw_args: Any) -> dict[str, Any]:
        """Parse tool arguments from various formats."""
        if isinstance(raw_args, dict):
            return raw_args
        if isinstance(raw_args, str):
            try:
                parsed = json.loads(raw_args)
                if isinstance(parsed, dict):
                    return parsed
            except (json.JSONDecodeError, TypeError):
                pass
            return {"input": raw_args}
        return {}

    def _log_decision(self, action: Action, decision: PolicyDecision) -> None:
        """Log a decision to audit trail."""
        if decision.is_allowed:
            logger.debug(
                "Aegis ALLOW output %s -> %s (rule=%s, risk=%s)",
                action.type,
                action.target,
                decision.matched_rule,
                decision.risk_level.name,
            )
        else:
            logger.warning(
                "Aegis BLOCK output %s -> %s (rule=%s, risk=%s)",
                action.type,
                action.target,
                decision.matched_rule,
                decision.risk_level.name,
            )
        if self._audit is not None:
            if not decision.is_allowed:
                result_status = ResultStatus.BLOCKED
                err_msg = f"Output blocked by rule: {decision.matched_rule}"
            else:
                result_status = ResultStatus.SUCCESS
                err_msg = None
            result = Result(
                action=action,
                status=result_status,
                error=err_msg,
                completed_at=datetime.now(UTC),
            )
            self._audit.log(self._session_id, decision, result=result)

    def evaluate(
        self, tool_name: str, tool_args: dict[str, Any], output: Any
    ) -> tuple[bool, str, dict[str, Any]]:
        """Evaluate tool output against policy.

        Returns:
            Tuple of (allow, reason, metadata).
        """
        try:
            action = self._build_action(tool_name, tool_args, output)
            decision: PolicyDecision = self._policy.evaluate(action)
            self._log_decision(action, decision)

            metadata = {
                "risk_level": decision.risk_level.name,
                "matched_rule": decision.matched_rule,
                "approval": decision.approval.value,
            }

            if not decision.is_allowed:
                return (
                    False,
                    f"Output blocked by policy rule: {decision.matched_rule}",
                    metadata,
                )

            return (True, f"Output allowed by policy rule: {decision.matched_rule}", metadata)

        except Exception as exc:
            logger.exception("Aegis output guardrail evaluation error: %s", exc)
            if self._fail_closed:
                return (
                    False,
                    "Evaluation error (fail-closed): internal governance error",
                    {"error": "Internal governance error", "fail_closed": True},
                )
            return (
                True,
                "Evaluation error (fail-open): internal governance error",
                {"error": "Internal governance error", "fail_closed": False},
            )

    async def __call__(self, data: Any) -> Any:
        """OpenAI Agents SDK ``tool_output_guardrail`` protocol.

        Receives ``ToolOutputGuardrailData`` with ``context``, ``agent``,
        and ``output``.

        Returns a ``ToolGuardrailFunctionOutput``.
        """
        from agents import ToolGuardrailFunctionOutput

        ctx = getattr(data, "context", None)
        tool_name: str = getattr(ctx, "tool_name", "") if ctx else ""
        raw_args = getattr(ctx, "tool_arguments", "") if ctx else ""
        tool_args = self._parse_tool_arguments(raw_args)
        output = getattr(data, "output", None)

        allow, reason, metadata = self.evaluate(tool_name, tool_args, output)

        if allow:
            return ToolGuardrailFunctionOutput.allow(output_info=metadata)
        if self._on_tripwire:
            return ToolGuardrailFunctionOutput.raise_exception(
                output_info={"reason": reason, **metadata}
            )

        return ToolGuardrailFunctionOutput.reject_content(reason, output_info=metadata)

    def health_check(self) -> dict[str, Any]:
        """Return guardrail health status."""
        return {
            "status": "healthy",
            "type": "output",
            "policy_rules": len(self._policy.rules),
            "fail_closed": self._fail_closed,
            "on_tripwire": self._on_tripwire,
        }


# ---------------------------------------------------------------------------
# Convenience factories
# ---------------------------------------------------------------------------


def create_aegis_input_guardrail(
    *,
    policy: Policy,
    target: str = "default",
    tool_target_map: dict[str, str] | None = None,
    fail_closed: bool = True,
    audit_logger: Any | None = None,
    session_id: str = "",
    on_tripwire: bool = False,
    name: str = "aegis_input_guardrail",
) -> Any:
    """Create an Aegis input guardrail compatible with ``@tool_input_guardrail``.

    Returns an object that can be passed to ``FunctionTool``'s
    ``tool_input_guardrails`` parameter. When the SDK is installed, wraps
    the guardrail via ``@tool_input_guardrail`` decorator for full protocol
    compliance.

    Example::

        from aegis import Policy
        from aegis.adapters.openai_agents import create_aegis_input_guardrail

        guard = create_aegis_input_guardrail(
            policy=Policy.from_yaml("policy.yaml"),
            fail_closed=True,
        )

        @function_tool(tool_input_guardrails=[guard])
        def my_tool(query: str) -> str:
            ...
    """
    guardrail = AegisToolInputGuardrail(
        policy=policy,
        target=target,
        tool_target_map=tool_target_map,
        fail_closed=fail_closed,
        audit_logger=audit_logger,
        session_id=session_id,
        on_tripwire=on_tripwire,
        name=name,
    )
    try:
        from agents import tool_input_guardrail

        @tool_input_guardrail(name=name)
        async def _aegis_input(data: Any) -> Any:
            return await guardrail(data)

        # Attach aegis internals for testing/introspection
        _aegis_input._aegis_guardrail = guardrail
        return _aegis_input
    except ImportError:
        # SDK not installed — return the raw callable (usable in tests)
        return guardrail


def create_aegis_output_guardrail(
    *,
    policy: Policy,
    target: str = "default",
    tool_target_map: dict[str, str] | None = None,
    fail_closed: bool = True,
    audit_logger: Any | None = None,
    session_id: str = "",
    on_tripwire: bool = False,
    name: str = "aegis_output_guardrail",
) -> Any:
    """Create an Aegis output guardrail compatible with ``@tool_output_guardrail``.

    Returns an object that can be passed to ``FunctionTool``'s
    ``tool_output_guardrails`` parameter.

    Example::

        from aegis import Policy
        from aegis.adapters.openai_agents import create_aegis_output_guardrail

        guard = create_aegis_output_guardrail(
            policy=Policy.from_yaml("policy.yaml"),
        )

        @function_tool(tool_output_guardrails=[guard])
        def my_tool(query: str) -> str:
            ...
    """
    guardrail = AegisToolOutputGuardrail(
        policy=policy,
        target=target,
        tool_target_map=tool_target_map,
        fail_closed=fail_closed,
        audit_logger=audit_logger,
        session_id=session_id,
        on_tripwire=on_tripwire,
        name=name,
    )
    try:
        from agents import tool_output_guardrail

        @tool_output_guardrail(name=name)
        async def _aegis_output(data: Any) -> Any:
            return await guardrail(data)

        _aegis_output._aegis_guardrail = guardrail
        return _aegis_output
    except ImportError:
        return guardrail
