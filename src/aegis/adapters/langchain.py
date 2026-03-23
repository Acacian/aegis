"""LangChain integration: wrap any LangChain tool with Aegis governance.

This adapter provides two integration modes:

1. **Executor mode** (``LangChainExecutor``): Wraps LangChain tools for use
   inside the Aegis runtime pipeline.
2. **Middleware mode** (``AegisMiddleware``): Plugs into LangChain's native
   ``AgentMiddleware`` system (langchain_v1) so every tool call in a
   LangChain agent is governed by Aegis policy automatically.

Requires: ``pip install agent-aegis[langchain]``

Executor example::

    from langchain_community.tools import DuckDuckGoSearchRun
    from aegis import Policy, Runtime
    from aegis.adapters.langchain import LangChainExecutor

    executor = LangChainExecutor(tools=[DuckDuckGoSearchRun()])
    runtime = Runtime(executor=executor, policy=Policy.from_yaml("policy.yaml"))

    plan = runtime.plan([
        Action("DuckDuckGoSearchRun", target="web", params={"query": "AI governance"}),
    ])
    results = await runtime.execute(plan)

Middleware example (langchain_v1)::

    from langchain.agents.middleware import AgentMiddleware
    from aegis import Policy
    from aegis.adapters.langchain import create_aegis_middleware

    middleware = create_aegis_middleware(policy=Policy.from_yaml("policy.yaml"))
    agent = create_agent(model, tools=tools, middleware=[middleware])
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from aegis.adapters.base import BaseExecutor
from aegis.core.action import Action
from aegis.core.policy import Approval, Policy, PolicyDecision
from aegis.core.result import Result, ResultStatus

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional langchain_v1 / langgraph imports (middleware support)
# ---------------------------------------------------------------------------
_HAS_MIDDLEWARE = False
try:
    from langchain.agents.middleware.types import (  # type: ignore[import-not-found]
        AgentMiddleware,
    )
    from langgraph.prebuilt.tool_node import (  # type: ignore[import-not-found]
        ToolCallRequest,
    )

    _HAS_MIDDLEWARE = True
except Exception:  # pragma: no cover – optional dependency
    AgentMiddleware = None
    ToolCallRequest = None


def _require_langchain() -> None:
    try:
        import langchain_core  # noqa: F401
    except ImportError:
        raise ImportError(
            "langchain-core is required for LangChainExecutor. "
            "Install it with: pip install 'agent-aegis[langchain]'"
        ) from None


def _require_middleware() -> None:
    if not _HAS_MIDDLEWARE:
        raise ImportError(
            "langchain_v1 and langgraph are required for AegisMiddleware. "
            "Install with: pip install 'langchain>=1.0' 'langgraph>=0.3'"
        )


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


# ---------------------------------------------------------------------------
# AgentMiddleware integration (langchain_v1)
# ---------------------------------------------------------------------------


class AegisMiddleware:
    """LangChain AgentMiddleware that governs every tool call via Aegis policy.

    Extends LangChain's ``AgentMiddleware`` base class (langchain_v1) to
    intercept tool calls, evaluate them against an Aegis :class:`Policy`,
    and block disallowed calls before they reach the underlying tool.

    The middleware operates transparently: allowed calls proceed normally,
    while blocked calls return a ``ToolMessage`` explaining the policy
    violation instead of executing the tool.

    Args:
        policy: Aegis :class:`Policy` to evaluate tool calls against.
        target: Default target identifier for Aegis actions.
            Tool calls are mapped to ``Action(type=tool_name, target=target)``.
        session_id: Optional session identifier for audit grouping.
            Auto-generated if not provided.
        audit_logger: Optional :class:`AuditLogger` for recording decisions.
            When ``None`` (default), decisions are logged via Python logging only.
        agent_id: Optional agent identifier attached to actions.
        tool_target_map: Optional mapping of tool names to Aegis target names.
            When a tool's name is found in this map, the mapped value is used
            as ``Action.target`` instead of the default *target* parameter.
        on_blocked: Optional async callback invoked when a tool call is blocked.
            Receives the :class:`PolicyDecision`. Useful for alerting.

    Example::

        from aegis import Policy
        from aegis.adapters.langchain import AegisMiddleware

        policy = Policy.from_yaml("policy.yaml")
        middleware = AegisMiddleware(policy=policy, target="agent-tools")

        # Pass to LangChain agent creation:
        agent = create_agent(model, tools=tools, middleware=[middleware])
    """

    def __init__(
        self,
        *,
        policy: Policy,
        target: str = "default",
        session_id: str | None = None,
        audit_logger: Any | None = None,
        agent_id: str = "",
        tool_target_map: dict[str, str] | None = None,
        on_blocked: Callable[[PolicyDecision], Awaitable[None]] | None = None,
    ) -> None:
        _require_middleware()
        self._policy = policy
        self._target = target
        self._session_id = session_id or uuid.uuid4().hex[:12]
        self._audit = audit_logger
        self._agent_id = agent_id
        self._tool_target_map = tool_target_map or {}
        self._on_blocked = on_blocked

    # -- Public helpers ----------------------------------------------------

    @property
    def name(self) -> str:
        """Middleware name reported to LangChain."""
        return "AegisMiddleware"

    @property
    def policy(self) -> Policy:
        """The active Aegis policy."""
        return self._policy

    @policy.setter
    def policy(self, value: Policy) -> None:
        """Hot-swap the policy without recreating the middleware."""
        self._policy = value

    @property
    def session_id(self) -> str:
        """Current audit session identifier."""
        return self._session_id

    # -- Core: tool call interception --------------------------------------

    def _build_action(self, tool_name: str, tool_args: dict[str, Any]) -> Action:
        """Map a LangChain tool call to an Aegis Action."""
        target = self._tool_target_map.get(tool_name, self._target)
        return Action(
            type=tool_name,
            target=target,
            params=tool_args,
            description=f"LangChain tool call: {tool_name}",
            agent_id=self._agent_id,
        )

    def _evaluate(self, action: Action) -> PolicyDecision:
        """Evaluate an action against the policy and optionally log it."""
        decision = self._policy.evaluate(action)
        # Always log via Python logging
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
        # Persist to audit logger if available
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
        return decision

    def _make_blocked_message(self, decision: PolicyDecision, tool_call_id: str) -> Any:
        """Create a ToolMessage indicating a blocked tool call."""
        from langchain_core.messages import ToolMessage

        return ToolMessage(
            content=(
                f"[AEGIS BLOCKED] Tool '{decision.action.type}' was blocked by "
                f"policy rule '{decision.matched_rule}' "
                f"(risk={decision.risk_level.name}). "
                "The agent is not permitted to execute this tool call."
            ),
            tool_call_id=tool_call_id,
            status="error",
        )

    def wrap_tool_call(
        self,
        request: Any,
        handler: Callable[..., Any],
    ) -> Any:
        """Synchronous tool call interception.

        Evaluates the tool call against Aegis policy. If the policy blocks it,
        returns a ``ToolMessage`` with an error explanation. Otherwise, delegates
        to the original handler.
        """
        tool_call: dict[str, Any] = request.tool_call
        tool_name: str = tool_call.get("name", "")
        tool_args: dict[str, Any] = tool_call.get("args", {})
        tool_call_id: str = tool_call.get("id", "")

        action = self._build_action(tool_name, tool_args)
        decision = self._evaluate(action)

        if not decision.is_allowed:
            return self._make_blocked_message(decision, tool_call_id)

        # Approval-required actions: for sync context we must block
        # (cannot do interactive approval in middleware pipeline)
        if decision.approval == Approval.APPROVE:
            logger.info(
                "Aegis: tool '%s' requires approval (rule=%s). "
                "Allowing in middleware — use Runtime for approval gates.",
                tool_name,
                decision.matched_rule,
            )

        return handler(request)

    async def awrap_tool_call(
        self,
        request: Any,
        handler: Callable[..., Awaitable[Any]],
    ) -> Any:
        """Async tool call interception.

        Evaluates the tool call against Aegis policy. If the policy blocks it,
        returns a ``ToolMessage`` with an error explanation. Otherwise, delegates
        to the original async handler.

        When an ``on_blocked`` callback is registered, it is awaited for
        blocked calls.
        """
        tool_call: dict[str, Any] = request.tool_call
        tool_name: str = tool_call.get("name", "")
        tool_args: dict[str, Any] = tool_call.get("args", {})
        tool_call_id: str = tool_call.get("id", "")

        action = self._build_action(tool_name, tool_args)
        decision = self._evaluate(action)

        if not decision.is_allowed:
            if self._on_blocked:
                await self._on_blocked(decision)
            return self._make_blocked_message(decision, tool_call_id)

        if decision.approval == Approval.APPROVE:
            logger.info(
                "Aegis: tool '%s' requires approval (rule=%s). "
                "Allowing in middleware — use Runtime for approval gates.",
                tool_name,
                decision.matched_rule,
            )

        return await handler(request)


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------


def create_aegis_middleware(
    *,
    policy: Policy,
    target: str = "default",
    session_id: str | None = None,
    audit_logger: Any | None = None,
    agent_id: str = "",
    tool_target_map: dict[str, str] | None = None,
    on_blocked: Callable[[PolicyDecision], Awaitable[None]] | None = None,
) -> AegisMiddleware:
    """Create an :class:`AegisMiddleware` instance for use with LangChain agents.

    This is a convenience factory that validates the middleware dependencies
    are available before constructing the middleware.

    All parameters are forwarded to :class:`AegisMiddleware`.

    Example::

        from aegis import Policy
        from aegis.adapters.langchain import create_aegis_middleware

        middleware = create_aegis_middleware(
            policy=Policy.from_yaml("policy.yaml"),
            target="my-agent",
        )
    """
    return AegisMiddleware(
        policy=policy,
        target=target,
        session_id=session_id,
        audit_logger=audit_logger,
        agent_id=agent_id,
        tool_target_map=tool_target_map,
        on_blocked=on_blocked,
    )
