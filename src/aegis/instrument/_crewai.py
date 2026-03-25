"""Auto-instrumentation for CrewAI.

Patches ``Crew.kickoff`` and registers a global ``BeforeToolCallHook``
so that every agent task and tool call passes through Aegis guardrails —
with zero changes to user code.

All CrewAI imports are deferred.  If ``crewai`` is not installed,
:func:`patch_crewai` records a skip and returns cleanly.
"""

from __future__ import annotations

import functools
import logging
from typing import Any

from aegis.instrument._state import FrameworkPatch, InstrumentationState

logger = logging.getLogger("aegis.instrument.crewai")

_originals: dict[str, Any] = {}
_patched = False
_hook_registered = False


def _run_guardrails(engine: Any, text: str, *, direction: str, on_block: str) -> None:
    """Run guardrails, raise on block if configured."""
    if engine is None or not text:
        return
    try:
        results = engine.check(text)
    except Exception:
        logger.debug("Guardrail check failed for %s", direction, exc_info=True)
        return

    blocked = [r for r in results if getattr(r, "action", None) == "blocked"]
    if blocked:
        details = "; ".join(
            getattr(r, "details", "") or getattr(r, "guardrail_name", "unknown") for r in blocked
        )
        reason = f"Aegis blocked {direction}: {details}"
        if on_block == "raise":
            from aegis.integrations.errors import AegisGuardrailError

            raise AegisGuardrailError(reason, guardrail_results=blocked)
        logger.warning(reason)


class _AegisCrewAIHook:
    """Internal BeforeToolCallHook for auto-instrumentation.

    Implements the ``__call__(context) -> bool | None`` protocol that
    CrewAI expects from ``BeforeToolCallHook``.
    """

    def __call__(self, context: Any) -> bool | None:
        s = InstrumentationState.get()
        engine = s.guardrail_engine
        if engine is None:
            return None

        tool_name = getattr(context, "tool_name", "")
        tool_input = getattr(context, "tool_input", {})
        text = f"{tool_name}: {tool_input}" if tool_input else tool_name

        try:
            results = engine.check(text)
            blocked = [r for r in results if getattr(r, "action", None) == "blocked"]
            if blocked:
                details = "; ".join(
                    getattr(r, "details", "") or getattr(r, "guardrail_name", "unknown")
                    for r in blocked
                )
                logger.warning("Aegis blocked CrewAI tool '%s': %s", tool_name, details)
                return False  # Block the tool call
        except Exception:
            logger.debug("CrewAI hook guardrail check failed", exc_info=True)

        return None  # Allow


def patch_crewai() -> FrameworkPatch:
    """Patch CrewAI with Aegis governance.

    1. Registers a global ``BeforeToolCallHook`` to govern all tool calls.
    2. Patches ``Crew.kickoff`` to run input guardrails on task descriptions.

    Safe to call multiple times.

    Returns:
        A :class:`FrameworkPatch` describing what was patched.
    """
    global _patched, _hook_registered  # noqa: PLW0603

    if _patched:
        return FrameworkPatch(name="crewai", patched=True, targets=list(_originals.keys()))

    targets: list[str] = []

    # -- Register global tool hook ------------------------------------
    try:
        from crewai.hooks.tool_hooks import register_before_tool_call_hook

        if not _hook_registered:
            register_before_tool_call_hook(_AegisCrewAIHook())
            _hook_registered = True
            targets.append("BeforeToolCallHook")

    except ImportError:
        pass

    # -- Patch Crew.kickoff -------------------------------------------
    try:
        from crewai import Crew

        _originals["Crew.kickoff"] = Crew.kickoff

        @functools.wraps(Crew.kickoff)
        def governed_kickoff(self: Any, *args: Any, **kwargs: Any) -> Any:
            s = InstrumentationState.get()
            engine = s.guardrail_engine

            # Check task descriptions for suspicious content
            tasks = getattr(self, "tasks", [])
            for task in tasks:
                desc = getattr(task, "description", "")
                if desc:
                    _run_guardrails(engine, desc, direction="crew_task", on_block=s.on_block)

            # Plan-level evaluation
            _check_plan_violations(tasks, s)

            return _originals["Crew.kickoff"](self, *args, **kwargs)

        Crew.kickoff = governed_kickoff
        targets.append("Crew.kickoff")

    except ImportError:
        pass

    # -- Patch Crew.kickoff_async -------------------------------------
    try:
        from crewai import Crew

        if hasattr(Crew, "kickoff_async"):
            _originals["Crew.kickoff_async"] = Crew.kickoff_async

            @functools.wraps(Crew.kickoff_async)
            async def governed_kickoff_async(self: Any, *args: Any, **kwargs: Any) -> Any:
                s = InstrumentationState.get()
                engine = s.guardrail_engine

                tasks = getattr(self, "tasks", [])
                for task in tasks:
                    desc = getattr(task, "description", "")
                    if desc:
                        _run_guardrails(engine, desc, direction="crew_task", on_block=s.on_block)

                # Plan-level evaluation
                _check_plan_violations(tasks, s)

                return await _originals["Crew.kickoff_async"](self, *args, **kwargs)

            Crew.kickoff_async = governed_kickoff_async
            targets.append("Crew.kickoff_async")

    except ImportError:
        pass

    if not targets:
        patch = FrameworkPatch(name="crewai", patched=False, error="crewai not installed")
    else:
        _patched = True
        patch = FrameworkPatch(name="crewai", patched=True, targets=targets)
        logger.info("CrewAI instrumented: %s", ", ".join(targets))

    InstrumentationState.get().register_patch(patch)
    return patch


def _extract_crew_plan(tasks: list[Any]) -> list[Any]:
    """Convert CrewAI tasks to Aegis Actions for plan-level evaluation."""
    from aegis.core.action import Action

    actions = []
    for task in tasks:
        action_type = getattr(task, "name", "") or "crew_task"
        description = getattr(task, "description", "")
        tools = [getattr(t, "name", str(t)) for t in (getattr(task, "tools", []) or [])]
        actions.append(
            Action(
                type=action_type,
                target="crewai",
                params={"tools": tools},
                description=description,
            )
        )
    return actions


def _check_plan_violations(tasks: list[Any], state: InstrumentationState) -> None:
    """Evaluate CrewAI tasks as a plan and raise/warn on violations."""
    policy = state.policy
    if policy is None or policy.plan_rules is None:
        return

    from aegis.core.plan import ExecutionPlan
    from aegis.core.policy import Approval

    actions = _extract_crew_plan(tasks)
    if not actions:
        return

    decisions = [policy.evaluate(a) for a in actions]
    exec_plan = ExecutionPlan(decisions=decisions)
    violations = policy.plan_rules.evaluate(exec_plan)

    blocking = [v for v in violations if v.approval == Approval.BLOCK]
    if blocking:
        reason = f"Aegis plan-rule blocked: {blocking[0].rule_name} — {blocking[0].description}"
        if state.on_block == "raise":
            from aegis.integrations.errors import AegisGuardrailError

            raise AegisGuardrailError(reason, guardrail_results=[])
        logger.warning(reason)


def unpatch_crewai() -> None:
    """Restore original CrewAI methods."""
    global _patched  # noqa: PLW0603

    if not _patched:
        return

    try:
        from crewai import Crew

        if "Crew.kickoff" in _originals:
            Crew.kickoff = _originals.pop("Crew.kickoff")
        if "Crew.kickoff_async" in _originals:
            Crew.kickoff_async = _originals.pop("Crew.kickoff_async")
    except ImportError:
        pass

    _originals.clear()
    _patched = False
    logger.info("CrewAI unpatched")
