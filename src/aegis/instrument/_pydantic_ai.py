"""Auto-instrumentation for Pydantic AI.

Patches ``Agent.run`` and ``Agent.run_sync`` so that every agent
execution passes through Aegis guardrails — with zero changes to
user code.

All Pydantic AI imports are deferred.  If ``pydantic-ai`` is not
installed, :func:`patch_pydantic_ai` records a skip and returns cleanly.
"""

from __future__ import annotations

import functools
import logging
from typing import Any

from aegis.instrument._state import FrameworkPatch, InstrumentationState

logger = logging.getLogger("aegis.instrument.pydantic_ai")

_originals: dict[str, Any] = {}
_patched = False


def _extract_input(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
    """Extract the user prompt from Agent.run arguments."""
    prompt = kwargs.get("user_prompt") or (args[0] if args else "")
    if isinstance(prompt, str):
        return prompt
    return str(prompt) if prompt else ""


def _extract_output(result: Any) -> str:
    """Extract text from a RunResult."""
    output = getattr(result, "output", None)
    if output is None:
        output = getattr(result, "data", None)
    if isinstance(output, str):
        return output
    return ""


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


def patch_pydantic_ai() -> FrameworkPatch:
    """Patch Pydantic AI Agent with Aegis governance.

    Wraps ``Agent.run`` and ``Agent.run_sync`` to apply guardrails
    to agent input and output.

    Safe to call multiple times.

    Returns:
        A :class:`FrameworkPatch` describing what was patched.
    """
    global _patched  # noqa: PLW0603

    if _patched:
        return FrameworkPatch(name="pydantic_ai", patched=True, targets=list(_originals.keys()))

    targets: list[str] = []

    try:
        from pydantic_ai import Agent

        # -- Patch Agent.run (async) ------------------------------------
        _originals["Agent.run"] = Agent.run

        @functools.wraps(Agent.run)
        async def governed_run(self: Any, *args: Any, **kwargs: Any) -> Any:
            s = InstrumentationState.get()
            engine = s.guardrail_engine

            input_text = _extract_input(args, kwargs)
            _run_guardrails(engine, input_text, direction="input", on_block=s.on_block)

            result = await _originals["Agent.run"](self, *args, **kwargs)

            output_text = _extract_output(result)
            _run_guardrails(engine, output_text, direction="output", on_block=s.on_block)

            return result

        Agent.run = governed_run
        targets.append("Agent.run")

        # -- Patch Agent.run_sync ---------------------------------------
        if hasattr(Agent, "run_sync"):
            _originals["Agent.run_sync"] = Agent.run_sync

            @functools.wraps(Agent.run_sync)
            def governed_run_sync(self: Any, *args: Any, **kwargs: Any) -> Any:
                s = InstrumentationState.get()
                engine = s.guardrail_engine

                input_text = _extract_input(args, kwargs)
                _run_guardrails(engine, input_text, direction="input", on_block=s.on_block)

                result = _originals["Agent.run_sync"](self, *args, **kwargs)

                output_text = _extract_output(result)
                _run_guardrails(engine, output_text, direction="output", on_block=s.on_block)

                return result

            Agent.run_sync = governed_run_sync
            targets.append("Agent.run_sync")

    except ImportError:
        pass

    if not targets:
        patch = FrameworkPatch(
            name="pydantic_ai",
            patched=False,
            error="pydantic-ai not installed",
        )
    else:
        _patched = True
        patch = FrameworkPatch(name="pydantic_ai", patched=True, targets=targets)
        logger.info("Pydantic AI instrumented: %s", ", ".join(targets))

    InstrumentationState.get().register_patch(patch)
    return patch


def unpatch_pydantic_ai() -> None:
    """Restore original Pydantic AI methods."""
    global _patched  # noqa: PLW0603

    if not _patched:
        return

    try:
        from pydantic_ai import Agent

        if "Agent.run" in _originals:
            Agent.run = _originals.pop("Agent.run")
        if "Agent.run_sync" in _originals:
            Agent.run_sync = _originals.pop("Agent.run_sync")
    except ImportError:
        pass

    _originals.clear()
    _patched = False
    logger.info("Pydantic AI unpatched")
