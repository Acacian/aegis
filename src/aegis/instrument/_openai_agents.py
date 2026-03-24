"""Auto-instrumentation for OpenAI Agents SDK.

Patches ``Runner.run`` and ``Runner.run_sync`` so that every agent
execution passes through Aegis guardrails — with zero changes to user code.

All OpenAI Agents SDK imports are deferred.  If ``openai-agents`` is not
installed, :func:`patch_openai_agents` records a skip and returns cleanly.
"""

from __future__ import annotations

import logging
from typing import Any

from aegis.instrument._state import FrameworkPatch, InstrumentationState

logger = logging.getLogger("aegis.instrument.openai_agents")

_originals: dict[str, Any] = {}
_patched = False


def _extract_input_text(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
    """Extract the user input from Runner.run arguments."""
    # Runner.run(agent, input=...) or Runner.run(agent, "prompt")
    inp = kwargs.get("input", "")
    if not inp and len(args) >= 2:
        inp = args[1]
    if isinstance(inp, str):
        return inp
    return str(inp) if inp else ""


def _extract_output_text(result: Any) -> str:
    """Extract text from a RunResult."""
    # RunResult has .final_output (str or object)
    output = getattr(result, "final_output", None)
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


def patch_openai_agents() -> FrameworkPatch:
    """Patch OpenAI Agents SDK Runner with Aegis governance.

    Wraps ``Runner.run`` and ``Runner.run_sync`` to apply guardrails
    to agent input and output.

    Safe to call multiple times.

    Returns:
        A :class:`FrameworkPatch` describing what was patched.
    """
    global _patched  # noqa: PLW0603

    if _patched:
        return FrameworkPatch(name="openai_agents", patched=True, targets=list(_originals.keys()))

    targets: list[str] = []

    try:
        from agents import Runner

        # -- Patch Runner.run (async) ---------------------------------
        _originals["Runner.run"] = Runner.run

        original_run = Runner.run

        async def governed_run(*args: Any, **kwargs: Any) -> Any:
            s = InstrumentationState.get()
            engine = s.guardrail_engine

            # Input guardrail
            input_text = _extract_input_text(args, kwargs)
            _run_guardrails(engine, input_text, direction="input", on_block=s.on_block)

            # Original call
            result = await original_run(*args, **kwargs)

            # Output guardrail
            output_text = _extract_output_text(result)
            _run_guardrails(engine, output_text, direction="output", on_block=s.on_block)

            return result

        Runner.run = governed_run  
        targets.append("Runner.run")

        # -- Patch Runner.run_sync ------------------------------------
        if hasattr(Runner, "run_sync"):
            _originals["Runner.run_sync"] = Runner.run_sync

            original_run_sync = Runner.run_sync

            def governed_run_sync(*args: Any, **kwargs: Any) -> Any:
                s = InstrumentationState.get()
                engine = s.guardrail_engine

                input_text = _extract_input_text(args, kwargs)
                _run_guardrails(engine, input_text, direction="input", on_block=s.on_block)

                result = original_run_sync(*args, **kwargs)

                output_text = _extract_output_text(result)
                _run_guardrails(engine, output_text, direction="output", on_block=s.on_block)

                return result

            Runner.run_sync = governed_run_sync  
            targets.append("Runner.run_sync")

    except ImportError:
        pass

    if not targets:
        patch = FrameworkPatch(
            name="openai_agents",
            patched=False,
            error="openai-agents not installed",
        )
    else:
        _patched = True
        patch = FrameworkPatch(name="openai_agents", patched=True, targets=targets)
        logger.info("OpenAI Agents SDK instrumented: %s", ", ".join(targets))

    InstrumentationState.get().register_patch(patch)
    return patch


def unpatch_openai_agents() -> None:
    """Restore original OpenAI Agents SDK methods."""
    global _patched  # noqa: PLW0603

    if not _patched:
        return

    try:
        from agents import Runner

        if "Runner.run" in _originals:
            Runner.run = _originals.pop("Runner.run")  
        if "Runner.run_sync" in _originals:
            Runner.run_sync = _originals.pop("Runner.run_sync")  
    except ImportError:
        pass

    _originals.clear()
    _patched = False
    logger.info("OpenAI Agents SDK unpatched")
