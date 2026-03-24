"""Auto-instrumentation for LiteLLM.

Patches ``litellm.completion`` and ``litellm.acompletion`` so that every
LLM call routed through LiteLLM passes through Aegis guardrails —
with zero changes to user code.

All LiteLLM imports are deferred.  If ``litellm`` is not installed,
:func:`patch_litellm` records a skip and returns cleanly.
"""

from __future__ import annotations

import logging
from typing import Any

from aegis.instrument._state import FrameworkPatch, InstrumentationState

logger = logging.getLogger("aegis.instrument.litellm")

_originals: dict[str, Any] = {}
_patched = False


def _extract_input(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
    """Extract text from litellm.completion arguments."""
    messages = kwargs.get("messages") or (args[1] if len(args) >= 2 else [])
    if isinstance(messages, list):
        parts: list[str] = []
        for msg in messages:
            if isinstance(msg, dict):
                c = msg.get("content", "")
                if isinstance(c, str):
                    parts.append(c)
        return "\n".join(parts)
    return str(messages) if messages else ""


def _extract_output(response: Any) -> str:
    """Extract text from litellm ModelResponse."""
    choices = getattr(response, "choices", None)
    if choices and len(choices) > 0:
        message = getattr(choices[0], "message", None)
        content = getattr(message, "content", None) if message else None
        if isinstance(content, str):
            return content
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


def patch_litellm() -> FrameworkPatch:
    """Patch LiteLLM with Aegis governance.

    Wraps ``litellm.completion`` and ``litellm.acompletion`` to apply
    guardrails to all LLM calls routed through LiteLLM.

    Safe to call multiple times.

    Returns:
        A :class:`FrameworkPatch` describing what was patched.
    """
    global _patched  # noqa: PLW0603

    if _patched:
        return FrameworkPatch(name="litellm", patched=True, targets=list(_originals.keys()))

    targets: list[str] = []

    try:
        import litellm

        # -- Patch litellm.completion ------------------------------------
        _originals["litellm.completion"] = litellm.completion

        original_completion = litellm.completion

        def governed_completion(*args: Any, **kwargs: Any) -> Any:
            s = InstrumentationState.get()
            engine = s.guardrail_engine

            input_text = _extract_input(args, kwargs)
            _run_guardrails(engine, input_text, direction="input", on_block=s.on_block)

            response = original_completion(*args, **kwargs)

            output_text = _extract_output(response)
            _run_guardrails(engine, output_text, direction="output", on_block=s.on_block)

            return response

        litellm.completion = governed_completion
        targets.append("litellm.completion")

        # -- Patch litellm.acompletion -----------------------------------
        _originals["litellm.acompletion"] = litellm.acompletion

        original_acompletion = litellm.acompletion

        async def governed_acompletion(*args: Any, **kwargs: Any) -> Any:
            s = InstrumentationState.get()
            engine = s.guardrail_engine

            input_text = _extract_input(args, kwargs)
            _run_guardrails(engine, input_text, direction="input", on_block=s.on_block)

            response = await original_acompletion(*args, **kwargs)

            output_text = _extract_output(response)
            _run_guardrails(engine, output_text, direction="output", on_block=s.on_block)

            return response

        litellm.acompletion = governed_acompletion
        targets.append("litellm.acompletion")

    except ImportError:
        pass

    if not targets:
        patch = FrameworkPatch(name="litellm", patched=False, error="litellm not installed")
    else:
        _patched = True
        patch = FrameworkPatch(name="litellm", patched=True, targets=targets)
        logger.info("LiteLLM instrumented: %s", ", ".join(targets))

    InstrumentationState.get().register_patch(patch)
    return patch


def unpatch_litellm() -> None:
    """Restore original LiteLLM functions."""
    global _patched  # noqa: PLW0603

    if not _patched:
        return

    try:
        import litellm

        if "litellm.completion" in _originals:
            litellm.completion = _originals.pop("litellm.completion")
        if "litellm.acompletion" in _originals:
            litellm.acompletion = _originals.pop("litellm.acompletion")
    except ImportError:
        pass

    _originals.clear()
    _patched = False
    logger.info("LiteLLM unpatched")
