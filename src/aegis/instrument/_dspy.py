"""Auto-instrumentation for DSPy.

Patches ``Module.__call__`` and ``LM.forward`` so that every DSPy
module invocation and LLM call passes through Aegis guardrails —
with zero changes to user code.

All DSPy imports are deferred.  If ``dspy`` is not installed,
:func:`patch_dspy` records a skip and returns cleanly.
"""

from __future__ import annotations

import functools
import logging
from typing import Any

from aegis.instrument._state import FrameworkPatch, InstrumentationState

logger = logging.getLogger("aegis.instrument.dspy")

_originals: dict[str, Any] = {}
_patched = False


def _extract_lm_input(kwargs: dict[str, Any]) -> str:
    """Extract text from LM.forward arguments."""
    prompt = kwargs.get("prompt", "")
    if isinstance(prompt, str) and prompt:
        return prompt
    messages = kwargs.get("messages", [])
    if isinstance(messages, list):
        parts: list[str] = []
        for msg in messages:
            if isinstance(msg, dict):
                c = msg.get("content", "")
                if isinstance(c, str):
                    parts.append(c)
        return "\n".join(parts)
    return ""


def _extract_lm_output(result: Any) -> str:
    """Extract text from LM.forward result."""
    if isinstance(result, list) and result:
        first = result[0]
        if isinstance(first, dict):
            return str(first.get("text", "") or first.get("content", ""))
        if isinstance(first, str):
            return first
    if isinstance(result, str):
        return result
    return ""


def _extract_module_input(kwargs: dict[str, Any]) -> str:
    """Extract text from Module.__call__ keyword arguments."""
    parts: list[str] = []
    for v in kwargs.values():
        if isinstance(v, str):
            parts.append(v)
    return "\n".join(parts) if parts else ""


def _extract_module_output(result: Any) -> str:
    """Extract text from a DSPy Prediction."""
    if hasattr(result, "toDict"):
        d = result.toDict()
        parts = [str(v) for v in d.values() if isinstance(v, str)]
        return "\n".join(parts) if parts else ""
    if isinstance(result, str):
        return result
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


def patch_dspy() -> FrameworkPatch:
    """Patch DSPy with Aegis governance.

    Wraps ``Module.__call__`` and ``LM.forward`` / ``LM.aforward``
    to apply guardrails to all DSPy module invocations and LLM calls.

    Safe to call multiple times.

    Returns:
        A :class:`FrameworkPatch` describing what was patched.
    """
    global _patched  # noqa: PLW0603

    if _patched:
        return FrameworkPatch(name="dspy", patched=True, targets=list(_originals.keys()))

    targets: list[str] = []

    # -- Patch LM.forward / LM.aforward --------------------------------
    try:
        from dspy.clients.lm import LM

        _originals["LM.forward"] = LM.forward

        @functools.wraps(LM.forward)
        def governed_lm_forward(self: Any, *args: Any, **kwargs: Any) -> Any:
            s = InstrumentationState.get()
            engine = s.guardrail_engine

            input_text = _extract_lm_input(kwargs)
            _run_guardrails(engine, input_text, direction="lm_input", on_block=s.on_block)

            result = _originals["LM.forward"](self, *args, **kwargs)

            output_text = _extract_lm_output(result)
            _run_guardrails(engine, output_text, direction="lm_output", on_block=s.on_block)

            return result

        LM.forward = governed_lm_forward
        targets.append("LM.forward")

        if hasattr(LM, "aforward"):
            _originals["LM.aforward"] = LM.aforward

            @functools.wraps(LM.aforward)
            async def governed_lm_aforward(self: Any, *args: Any, **kwargs: Any) -> Any:
                s = InstrumentationState.get()
                engine = s.guardrail_engine

                input_text = _extract_lm_input(kwargs)
                _run_guardrails(engine, input_text, direction="lm_input", on_block=s.on_block)

                result = await _originals["LM.aforward"](self, *args, **kwargs)

                output_text = _extract_lm_output(result)
                _run_guardrails(engine, output_text, direction="lm_output", on_block=s.on_block)

                return result

            LM.aforward = governed_lm_aforward
            targets.append("LM.aforward")

    except ImportError:
        pass

    # -- Patch Module.__call__ ------------------------------------------
    try:
        from dspy import Module

        _originals["Module.__call__"] = Module.__call__

        @functools.wraps(Module.__call__)
        def governed_module_call(self: Any, *args: Any, **kwargs: Any) -> Any:
            s = InstrumentationState.get()
            engine = s.guardrail_engine

            input_text = _extract_module_input(kwargs)
            _run_guardrails(engine, input_text, direction="module_input", on_block=s.on_block)

            result = _originals["Module.__call__"](self, *args, **kwargs)

            output_text = _extract_module_output(result)
            _run_guardrails(engine, output_text, direction="module_output", on_block=s.on_block)

            return result

        Module.__call__ = governed_module_call
        targets.append("Module.__call__")

    except ImportError:
        pass

    if not targets:
        patch = FrameworkPatch(name="dspy", patched=False, error="dspy not installed")
    else:
        _patched = True
        patch = FrameworkPatch(name="dspy", patched=True, targets=targets)
        logger.info("DSPy instrumented: %s", ", ".join(targets))

    InstrumentationState.get().register_patch(patch)
    return patch


def unpatch_dspy() -> None:
    """Restore original DSPy methods."""
    global _patched  # noqa: PLW0603

    if not _patched:
        return

    try:
        from dspy.clients.lm import LM

        for key in ["LM.forward", "LM.aforward"]:
            if key in _originals:
                setattr(LM, key.split(".")[1], _originals.pop(key))
    except ImportError:
        pass

    try:
        from dspy import Module

        if "Module.__call__" in _originals:
            Module.__call__ = _originals.pop("Module.__call__")
    except ImportError:
        pass

    _originals.clear()
    _patched = False
    logger.info("DSPy unpatched")
