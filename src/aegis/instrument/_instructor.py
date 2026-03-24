"""Auto-instrumentation for Instructor.

Patches ``Instructor.create`` and ``AsyncInstructor.create`` so that
every structured-output LLM call passes through Aegis guardrails —
with zero changes to user code.

All Instructor imports are deferred.  If ``instructor`` is not
installed, :func:`patch_instructor` records a skip and returns cleanly.
"""

from __future__ import annotations

import functools
import logging
from typing import Any

from aegis.instrument._state import FrameworkPatch, InstrumentationState

logger = logging.getLogger("aegis.instrument.instructor")

_originals: dict[str, Any] = {}
_patched = False


def _extract_input(kwargs: dict[str, Any]) -> str:
    """Extract text from Instructor.create messages argument."""
    messages = kwargs.get("messages", [])
    if isinstance(messages, list):
        parts: list[str] = []
        for msg in messages:
            if isinstance(msg, dict):
                c = msg.get("content", "")
                if isinstance(c, str):
                    parts.append(c)
            else:
                content = getattr(msg, "content", None)
                if isinstance(content, str):
                    parts.append(content)
        return "\n".join(parts)
    return str(messages) if messages else ""


def _extract_output(result: Any) -> str:
    """Extract text from Instructor result (Pydantic model or raw)."""
    if isinstance(result, str):
        return result
    # Pydantic model — try model_dump or json
    if hasattr(result, "model_dump"):
        return str(result.model_dump())
    return str(result) if result is not None else ""


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


def patch_instructor() -> FrameworkPatch:
    """Patch Instructor with Aegis governance.

    Wraps ``Instructor.create`` and ``AsyncInstructor.create`` to apply
    guardrails to all structured-output LLM calls.

    Safe to call multiple times.

    Returns:
        A :class:`FrameworkPatch` describing what was patched.
    """
    global _patched  # noqa: PLW0603

    if _patched:
        return FrameworkPatch(name="instructor", patched=True, targets=list(_originals.keys()))

    targets: list[str] = []

    try:
        from instructor.client import Instructor

        _originals["Instructor.create"] = Instructor.create

        @functools.wraps(Instructor.create)
        def governed_create(self: Any, *args: Any, **kwargs: Any) -> Any:
            s = InstrumentationState.get()
            engine = s.guardrail_engine

            input_text = _extract_input(kwargs)
            _run_guardrails(engine, input_text, direction="input", on_block=s.on_block)

            result = _originals["Instructor.create"](self, *args, **kwargs)

            output_text = _extract_output(result)
            _run_guardrails(engine, output_text, direction="output", on_block=s.on_block)

            return result

        Instructor.create = governed_create
        targets.append("Instructor.create")

    except ImportError:
        pass

    try:
        from instructor.client import AsyncInstructor

        _originals["AsyncInstructor.create"] = AsyncInstructor.create

        @functools.wraps(AsyncInstructor.create)
        async def governed_async_create(self: Any, *args: Any, **kwargs: Any) -> Any:
            s = InstrumentationState.get()
            engine = s.guardrail_engine

            input_text = _extract_input(kwargs)
            _run_guardrails(engine, input_text, direction="input", on_block=s.on_block)

            result = await _originals["AsyncInstructor.create"](self, *args, **kwargs)

            output_text = _extract_output(result)
            _run_guardrails(engine, output_text, direction="output", on_block=s.on_block)

            return result

        AsyncInstructor.create = governed_async_create
        targets.append("AsyncInstructor.create")

    except ImportError:
        pass

    if not targets:
        patch = FrameworkPatch(
            name="instructor",
            patched=False,
            error="instructor not installed",
        )
    else:
        _patched = True
        patch = FrameworkPatch(name="instructor", patched=True, targets=targets)
        logger.info("Instructor instrumented: %s", ", ".join(targets))

    InstrumentationState.get().register_patch(patch)
    return patch


def unpatch_instructor() -> None:
    """Restore original Instructor methods."""
    global _patched  # noqa: PLW0603

    if not _patched:
        return

    try:
        from instructor.client import Instructor

        if "Instructor.create" in _originals:
            Instructor.create = _originals.pop("Instructor.create")
    except ImportError:
        pass

    try:
        from instructor.client import AsyncInstructor

        if "AsyncInstructor.create" in _originals:
            AsyncInstructor.create = _originals.pop("AsyncInstructor.create")
    except ImportError:
        pass

    _originals.clear()
    _patched = False
    logger.info("Instructor unpatched")
