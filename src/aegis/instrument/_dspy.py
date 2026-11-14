"""Auto-instrumentation for DSPy.

Patches ``Module.__call__`` and the LM call path so that every DSPy
module invocation and LLM call passes through Aegis guardrails —
with zero changes to user code.

The LM call path depends on the DSPy version:

* DSPy <= 3.3: ``LM.__call__`` / ``LM.acall`` delegate to ``LM.forward`` /
  ``LM.aforward``.
* DSPy 3.4: ``__call__`` / ``acall`` run the call themselves through
  ``dspy.clients.execution``; ``forward`` remains as a separate direct entry.
* DSPy 3.5: ``forward`` is gone; ``__call__`` / ``acall`` take a string, an
  lm15 ``Request`` or an adapter ``Prompt``.

Every one of those methods the installed DSPy defines is wrapped.  A context
variable marks an LM call in progress, so when one entry point delegates to
another only the outermost call runs the guardrails.

All DSPy imports are deferred.  If ``dspy`` is not installed,
:func:`patch_dspy` records a skip and returns cleanly.
"""

from __future__ import annotations

import contextvars
import functools
import logging
from typing import Any

from aegis.instrument._state import FrameworkPatch, InstrumentationState

logger = logging.getLogger("aegis.instrument.dspy")

_originals: dict[str, Any] = {}
# Keys in _originals whose attribute was inherited rather than defined on LM
# itself; unpatch deletes the override instead of setting it back.
_inherited: set[str] = set()
_patched = False

# (attribute, is_async) for every LM entry point across DSPy versions.
_LM_METHODS = (("__call__", False), ("acall", True), ("forward", False), ("aforward", True))

# True while a governed LM call is running; nested entry points skip checks.
_in_lm_call: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "aegis_dspy_in_lm_call", default=False
)


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


def _text_of(content: Any) -> str:
    """Text of a system value or message: a string, a chat dict, or parts with ``.text``."""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        return _text_of(content.get("content"))
    if isinstance(content, (list, tuple)):
        return "\n".join(t for t in (_text_of(part) for part in content) if t)
    if content is None:
        return ""
    for attr in ("text", "content"):
        value = getattr(content, attr, None)
        if isinstance(value, str):
            return value
    return ""


def _extract_lm_call_input(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
    """Extract text from the arguments of any DSPy LM entry point.

    Covers a prompt string (positional or ``prompt=``), OpenAI-style
    ``messages=`` dicts, and request objects — lm15 ``Request``, adapter
    ``Prompt``, DSPy 3.3 ``LMRequest`` — that carry ``system`` and ``messages``.
    """
    prompt = args[0] if args else kwargs.get("prompt")
    if prompt is None:
        prompt = kwargs.get("request")
    if isinstance(prompt, str) and prompt:
        return prompt
    if prompt is None or isinstance(prompt, str) or not hasattr(prompt, "messages"):
        return _extract_lm_input(kwargs)
    parts = [_text_of(getattr(prompt, "system", None))]
    parts.extend(_text_of(msg) for msg in getattr(prompt, "messages", ()) or ())
    return "\n".join(p for p in parts if p)


def _extract_lm_output(result: Any) -> str:
    """Extract text from an LM result: a list of outputs or an lm15 ``Response``."""
    if isinstance(result, list) and result:
        first = result[0]
        if isinstance(first, dict):
            return str(first.get("text", "") or first.get("content", ""))
        if isinstance(first, str):
            return first
    if isinstance(result, str):
        return result
    if isinstance(result, (list, dict)) or result is None:
        return ""
    text = getattr(result, "text", None)
    return text if isinstance(text, str) else ""


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


def _defines(cls: Any, attr: str) -> bool:
    """True when ``attr`` is defined on ``cls`` or a base other than ``object``.

    ``hasattr(cls, "__call__")`` is always true for a class (it finds
    ``type.__call__``), so look in the MRO instead.
    """
    return any(attr in vars(base) for base in cls.__mro__ if base is not object)


def _patch_lm_method(lm_cls: Any, attr: str, *, is_async: bool) -> str:
    """Wrap one LM entry point with input/output guardrails and return its target name."""
    key = f"LM.{attr}"
    original = getattr(lm_cls, attr)
    _originals[key] = original
    if attr not in vars(lm_cls):
        _inherited.add(key)

    def check_input(args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        s = InstrumentationState.get()
        text = _extract_lm_call_input(args, kwargs)
        _run_guardrails(s.guardrail_engine, text, direction="lm_input", on_block=s.on_block)

    def check_output(result: Any) -> None:
        s = InstrumentationState.get()
        text = _extract_lm_output(result)
        _run_guardrails(s.guardrail_engine, text, direction="lm_output", on_block=s.on_block)

    if is_async:

        @functools.wraps(original)
        async def governed(self: Any, *args: Any, **kwargs: Any) -> Any:
            if _in_lm_call.get():
                return await original(self, *args, **kwargs)
            check_input(args, kwargs)
            token = _in_lm_call.set(True)
            try:
                result = await original(self, *args, **kwargs)
            finally:
                _in_lm_call.reset(token)
            check_output(result)
            return result

    else:

        @functools.wraps(original)
        def governed(self: Any, *args: Any, **kwargs: Any) -> Any:
            if _in_lm_call.get():
                return original(self, *args, **kwargs)
            check_input(args, kwargs)
            token = _in_lm_call.set(True)
            try:
                result = original(self, *args, **kwargs)
            finally:
                _in_lm_call.reset(token)
            check_output(result)
            return result

    setattr(lm_cls, attr, governed)
    return key


def patch_dspy() -> FrameworkPatch:
    """Patch DSPy with Aegis governance.

    Wraps ``Module.__call__`` and every LM entry point the installed DSPy
    defines (``__call__``, ``acall``, ``forward``, ``aforward``) to apply
    guardrails to all DSPy module invocations and LLM calls.

    Safe to call multiple times.

    Returns:
        A :class:`FrameworkPatch` describing what was patched.
    """
    global _patched  # noqa: PLW0603

    if _patched:
        return FrameworkPatch(name="dspy", patched=True, targets=list(_originals.keys()))

    targets: list[str] = []

    # -- Patch the LM call path -----------------------------------------
    try:
        from dspy.clients.lm import LM
    except ImportError:
        pass
    else:
        for attr, is_async in _LM_METHODS:
            if _defines(LM, attr):
                targets.append(_patch_lm_method(LM, attr, is_async=is_async))

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

        for attr, _ in _LM_METHODS:
            key = f"LM.{attr}"
            if key not in _originals:
                continue
            original = _originals.pop(key)
            if key in _inherited:
                delattr(LM, attr)
            else:
                setattr(LM, attr, original)
    except ImportError:
        pass

    try:
        from dspy import Module

        if "Module.__call__" in _originals:
            Module.__call__ = _originals.pop("Module.__call__")
    except ImportError:
        pass

    _originals.clear()
    _inherited.clear()
    _patched = False
    logger.info("DSPy unpatched")
