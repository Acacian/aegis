"""Auto-instrumentation for LlamaIndex.

Patches ``LLM.chat/complete`` and ``BaseQueryEngine.query`` so that
every LLM call and RAG query passes through Aegis guardrails —
with zero changes to user code.

Patching the base class is not enough.  Every concrete LlamaIndex LLM
overrides ``chat``/``complete`` in its own module (``OpenAI.chat`` lives in
``llama_index.llms.openai.base``, ``CustomLLM.chat`` in
``llama_index.core.llms.custom``), so attribute lookup finds the override and
the governed base method is never reached — prompts went out ungoverned.
LlamaIndex's native instrumentation dispatcher is no help either: it emits the
events but swallows handler exceptions, so it can observe but cannot block.

So the override itself has to be wrapped.  :func:`patch_llamaindex` walks the
``LLM`` subclass tree and governs each override it finds, then installs an
``__init_subclass__`` hook so classes imported *after* ``auto_instrument()``
are governed as they are defined — which is the normal case, since the
documented usage puts ``aegis.auto_instrument()`` at the top of the file.

All LlamaIndex imports are deferred.  If ``llama-index-core`` is not
installed, :func:`patch_llamaindex` records a skip and returns cleanly.
"""

from __future__ import annotations

import contextlib
import functools
import logging
from typing import Any

from aegis.instrument._state import FrameworkPatch, InstrumentationState

logger = logging.getLogger("aegis.instrument.llamaindex")

_originals: dict[str, Any] = {}
_patched = False

# (cls, method name, _originals key) for every override we wrapped.
_patched_methods: list[tuple[type, str, str]] = []

# Marker set on our wrappers so a class is never double-wrapped.
_GOVERNED = "__aegis_governed__"

# Set when we install __init_subclass__ on the LLM root, so unpatch can undo it.
_subclass_hook: tuple[type, Any] | None = None


def _extract_chat_input(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
    """Extract text from LLM.chat messages argument."""
    messages = args[0] if args else kwargs.get("messages", [])
    if isinstance(messages, list):
        parts: list[str] = []
        for msg in messages:
            content = getattr(msg, "content", None)
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(msg, dict):
                c = msg.get("content", "")
                if isinstance(c, str):
                    parts.append(c)
        return "\n".join(parts)
    return str(messages) if messages else ""


def _extract_prompt(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
    """Extract text from LLM.complete prompt argument."""
    prompt = args[0] if args else kwargs.get("prompt", "")
    return prompt if isinstance(prompt, str) else str(prompt or "")


def _extract_chat_output(response: Any) -> str:
    """Extract text from ChatResponse."""
    message = getattr(response, "message", None)
    if message:
        content = getattr(message, "content", None)
        if isinstance(content, str):
            return content
    return ""


def _extract_completion_output(response: Any) -> str:
    """Extract text from CompletionResponse."""
    text = getattr(response, "text", None)
    return text if isinstance(text, str) else ""


def _extract_query_input(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
    """Extract text from QueryEngine.query input."""
    query = args[0] if args else kwargs.get("str_or_query_bundle", "")
    if isinstance(query, str):
        return query
    query_str = getattr(query, "query_str", None)
    return query_str if isinstance(query_str, str) else str(query or "")


def _extract_query_output(response: Any) -> str:
    """Extract text from query Response."""
    text = getattr(response, "response", None)
    return text if isinstance(text, str) else ""


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


def _make_governed(
    key: str,
    extract_input: Any,
    extract_output: Any,
    *,
    is_async: bool,
) -> Any:
    """Build a guardrail-enforcing wrapper around ``_originals[key]``.

    The original is looked up at call time rather than captured, so the
    wrapper keeps working if the entry is swapped out.
    """
    original = _originals[key]

    if is_async:

        @functools.wraps(original)
        async def governed(self: Any, *args: Any, **kwargs: Any) -> Any:
            s = InstrumentationState.get()
            engine = s.guardrail_engine

            input_text = extract_input(args, kwargs)
            _run_guardrails(engine, input_text, direction="input", on_block=s.on_block)

            response = await _originals[key](self, *args, **kwargs)

            output_text = extract_output(response)
            _run_guardrails(engine, output_text, direction="output", on_block=s.on_block)

            return response

    else:

        @functools.wraps(original)
        def governed(self: Any, *args: Any, **kwargs: Any) -> Any:
            s = InstrumentationState.get()
            engine = s.guardrail_engine

            input_text = extract_input(args, kwargs)
            _run_guardrails(engine, input_text, direction="input", on_block=s.on_block)

            response = _originals[key](self, *args, **kwargs)

            output_text = extract_output(response)
            _run_guardrails(engine, output_text, direction="output", on_block=s.on_block)

            return response

    setattr(governed, _GOVERNED, True)
    return governed


# method name -> (input extractor, output extractor, is_async)
_LLM_METHODS: dict[str, tuple[Any, Any, bool]] = {
    "chat": (_extract_chat_input, _extract_chat_output, False),
    "achat": (_extract_chat_input, _extract_chat_output, True),
    "complete": (_extract_prompt, _extract_completion_output, False),
    "acomplete": (_extract_prompt, _extract_completion_output, True),
}


def _govern_llm_class(cls: type, targets: list[str], *, is_root: bool) -> None:
    """Wrap this class's chat/complete methods, recording each for unpatch.

    On the root, inherited methods are wrapped too (they are what an LLM with
    no override of its own will call).  On subclasses only methods defined on
    the class itself are wrapped — anything inherited is already governed by
    whichever ancestor defined it.
    """
    for method, (extract_input, extract_output, is_async) in _LLM_METHODS.items():
        fn = getattr(cls, method, None) if is_root else cls.__dict__.get(method)
        if fn is None or getattr(fn, _GOVERNED, False):
            continue

        # The root keeps a stable "LLM.<method>" key regardless of the class's
        # own name; subclass keys are module-qualified so same-named LLMs from
        # different integration packages do not collide.
        key = f"LLM.{method}" if is_root else f"{cls.__module__}.{cls.__qualname__}.{method}"
        if key in _originals:
            continue

        _originals[key] = fn
        setattr(cls, method, _make_governed(key, extract_input, extract_output, is_async=is_async))
        _patched_methods.append((cls, method, key))
        targets.append(key)


def _walk_subclasses(root: type) -> list[type]:
    """Every subclass of ``root``, depth-first, each visited once."""
    seen: set[type] = set()
    order: list[type] = []
    stack: list[type] = list(root.__subclasses__())
    while stack:
        cls = stack.pop()
        if cls in seen:
            continue
        seen.add(cls)
        order.append(cls)
        try:
            stack.extend(cls.__subclasses__())
        except TypeError:  # pragma: no cover — non-class entries in the tree
            continue
    return order


def _install_subclass_hook(root: type) -> None:
    """Govern LLM subclasses defined after this point.

    LlamaIndex LLMs are Pydantic models, so the previous ``__init_subclass__``
    (Pydantic's, or an ancestor's) has to run first or model construction
    breaks.
    """
    global _subclass_hook  # noqa: PLW0603

    previous = root.__dict__.get("__init_subclass__")

    def __init_subclass__(cls: type, /, **kwargs: Any) -> None:
        if previous is not None:
            previous.__func__(cls, **kwargs)
        else:
            super(root, cls).__init_subclass__(**kwargs)  # type: ignore[arg-type]
        try:
            _govern_llm_class(cls, [], is_root=False)
        except Exception:  # pragma: no cover — never break class creation
            logger.debug("Failed to govern LLM subclass %s", cls, exc_info=True)

    root.__init_subclass__ = classmethod(__init_subclass__)  # type: ignore[assignment]
    _subclass_hook = (root, previous)


def patch_llamaindex() -> FrameworkPatch:
    """Patch LlamaIndex with Aegis governance.

    Wraps LLM chat/complete methods and BaseQueryEngine.query to apply
    guardrails to all LLM calls and RAG queries.

    Safe to call multiple times.

    Returns:
        A :class:`FrameworkPatch` describing what was patched.
    """
    global _patched  # noqa: PLW0603

    if _patched:
        return FrameworkPatch(name="llamaindex", patched=True, targets=list(_originals.keys()))

    targets: list[str] = []
    subclass_targets: list[str] = []

    # -- Patch LLM.chat / complete, on the base class and every override --
    try:
        from llama_index.core.llms import LLM

        _govern_llm_class(LLM, targets, is_root=True)

        for cls in _walk_subclasses(LLM):
            _govern_llm_class(cls, subclass_targets, is_root=False)
        targets.extend(subclass_targets)

        _install_subclass_hook(LLM)

        if subclass_targets:
            logger.debug(
                "Governed %d LLM subclass override(s): %s",
                len(subclass_targets),
                ", ".join(subclass_targets),
            )

    except ImportError:
        pass

    # -- Patch BaseQueryEngine.query / aquery ---------------------------
    try:
        from llama_index.core.base.base_query_engine import BaseQueryEngine

        _originals["BaseQueryEngine.query"] = BaseQueryEngine.query

        @functools.wraps(BaseQueryEngine.query)
        def governed_query(self: Any, *args: Any, **kwargs: Any) -> Any:
            s = InstrumentationState.get()
            engine = s.guardrail_engine

            input_text = _extract_query_input(args, kwargs)
            _run_guardrails(engine, input_text, direction="query_input", on_block=s.on_block)

            response = _originals["BaseQueryEngine.query"](self, *args, **kwargs)

            output_text = _extract_query_output(response)
            _run_guardrails(engine, output_text, direction="query_output", on_block=s.on_block)

            return response

        BaseQueryEngine.query = governed_query
        targets.append("BaseQueryEngine.query")

        _originals["BaseQueryEngine.aquery"] = BaseQueryEngine.aquery

        @functools.wraps(BaseQueryEngine.aquery)
        async def governed_aquery(self: Any, *args: Any, **kwargs: Any) -> Any:
            s = InstrumentationState.get()
            engine = s.guardrail_engine

            input_text = _extract_query_input(args, kwargs)
            _run_guardrails(engine, input_text, direction="query_input", on_block=s.on_block)

            response = await _originals["BaseQueryEngine.aquery"](self, *args, **kwargs)

            output_text = _extract_query_output(response)
            _run_guardrails(engine, output_text, direction="query_output", on_block=s.on_block)

            return response

        BaseQueryEngine.aquery = governed_aquery
        targets.append("BaseQueryEngine.aquery")

    except ImportError:
        pass

    if not targets:
        patch = FrameworkPatch(
            name="llamaindex",
            patched=False,
            error="llama-index-core not installed",
        )
    else:
        _patched = True
        patch = FrameworkPatch(name="llamaindex", patched=True, targets=targets)
        # The subclass overrides are listed at DEBUG — there can be dozens, and
        # naming each one here would bury the base targets.
        summary = [t for t in targets if t not in subclass_targets]
        if subclass_targets:
            summary.append(f"+{len(subclass_targets)} LLM subclass override(s)")
        logger.info("LlamaIndex instrumented: %s", ", ".join(summary))

    InstrumentationState.get().register_patch(patch)
    return patch


def unpatch_llamaindex() -> None:
    """Restore original LlamaIndex methods."""
    global _patched, _subclass_hook  # noqa: PLW0603

    if not _patched:
        return

    if _subclass_hook is not None:
        root, previous = _subclass_hook
        if previous is not None:
            root.__init_subclass__ = previous  # type: ignore[assignment]
        else:
            # Drop our override so the inherited __init_subclass__ applies again.
            with contextlib.suppress(AttributeError):
                del root.__init_subclass__  # type: ignore[misc]
        _subclass_hook = None

    for cls, method, key in reversed(_patched_methods):
        if key in _originals:
            setattr(cls, method, _originals.pop(key))
    _patched_methods.clear()

    try:
        from llama_index.core.base.base_query_engine import BaseQueryEngine

        for key in ["BaseQueryEngine.query", "BaseQueryEngine.aquery"]:
            if key in _originals:
                setattr(BaseQueryEngine, key.split(".")[1], _originals.pop(key))
    except ImportError:
        pass

    _originals.clear()
    _patched = False
    logger.info("LlamaIndex unpatched")
