"""Auto-instrumentation for LlamaIndex.

Patches ``LLM.chat/complete`` and ``BaseQueryEngine.query`` so that
every LLM call and RAG query passes through Aegis guardrails —
with zero changes to user code.

All LlamaIndex imports are deferred.  If ``llama-index-core`` is not
installed, :func:`patch_llamaindex` records a skip and returns cleanly.
"""

from __future__ import annotations

import functools
import logging
from typing import Any

from aegis.instrument._state import FrameworkPatch, InstrumentationState

logger = logging.getLogger("aegis.instrument.llamaindex")

_originals: dict[str, Any] = {}
_patched = False


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

    # -- Patch LLM.chat / LLM.achat ------------------------------------
    try:
        from llama_index.core.llms import LLM

        _originals["LLM.chat"] = LLM.chat

        @functools.wraps(LLM.chat)
        def governed_chat(self: Any, *args: Any, **kwargs: Any) -> Any:
            s = InstrumentationState.get()
            engine = s.guardrail_engine

            input_text = _extract_chat_input(args, kwargs)
            _run_guardrails(engine, input_text, direction="input", on_block=s.on_block)

            response = _originals["LLM.chat"](self, *args, **kwargs)

            output_text = _extract_chat_output(response)
            _run_guardrails(engine, output_text, direction="output", on_block=s.on_block)

            return response

        LLM.chat = governed_chat
        targets.append("LLM.chat")

        # Async
        _originals["LLM.achat"] = LLM.achat

        @functools.wraps(LLM.achat)
        async def governed_achat(self: Any, *args: Any, **kwargs: Any) -> Any:
            s = InstrumentationState.get()
            engine = s.guardrail_engine

            input_text = _extract_chat_input(args, kwargs)
            _run_guardrails(engine, input_text, direction="input", on_block=s.on_block)

            response = await _originals["LLM.achat"](self, *args, **kwargs)

            output_text = _extract_chat_output(response)
            _run_guardrails(engine, output_text, direction="output", on_block=s.on_block)

            return response

        LLM.achat = governed_achat
        targets.append("LLM.achat")

        # -- Patch LLM.complete / LLM.acomplete -------------------------
        _originals["LLM.complete"] = LLM.complete

        @functools.wraps(LLM.complete)
        def governed_complete(self: Any, *args: Any, **kwargs: Any) -> Any:
            s = InstrumentationState.get()
            engine = s.guardrail_engine

            input_text = _extract_prompt(args, kwargs)
            _run_guardrails(engine, input_text, direction="input", on_block=s.on_block)

            response = _originals["LLM.complete"](self, *args, **kwargs)

            output_text = _extract_completion_output(response)
            _run_guardrails(engine, output_text, direction="output", on_block=s.on_block)

            return response

        LLM.complete = governed_complete
        targets.append("LLM.complete")

        _originals["LLM.acomplete"] = LLM.acomplete

        @functools.wraps(LLM.acomplete)
        async def governed_acomplete(self: Any, *args: Any, **kwargs: Any) -> Any:
            s = InstrumentationState.get()
            engine = s.guardrail_engine

            input_text = _extract_prompt(args, kwargs)
            _run_guardrails(engine, input_text, direction="input", on_block=s.on_block)

            response = await _originals["LLM.acomplete"](self, *args, **kwargs)

            output_text = _extract_completion_output(response)
            _run_guardrails(engine, output_text, direction="output", on_block=s.on_block)

            return response

        LLM.acomplete = governed_acomplete
        targets.append("LLM.acomplete")

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
        logger.info("LlamaIndex instrumented: %s", ", ".join(targets))

    InstrumentationState.get().register_patch(patch)
    return patch


def unpatch_llamaindex() -> None:
    """Restore original LlamaIndex methods."""
    global _patched  # noqa: PLW0603

    if not _patched:
        return

    try:
        from llama_index.core.llms import LLM

        for key in ["LLM.chat", "LLM.achat", "LLM.complete", "LLM.acomplete"]:
            if key in _originals:
                setattr(LLM, key.split(".")[1], _originals.pop(key))
    except ImportError:
        pass

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
