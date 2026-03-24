"""Auto-instrumentation for LangChain.

Patches ``BaseChatModel.invoke/ainvoke`` and ``BaseTool.invoke/ainvoke``
so that every LLM call and tool call passes through Aegis guardrails —
with zero changes to user code.

All LangChain imports are deferred.  If ``langchain-core`` is not
installed, :func:`patch_langchain` records a skip and returns cleanly.
"""

from __future__ import annotations

import functools
import logging
from typing import Any

from aegis.instrument._state import FrameworkPatch, InstrumentationState

logger = logging.getLogger("aegis.instrument.langchain")

# Original methods stored for unpatch
_originals: dict[str, Any] = {}
_patched = False


def _extract_chat_input(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
    """Extract text from BaseChatModel.invoke input."""
    inp = args[0] if args else kwargs.get("input", "")
    if isinstance(inp, str):
        return inp
    if isinstance(inp, list):
        parts: list[str] = []
        for msg in inp:
            content = getattr(msg, "content", None)
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(msg, dict):
                c = msg.get("content", "")
                if isinstance(c, str):
                    parts.append(c)
        return "\n".join(parts)
    return str(inp)


def _extract_chat_output(response: Any) -> str:
    """Extract text from BaseChatModel response."""
    content = getattr(response, "content", None)
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


def patch_langchain() -> FrameworkPatch:
    """Patch LangChain's BaseChatModel and BaseTool with Aegis governance.

    Safe to call multiple times — subsequent calls are no-ops.

    Returns:
        A :class:`FrameworkPatch` describing what was patched.
    """
    global _patched  # noqa: PLW0603

    if _patched:
        return FrameworkPatch(name="langchain", patched=True, targets=list(_originals.keys()))

    targets: list[str] = []

    # -- Patch BaseChatModel ------------------------------------------
    try:
        from langchain_core.language_models.chat_models import BaseChatModel

        # Sync invoke
        _originals["BaseChatModel.invoke"] = BaseChatModel.invoke

        @functools.wraps(BaseChatModel.invoke)
        def governed_invoke(self: Any, *args: Any, **kwargs: Any) -> Any:
            s = InstrumentationState.get()
            engine = s.guardrail_engine

            # Input guardrail
            input_text = _extract_chat_input(args, kwargs)
            _run_guardrails(engine, input_text, direction="input", on_block=s.on_block)

            # Original call
            response = _originals["BaseChatModel.invoke"](self, *args, **kwargs)

            # Output guardrail
            output_text = _extract_chat_output(response)
            _run_guardrails(engine, output_text, direction="output", on_block=s.on_block)

            return response

        BaseChatModel.invoke = governed_invoke
        targets.append("BaseChatModel.invoke")

        # Async ainvoke
        _originals["BaseChatModel.ainvoke"] = BaseChatModel.ainvoke

        @functools.wraps(BaseChatModel.ainvoke)
        async def governed_ainvoke(self: Any, *args: Any, **kwargs: Any) -> Any:
            s = InstrumentationState.get()
            engine = s.guardrail_engine

            input_text = _extract_chat_input(args, kwargs)
            _run_guardrails(engine, input_text, direction="input", on_block=s.on_block)

            response = await _originals["BaseChatModel.ainvoke"](self, *args, **kwargs)

            output_text = _extract_chat_output(response)
            _run_guardrails(engine, output_text, direction="output", on_block=s.on_block)

            return response

        BaseChatModel.ainvoke = governed_ainvoke
        targets.append("BaseChatModel.ainvoke")

    except ImportError:
        pass  # langchain-core not installed

    # -- Patch BaseTool -----------------------------------------------
    try:
        from langchain_core.tools import BaseTool

        _originals["BaseTool.invoke"] = BaseTool.invoke

        @functools.wraps(BaseTool.invoke)
        def governed_tool_invoke(self: Any, *args: Any, **kwargs: Any) -> Any:
            s = InstrumentationState.get()
            engine = s.guardrail_engine

            # Check tool input
            tool_input = str(args[0]) if args else str(kwargs.get("input", ""))
            _run_guardrails(engine, tool_input, direction="tool_input", on_block=s.on_block)

            response = _originals["BaseTool.invoke"](self, *args, **kwargs)

            # Check tool output
            if isinstance(response, str):
                _run_guardrails(engine, response, direction="tool_output", on_block=s.on_block)

            return response

        BaseTool.invoke = governed_tool_invoke
        targets.append("BaseTool.invoke")

        # Async
        _originals["BaseTool.ainvoke"] = BaseTool.ainvoke

        @functools.wraps(BaseTool.ainvoke)
        async def governed_tool_ainvoke(self: Any, *args: Any, **kwargs: Any) -> Any:
            s = InstrumentationState.get()
            engine = s.guardrail_engine

            tool_input = str(args[0]) if args else str(kwargs.get("input", ""))
            _run_guardrails(engine, tool_input, direction="tool_input", on_block=s.on_block)

            response = await _originals["BaseTool.ainvoke"](self, *args, **kwargs)

            if isinstance(response, str):
                _run_guardrails(engine, response, direction="tool_output", on_block=s.on_block)

            return response

        BaseTool.ainvoke = governed_tool_ainvoke
        targets.append("BaseTool.ainvoke")

    except ImportError:
        pass

    if not targets:
        patch = FrameworkPatch(
            name="langchain",
            patched=False,
            error="langchain-core not installed",
        )
    else:
        _patched = True
        patch = FrameworkPatch(name="langchain", patched=True, targets=targets)
        logger.info("LangChain instrumented: %s", ", ".join(targets))

    InstrumentationState.get().register_patch(patch)
    return patch


def unpatch_langchain() -> None:
    """Restore original LangChain methods."""
    global _patched  # noqa: PLW0603

    if not _patched:
        return

    try:
        from langchain_core.language_models.chat_models import BaseChatModel

        if "BaseChatModel.invoke" in _originals:
            BaseChatModel.invoke = _originals.pop("BaseChatModel.invoke")
        if "BaseChatModel.ainvoke" in _originals:
            BaseChatModel.ainvoke = _originals.pop("BaseChatModel.ainvoke")
    except ImportError:
        pass

    try:
        from langchain_core.tools import BaseTool

        if "BaseTool.invoke" in _originals:
            BaseTool.invoke = _originals.pop("BaseTool.invoke")
        if "BaseTool.ainvoke" in _originals:
            BaseTool.ainvoke = _originals.pop("BaseTool.ainvoke")
    except ImportError:
        pass

    _originals.clear()
    _patched = False
    logger.info("LangChain unpatched")
