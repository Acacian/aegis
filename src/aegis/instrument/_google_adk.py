"""Auto-instrumentation for Google Agent Development Kit (ADK).

Provides :class:`AegisPlugin` — a native ADK ``BasePlugin`` that integrates
governance at the framework level, not the raw genai SDK level.

Two usage modes:

1. **Direct** (recommended)::

       from aegis.instrument._google_adk import AegisPlugin
       app = App(agent=root_agent, plugins=[AegisPlugin()])

2. **Auto-instrument**::

       from aegis.instrument import auto_instrument
       auto_instrument(frameworks=["google_adk"])
       # Patches Runner.__init__ to auto-inject AegisPlugin

Governs ADK-level constructs:

- **Tool calls** — before/after hooks with guardrails on tool args and results
- **Model calls** — input/output guardrails on LLM request/response content
- **Agent invocations** — audit logging for agent lifecycle
- **Events** — audit trail for state deltas and agent transfers

All Google ADK imports are deferred.  If ``google-adk`` is not installed,
:func:`patch_google_adk` records a skip and returns cleanly.
"""

from __future__ import annotations

import functools
import logging
from typing import Any

from aegis.instrument._state import FrameworkPatch, InstrumentationState

logger = logging.getLogger("aegis.instrument.google_adk")

_originals: dict[str, Any] = {}
_patched = False

# ---------------------------------------------------------------------------
# Conditional BasePlugin import
# ---------------------------------------------------------------------------

try:
    from google.adk.plugins.base_plugin import BasePlugin as _BasePlugin
except ImportError:
    _BasePlugin = object  # type: ignore[misc,assignment]


# ---------------------------------------------------------------------------
# Text extraction helpers
# ---------------------------------------------------------------------------


def _extract_llm_request_text(llm_request: Any) -> str:
    """Extract text from an ADK ``LlmRequest``.

    Walks ``llm_request.contents`` (list of Content) and collects text parts.
    Also checks ``config.system_instruction`` if present.
    """
    parts: list[str] = []

    contents = getattr(llm_request, "contents", None) or []
    for content in contents:
        for part in getattr(content, "parts", []):
            text = getattr(part, "text", None)
            if text:
                parts.append(text)

    config = getattr(llm_request, "config", None)
    if config:
        sys_inst = getattr(config, "system_instruction", None)
        if sys_inst and isinstance(sys_inst, str):
            parts.append(sys_inst)

    return "\n".join(parts)


def _extract_llm_response_text(llm_response: Any) -> str:
    """Extract text from an ADK ``LlmResponse``.

    Walks ``llm_response.content.parts`` for text.
    """
    content = getattr(llm_response, "content", None)
    if content:
        for part in getattr(content, "parts", []):
            text = getattr(part, "text", None)
            if text:
                return str(text)
    return ""


def _extract_tool_text(tool: Any, args: Any) -> str:
    """Build a text representation of a tool call for guardrail checks."""
    tool_name = getattr(tool, "name", None) or str(tool)
    if args:
        return f"{tool_name}: {args}"
    return tool_name


# ---------------------------------------------------------------------------
# Shared guardrail runner (same pattern as other adapters)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# AegisPlugin
# ---------------------------------------------------------------------------


class AegisPlugin(_BasePlugin):  # type: ignore[misc]
    """Aegis governance plugin for Google ADK.

    Implements the ADK ``BasePlugin`` interface to provide guardrails at
    every stage of the agent lifecycle::

        from aegis.instrument._google_adk import AegisPlugin
        from google.adk import App

        plugin = AegisPlugin()  # uses default guardrails
        app = App(agent=root_agent, plugins=[plugin])

    Args:
        guardrails: Custom guardrail engine.  ``None`` = use the shared
            engine from :func:`auto_instrument` or the default engine.
        on_block: ``"raise"`` (default), ``"warn"``, or ``"log"``.
            ``None`` = inherit from InstrumentationState.
        audit: Enable audit logging for ADK events.
    """

    def __init__(
        self,
        *,
        guardrails: Any = None,
        on_block: str | None = None,
        audit: bool = True,
    ) -> None:
        if _BasePlugin is not object:
            super().__init__(name="aegis")
        self._guardrails = guardrails
        self._on_block = on_block
        self._audit = audit

    @property
    def name(self) -> str:  # type: ignore[override]
        return "aegis"

    def _get_engine(self) -> Any:
        if self._guardrails is not None:
            return self._guardrails
        return InstrumentationState.get().guardrail_engine

    @property
    def _effective_on_block(self) -> str:
        if self._on_block is not None:
            return self._on_block
        s = InstrumentationState.get()
        return s.on_block if s.active else "raise"

    # -- Model callbacks ---------------------------------------------------

    async def before_model_callback(
        self, *, callback_context: Any, llm_request: Any, **kw: Any
    ) -> Any:
        """Run input guardrails on LLM request content."""
        engine = self._get_engine()
        text = _extract_llm_request_text(llm_request)
        _run_guardrails(engine, text, direction="input", on_block=self._effective_on_block)
        return None  # continue normal flow

    async def after_model_callback(
        self, *, callback_context: Any, llm_response: Any, **kw: Any
    ) -> Any:
        """Run output guardrails on LLM response content."""
        engine = self._get_engine()
        text = _extract_llm_response_text(llm_response)
        _run_guardrails(engine, text, direction="output", on_block=self._effective_on_block)
        return None

    # -- Tool callbacks ----------------------------------------------------

    async def before_tool_callback(
        self, *, tool: Any, args: Any, tool_context: Any, **kw: Any
    ) -> Any:
        """Run guardrails on tool call arguments."""
        engine = self._get_engine()
        text = _extract_tool_text(tool, args)
        _run_guardrails(engine, text, direction="tool_input", on_block=self._effective_on_block)
        return None

    async def after_tool_callback(
        self, *, tool: Any, args: Any, tool_context: Any, tool_response: Any, **kw: Any
    ) -> Any:
        """Run guardrails on tool call results."""
        engine = self._get_engine()
        text = str(tool_response) if tool_response else ""
        _run_guardrails(engine, text, direction="tool_output", on_block=self._effective_on_block)
        return None

    # -- Agent callbacks ---------------------------------------------------

    async def before_agent_callback(self, *, callback_context: Any, **kw: Any) -> Any:
        """Audit agent invocation start."""
        if self._audit:
            agent = getattr(callback_context, "agent", None)
            agent_name = getattr(agent, "name", "unknown") if agent else "unknown"
            logger.debug("ADK agent invoked: %s", agent_name)
        return None

    async def after_agent_callback(self, *, callback_context: Any, **kw: Any) -> Any:
        """Audit agent invocation completion."""
        if self._audit:
            agent = getattr(callback_context, "agent", None)
            agent_name = getattr(agent, "name", "unknown") if agent else "unknown"
            logger.debug("ADK agent completed: %s", agent_name)
        return None

    # -- Event callback ----------------------------------------------------

    async def on_event_callback(self, *, event: Any, callback_context: Any, **kw: Any) -> Any:
        """Audit ADK events (state deltas, agent transfers, auth requests)."""
        if self._audit:
            actions = getattr(event, "actions", None)
            if actions:
                # Log agent transfers
                transfer = getattr(actions, "transfer_to_agent", None)
                if transfer:
                    logger.info("ADK agent transfer → %s", transfer)
                # Log state deltas
                state_delta = getattr(actions, "state_delta", None)
                if state_delta:
                    logger.debug("ADK state delta: %d keys", len(state_delta))
        return None


# ---------------------------------------------------------------------------
# Patch / Unpatch for auto_instrument
# ---------------------------------------------------------------------------


def patch_google_adk() -> FrameworkPatch:
    """Patch Google ADK with Aegis governance.

    Monkey-patches ``Runner.__init__`` to auto-inject :class:`AegisPlugin`
    into any ``App`` that doesn't already have it.

    Safe to call multiple times.

    Returns:
        A :class:`FrameworkPatch` describing what was patched.
    """
    global _patched  # noqa: PLW0603

    if _patched:
        return FrameworkPatch(name="google_adk", patched=True, targets=list(_originals.keys()))

    targets: list[str] = []

    # -- Patch Runner.__init__ to auto-inject AegisPlugin ------------------
    try:
        from google.adk.runners import Runner

        _originals["Runner.__init__"] = Runner.__init__

        @functools.wraps(Runner.__init__)
        def governed_runner_init(self: Any, *args: Any, **kwargs: Any) -> None:
            _originals["Runner.__init__"](self, *args, **kwargs)

            # Find the app (could be attribute or argument)
            app = getattr(self, "_app", None) or getattr(self, "app", None)
            if app is None:
                # Try first positional arg or kwarg
                app = args[0] if args else kwargs.get("app")

            if app is None:
                return

            plugins = getattr(app, "plugins", None) or []
            if any(getattr(p, "name", None) == "aegis" for p in plugins):
                return  # already injected

            state = InstrumentationState.get()
            plugin = AegisPlugin(
                guardrails=state.guardrail_engine,
                on_block=state.on_block,
                audit=state.audit,
            )

            if hasattr(app, "plugins") and app.plugins is not None:
                app.plugins.append(plugin)
            else:
                try:
                    app.plugins = [plugin]
                except (AttributeError, TypeError):
                    logger.debug("Cannot inject AegisPlugin into app.plugins")

        Runner.__init__ = governed_runner_init  # type: ignore[assignment]
        targets.append("Runner.__init__")

    except ImportError:
        pass

    if not targets:
        patch = FrameworkPatch(
            name="google_adk",
            patched=False,
            error="google-adk not installed",
        )
    else:
        _patched = True
        patch = FrameworkPatch(name="google_adk", patched=True, targets=targets)
        logger.info("Google ADK instrumented: %s", ", ".join(targets))

    InstrumentationState.get().register_patch(patch)
    return patch


def unpatch_google_adk() -> None:
    """Restore original Google ADK methods."""
    global _patched  # noqa: PLW0603

    if not _patched:
        return

    try:
        from google.adk.runners import Runner

        if "Runner.__init__" in _originals:
            Runner.__init__ = _originals.pop("Runner.__init__")  # type: ignore[assignment]
    except ImportError:
        pass

    _originals.clear()
    _patched = False
    logger.info("Google ADK unpatched")
