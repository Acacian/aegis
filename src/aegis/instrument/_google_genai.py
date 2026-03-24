"""Auto-instrumentation for Google GenAI SDK (Gemini).

Patches ``Models.generate_content`` in the new ``google-genai`` SDK
and ``GenerativeModel.generate_content`` in the legacy
``google-generativeai`` SDK so that every Gemini call passes through
Aegis guardrails — with zero changes to user code.

All Google imports are deferred.  If neither SDK is installed,
:func:`patch_google_genai` records a skip and returns cleanly.
"""

from __future__ import annotations

import functools
import logging
from typing import Any

from aegis.instrument._state import FrameworkPatch, InstrumentationState

logger = logging.getLogger("aegis.instrument.google_genai")

_originals: dict[str, Any] = {}
_patched = False


def _extract_contents(kwargs: dict[str, Any]) -> str:
    """Extract text from generate_content arguments."""
    contents = kwargs.get("contents", "")
    if isinstance(contents, str):
        return contents
    if isinstance(contents, list):
        parts: list[str] = []
        for item in contents:
            if isinstance(item, str):
                parts.append(item)
            elif hasattr(item, "text"):
                parts.append(str(item.text))
            elif isinstance(item, dict):
                t = item.get("text", "")
                if isinstance(t, str):
                    parts.append(t)
        return "\n".join(parts)
    return str(contents) if contents else ""


def _extract_response_text(response: Any) -> str:
    """Extract text from a GenerateContentResponse."""
    # New SDK: response.text
    text = getattr(response, "text", None)
    if isinstance(text, str):
        return text
    # Legacy SDK: response.candidates[0].content.parts[0].text
    candidates = getattr(response, "candidates", None)
    if candidates and len(candidates) > 0:
        content = getattr(candidates[0], "content", None)
        if content:
            parts = getattr(content, "parts", [])
            if parts and hasattr(parts[0], "text"):
                return str(parts[0].text)
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


def patch_google_genai() -> FrameworkPatch:
    """Patch Google GenAI SDKs with Aegis governance.

    Supports both the new ``google-genai`` SDK and the legacy
    ``google-generativeai`` SDK.

    Safe to call multiple times.

    Returns:
        A :class:`FrameworkPatch` describing what was patched.
    """
    global _patched  # noqa: PLW0603

    if _patched:
        return FrameworkPatch(name="google_genai", patched=True, targets=list(_originals.keys()))

    targets: list[str] = []

    # -- New SDK: google.genai ------------------------------------------
    try:
        from google.genai import models as genai_models

        Models = genai_models.Models

        _originals["Models.generate_content"] = Models.generate_content

        @functools.wraps(Models.generate_content)
        def governed_generate(self: Any, *args: Any, **kwargs: Any) -> Any:
            s = InstrumentationState.get()
            engine = s.guardrail_engine

            input_text = _extract_contents(kwargs)
            _run_guardrails(engine, input_text, direction="input", on_block=s.on_block)

            response = _originals["Models.generate_content"](self, *args, **kwargs)

            output_text = _extract_response_text(response)
            _run_guardrails(engine, output_text, direction="output", on_block=s.on_block)

            return response

        Models.generate_content = governed_generate
        targets.append("Models.generate_content")

    except ImportError:
        pass

    # -- Legacy SDK: google.generativeai --------------------------------
    try:
        from google.generativeai import GenerativeModel

        if "GenerativeModel.generate_content" not in _originals:
            _originals["GenerativeModel.generate_content"] = GenerativeModel.generate_content

            @functools.wraps(GenerativeModel.generate_content)
            def governed_legacy_generate(self: Any, *args: Any, **kwargs: Any) -> Any:
                s = InstrumentationState.get()
                engine = s.guardrail_engine

                # Legacy SDK: first positional arg is contents
                contents = args[0] if args else kwargs.get("contents", "")
                input_text = contents if isinstance(contents, str) else str(contents or "")
                _run_guardrails(engine, input_text, direction="input", on_block=s.on_block)

                response = _originals["GenerativeModel.generate_content"](self, *args, **kwargs)

                output_text = _extract_response_text(response)
                _run_guardrails(engine, output_text, direction="output", on_block=s.on_block)

                return response

            GenerativeModel.generate_content = governed_legacy_generate
            targets.append("GenerativeModel.generate_content")

    except ImportError:
        pass

    if not targets:
        patch = FrameworkPatch(
            name="google_genai",
            patched=False,
            error="google-genai/google-generativeai not installed",
        )
    else:
        _patched = True
        patch = FrameworkPatch(name="google_genai", patched=True, targets=targets)
        logger.info("Google GenAI instrumented: %s", ", ".join(targets))

    InstrumentationState.get().register_patch(patch)
    return patch


def unpatch_google_genai() -> None:
    """Restore original Google GenAI methods."""
    global _patched  # noqa: PLW0603

    if not _patched:
        return

    try:
        from google.genai import models as genai_models

        Models = genai_models.Models
        if "Models.generate_content" in _originals:
            Models.generate_content = _originals.pop("Models.generate_content")
    except ImportError:
        pass

    try:
        from google.generativeai import GenerativeModel

        if "GenerativeModel.generate_content" in _originals:
            GenerativeModel.generate_content = _originals.pop("GenerativeModel.generate_content")
    except ImportError:
        pass

    _originals.clear()
    _patched = False
    logger.info("Google GenAI unpatched")
