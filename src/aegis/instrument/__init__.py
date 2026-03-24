"""Zero-code auto-instrumentation for AI agent frameworks.

Add governance to **any** AI framework project with a single line of
code — no refactoring required.  Supports 9 frameworks + raw API clients.

Quick start::

    # Option 1: One line — auto-detect and patch all installed frameworks
    import aegis.instrument

    # Option 2: Explicit control
    from aegis.instrument import auto_instrument
    auto_instrument(frameworks=["langchain", "litellm"], on_block="warn")

    # Option 3: Environment variable — zero code changes
    # AEGIS_INSTRUMENT=1 python my_agent.py

Per-framework functions::

    from aegis.instrument import patch_langchain, patch_litellm, ...
    patch_langchain()        # Only LangChain
    patch_litellm()          # Only LiteLLM
    patch_google_genai()     # Only Google GenAI (Gemini)
    patch_pydantic_ai()      # Only Pydantic AI
    patch_llamaindex()       # Only LlamaIndex
    patch_instructor()       # Only Instructor
    patch_dspy()             # Only DSPy
    patch_crewai()           # Only CrewAI
    patch_openai_agents()    # Only OpenAI Agents SDK

Also patches raw OpenAI/Anthropic API clients via the existing
:mod:`aegis.integrations` module.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

from aegis.instrument._crewai import patch_crewai, unpatch_crewai
from aegis.instrument._defaults import resolve_guardrails
from aegis.instrument._dspy import patch_dspy, unpatch_dspy
from aegis.instrument._google_genai import patch_google_genai, unpatch_google_genai
from aegis.instrument._instructor import patch_instructor, unpatch_instructor
from aegis.instrument._langchain import patch_langchain, unpatch_langchain
from aegis.instrument._litellm import patch_litellm, unpatch_litellm
from aegis.instrument._llamaindex import patch_llamaindex, unpatch_llamaindex
from aegis.instrument._openai_agents import (
    patch_openai_agents,
    unpatch_openai_agents,
)
from aegis.instrument._pydantic_ai import patch_pydantic_ai, unpatch_pydantic_ai
from aegis.instrument._state import FrameworkPatch, InstrumentationState

logger = logging.getLogger("aegis.instrument")

__all__ = [
    "auto_instrument",
    "InstrumentationReport",
    "patch_crewai",
    "patch_dspy",
    "patch_google_genai",
    "patch_instructor",
    "patch_langchain",
    "patch_litellm",
    "patch_llamaindex",
    "patch_openai_agents",
    "patch_pydantic_ai",
    "reset",
    "status",
    "unpatch_crewai",
    "unpatch_dspy",
    "unpatch_google_genai",
    "unpatch_instructor",
    "unpatch_langchain",
    "unpatch_litellm",
    "unpatch_llamaindex",
    "unpatch_openai_agents",
    "unpatch_pydantic_ai",
]

# All known frameworks and their patch/unpatch functions
_FRAMEWORK_REGISTRY: dict[str, tuple[Any, Any]] = {
    "langchain": (patch_langchain, unpatch_langchain),
    "crewai": (patch_crewai, unpatch_crewai),
    "openai_agents": (patch_openai_agents, unpatch_openai_agents),
    "litellm": (patch_litellm, unpatch_litellm),
    "google_genai": (patch_google_genai, unpatch_google_genai),
    "pydantic_ai": (patch_pydantic_ai, unpatch_pydantic_ai),
    "llamaindex": (patch_llamaindex, unpatch_llamaindex),
    "instructor": (patch_instructor, unpatch_instructor),
    "dspy": (patch_dspy, unpatch_dspy),
}


@dataclass(frozen=True)
class InstrumentationReport:
    """Summary of what was instrumented."""

    patched: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def any_patched(self) -> bool:
        """True if at least one framework was successfully patched."""
        return len(self.patched) > 0

    def __str__(self) -> str:
        parts: list[str] = []
        if self.patched:
            parts.append(f"Patched: {', '.join(self.patched)}")
        if self.skipped:
            parts.append(f"Skipped (not installed): {', '.join(self.skipped)}")
        if self.errors:
            errs = ", ".join(f"{k}: {v}" for k, v in self.errors.items())
            parts.append(f"Errors: {errs}")
        return "; ".join(parts) if parts else "No frameworks detected"


def auto_instrument(
    *,
    guardrails: Any = "default",
    on_block: str = "raise",
    audit: bool = True,
    frameworks: list[str] | None = None,
) -> InstrumentationReport:
    """Instrument all detected AI frameworks with Aegis governance.

    This is the main entry point. It:

    1. Builds a guardrail engine (injection + toxicity + PII + prompt leak).
    2. Detects which frameworks are installed.
    3. Monkey-patches their core methods to run guardrails on I/O.
    4. Also patches raw OpenAI/Anthropic clients.

    Args:
        guardrails: Guardrail configuration.
            ``"default"`` — use built-in guardrails (injection, toxicity,
            PII, prompt leak).
            ``"none"`` — no guardrails (audit only).
            A :class:`~aegis.guardrails.engine.GuardrailEngine` or list
            of guardrail instances — use those.
        on_block: What to do when a guardrail blocks:
            ``"raise"`` (default), ``"warn"``, or ``"log"``.
        audit: Whether to enable audit logging. Default ``True``.
        frameworks: Which frameworks to patch. ``None`` = auto-detect all.
            Valid names: ``"langchain"``, ``"crewai"``, ``"openai_agents"``,
            ``"litellm"``, ``"google_genai"``, ``"pydantic_ai"``,
            ``"llamaindex"``, ``"instructor"``, ``"dspy"``.

    Returns:
        An :class:`InstrumentationReport` summarizing what was patched.

    Example::

        from aegis.instrument import auto_instrument

        report = auto_instrument()
        print(report)  # "Patched: langchain, openai; Skipped: crewai"
    """
    state = InstrumentationState.get()

    # Build guardrail engine
    engine = resolve_guardrails(guardrails)
    state.configure(guardrail_engine=engine, on_block=on_block, audit=audit)

    # Determine which frameworks to patch
    targets = list(frameworks) if frameworks else list(_FRAMEWORK_REGISTRY.keys())

    patched: list[str] = []
    skipped: list[str] = []
    errors: dict[str, str] = {}

    for name in targets:
        if name not in _FRAMEWORK_REGISTRY:
            errors[name] = f"Unknown framework: {name!r}"
            continue

        patch_fn, _ = _FRAMEWORK_REGISTRY[name]
        try:
            result: FrameworkPatch = patch_fn()
            if result.patched:
                patched.append(name)
            else:
                skipped.append(name)
        except Exception as exc:
            errors[name] = str(exc)
            logger.warning("Failed to instrument %s: %s", name, exc)

    # Also patch raw OpenAI/Anthropic API clients
    _patch_raw_apis(engine=engine, on_block=on_block, audit=audit)

    report = InstrumentationReport(patched=patched, skipped=skipped, errors=errors)

    if report.any_patched:
        logger.info("Aegis auto-instrumentation complete: %s", report)
    else:
        logger.info("Aegis auto-instrumentation: no frameworks detected")

    return report


def _patch_raw_apis(*, engine: Any, on_block: str, audit: bool) -> None:
    """Patch raw OpenAI/Anthropic clients using existing integrations."""
    state = InstrumentationState.get()

    # OpenAI
    try:
        from aegis.integrations.patch_openai import patch_openai

        patch_openai(guardrails=engine, on_block=on_block, audit=audit)
        state.register_patch(
            FrameworkPatch(name="openai", patched=True, targets=["Completions.create"])
        )
    except ImportError:
        state.register_patch(
            FrameworkPatch(name="openai", patched=False, error="openai not installed")
        )
    except Exception as exc:
        state.register_patch(FrameworkPatch(name="openai", patched=False, error=str(exc)))

    # Anthropic
    try:
        from aegis.integrations.patch_anthropic import patch_anthropic

        patch_anthropic(guardrails=engine, on_block=on_block, audit=audit)
        state.register_patch(
            FrameworkPatch(name="anthropic", patched=True, targets=["Messages.create"])
        )
    except ImportError:
        state.register_patch(
            FrameworkPatch(name="anthropic", patched=False, error="anthropic not installed")
        )
    except Exception as exc:
        state.register_patch(FrameworkPatch(name="anthropic", patched=False, error=str(exc)))


def status() -> dict[str, Any]:
    """Return current instrumentation status.

    Returns:
        A dict with ``active``, ``frameworks``, and ``guardrails`` keys.

    Example::

        from aegis.instrument import status
        info = status()
        # {
        #     "active": True,
        #     "frameworks": {"langchain": {"patched": True, "targets": [...]}},
        #     "guardrails": 4,
        #     "on_block": "raise",
        # }
    """
    state = InstrumentationState.get()
    frameworks: dict[str, Any] = {}
    for name, patch in state.all_patches.items():
        frameworks[name] = {
            "patched": patch.patched,
            "targets": patch.targets,
            "error": patch.error,
        }

    engine = state.guardrail_engine
    guardrail_count = len(engine) if engine is not None and hasattr(engine, "__len__") else 0

    return {
        "active": state.active,
        "frameworks": frameworks,
        "guardrails": guardrail_count,
        "on_block": state.on_block,
        "audit": state.audit,
    }


def reset() -> None:
    """Unpatch all frameworks and reset instrumentation state.

    Restores all monkey-patched methods to their originals.
    """
    for name, (_, unpatch_fn) in _FRAMEWORK_REGISTRY.items():
        try:
            unpatch_fn()
        except Exception:
            logger.debug("Error unpatching %s", name, exc_info=True)

    # Unpatch raw APIs
    try:
        from aegis.integrations.patch_openai import unpatch_openai

        unpatch_openai()
    except Exception:
        pass

    try:
        from aegis.integrations.patch_anthropic import unpatch_anthropic

        unpatch_anthropic()
    except Exception:
        pass

    InstrumentationState.reset()
    logger.info("Aegis instrumentation reset")


# ---------------------------------------------------------------------------
# Auto-instrument on import if AEGIS_INSTRUMENT env var is set
# ---------------------------------------------------------------------------


def _maybe_auto_instrument() -> None:
    """Check env var and auto-instrument if requested."""
    env = os.environ.get("AEGIS_INSTRUMENT", "").lower()
    if env in ("1", "true", "yes", "on"):
        on_block = os.environ.get("AEGIS_ON_BLOCK", "raise")
        audit = os.environ.get("AEGIS_AUDIT", "true").lower() in ("1", "true", "yes")
        guardrails = os.environ.get("AEGIS_GUARDRAILS", "default")
        auto_instrument(guardrails=guardrails, on_block=on_block, audit=audit)


_maybe_auto_instrument()
