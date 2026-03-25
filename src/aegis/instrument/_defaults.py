"""Default guardrail configuration for auto-instrumentation.

Builds a :class:`~aegis.guardrails.engine.GuardrailEngine` with a
sensible set of guardrails that cover the most common risks:

- Prompt injection detection
- PII detection (masking mode)
- Toxicity detection
- Prompt leakage detection

All guardrails are deterministic (no LLM calls) and lightweight.

Standalone guardrails (ToxicityGuardrail, PromptLeakGuardrail) don't
implement the :class:`~aegis.guardrails.base.Guardrail` ABC, so we
wrap them via :class:`_StandaloneAdapter` to make them compatible with
:class:`~aegis.guardrails.engine.GuardrailEngine`.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("aegis.instrument")


class _StandaloneAdapter:
    """Adapt a standalone guardrail to the GuardrailEngine interface.

    Standalone guardrails (toxicity, hallucination, prompt_leak, cot)
    have ``check(content) -> Result`` without ``context`` kwarg and
    without ``check_and_transform``.  This adapter bridges the gap.
    """

    def __init__(self, inner: Any, name: str) -> None:
        self._inner = inner
        self.name = name
        self.description = name
        self.severity = getattr(inner, "severity", "medium")

    def check(self, content: str, *, context: dict[str, object] | None = None) -> Any:
        from aegis.guardrails.base import GuardrailResult

        result = self._inner.check(content)

        # Normalize different result shapes:
        # - InjectionGuardrailResult has .passed, .action
        # - ToxicityResult has .passed, .action
        # - PromptLeakResult has .passed, .action
        # - PII CheckResult has .detected (no .passed, no .action)
        passed = getattr(result, "passed", None)
        if passed is None:
            # PII-style: detected=True means NOT passed
            passed = not getattr(result, "detected", False)

        action = getattr(result, "action", None)
        if action is None:
            # Derive action from the inner guardrail's configured action
            inner_action = getattr(self._inner, "action", "warn")
            action = (
                "allowed"
                if passed
                else (inner_action + "ed" if inner_action != "log" else "allowed")
            )

        return GuardrailResult(
            passed=passed,
            guardrail_name=self.name,
            action=action,
            details=getattr(result, "details", None),
            severity=getattr(result, "severity", self.severity),
        )

    def check_and_transform(
        self, content: str, *, context: dict[str, object] | None = None
    ) -> tuple[Any, str]:
        result = self.check(content, context=context)
        return result, content


def build_default_engine() -> Any:
    """Build a GuardrailEngine with production-safe defaults.

    Returns ``None`` if guardrail modules are not available (should not
    happen in a normal install, but guards against partial installs).
    """
    try:
        from aegis.guardrails.engine import GuardrailEngine
        from aegis.guardrails.injection import InjectionGuardrail
        from aegis.guardrails.pii import PIIGuardrail
        from aegis.guardrails.prompt_leak import PromptLeakGuardrail
        from aegis.guardrails.toxicity import ToxicityGuardrail

        engine = GuardrailEngine(
            guardrails=[
                InjectionGuardrail(action="block", sensitivity="medium"),  # type: ignore[list-item]
                _StandaloneAdapter(  # type: ignore[list-item]
                    ToxicityGuardrail(action="warn", sensitivity="medium"),
                    name="toxicity",
                ),
                _StandaloneAdapter(  # type: ignore[list-item]
                    PIIGuardrail(action="warn"),
                    name="pii",
                ),
                _StandaloneAdapter(  # type: ignore[list-item]
                    PromptLeakGuardrail(action="warn", sensitivity="medium"),
                    name="prompt_leak",
                ),
            ]
        )
        logger.debug("Built default guardrail engine with %d guardrails", len(engine))
        return engine
    except Exception:
        logger.warning("Could not build default guardrail engine", exc_info=True)
        return None


def resolve_guardrails(guardrails: Any) -> Any:
    """Normalize a guardrails argument into a GuardrailEngine or None.

    Accepts:
    - ``"default"`` or ``None`` → build default engine
    - A ``GuardrailEngine`` instance → use as-is
    - A list of guardrail instances → wrap in engine
    - ``"none"`` → no guardrails
    """
    if guardrails == "none":
        return None

    if guardrails is None or guardrails == "default":
        return build_default_engine()

    try:
        from aegis.guardrails.engine import GuardrailEngine
    except ImportError:
        return None

    if isinstance(guardrails, GuardrailEngine):
        return guardrails

    if isinstance(guardrails, list):
        return GuardrailEngine(guardrails=guardrails)

    # Single guardrail
    return GuardrailEngine(guardrails=[guardrails])
