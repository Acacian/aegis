"""Guardrails subsystem for content inspection and transformation.

Provides base classes for building guardrails, concrete pattern/keyword
implementations, and an engine to orchestrate them as a pipeline.

Example::

    from aegis.guardrails import GuardrailEngine, PatternGuardrail

    engine = GuardrailEngine()
    engine.add(PatternGuardrail(
        name="ssn_detector",
        pattern=r"\\b\\d{3}-\\d{2}-\\d{4}\\b",
        action="mask",
    ))
    results, cleaned = engine.check_and_transform(user_input)
"""

from aegis.guardrails.base import Guardrail, GuardrailResult
from aegis.guardrails.engine import GuardrailEngine
from aegis.guardrails.injection import (
    InjectionGuardrail,
    InjectionGuardrailResult,
    InjectionMatch,
)
from aegis.guardrails.pattern import KeywordGuardrail, PatternGuardrail

__all__ = [
    "Guardrail",
    "GuardrailEngine",
    "GuardrailResult",
    "InjectionGuardrail",
    "InjectionGuardrailResult",
    "InjectionMatch",
    "KeywordGuardrail",
    "PatternGuardrail",
]
