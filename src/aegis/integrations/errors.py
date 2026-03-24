"""Error types for Aegis integration layer."""

from __future__ import annotations

from typing import Any


class AegisBlockedError(Exception):
    """Raised when an action is blocked by Aegis governance.

    Attributes:
        reason: Human-readable explanation of why the action was blocked.
        decision: The :class:`~aegis.core.policy.PolicyDecision` that blocked
            the action, if available.
        guardrail_results: List of
            :class:`~aegis.guardrails.base.GuardrailResult` objects from
            guardrails that triggered the block.
    """

    def __init__(
        self,
        reason: str,
        decision: Any = None,
        guardrail_results: list[Any] | None = None,
    ) -> None:
        self.reason = reason
        self.decision = decision
        self.guardrail_results = guardrail_results or []
        super().__init__(reason)


class AegisGuardrailError(AegisBlockedError):
    """Raised when a guardrail blocks content.

    This is a specialization of :class:`AegisBlockedError` for cases where
    content guardrails (PII detection, injection detection, etc.) prevent
    an operation from proceeding.
    """
