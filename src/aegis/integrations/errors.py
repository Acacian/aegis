"""Error types for Aegis integration layer."""

from __future__ import annotations

from typing import Any


class AegisError(Exception):
    """Base exception for all Aegis errors.

    All Aegis-specific exceptions inherit from this class, making it
    possible to catch any Aegis error with a single ``except AegisError``.
    """


class AegisBlockedError(AegisError):
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


class AegisPolicyError(AegisError):
    """Raised when a policy is malformed or cannot be evaluated.

    Examples: invalid YAML, unknown rule type, circular rule references.
    """


class AegisConfigError(AegisError):
    """Raised when Aegis configuration is invalid or incomplete.

    Examples: missing required fields, invalid parameter values,
    incompatible option combinations.
    """


class AegisConnectionError(AegisError):
    """Raised when communication with the Aegis server fails.

    Wraps network errors, timeouts, and authentication failures
    when using :class:`~aegis.client.AegisClient`.
    """


class AegisApprovalTimeout(AegisError):
    """Raised when an approval request times out.

    The approval handler did not receive a response within the
    configured timeout period.
    """


class AegisExecutionError(AegisError):
    """Raised when action execution fails within the governance pipeline.

    Wraps errors from :class:`~aegis.adapters.base.BaseExecutor`
    implementations.
    """


class AegisAuditError(AegisError):
    """Raised when audit logging fails critically.

    Non-critical audit failures are logged as warnings; this exception
    is reserved for cases where audit integrity is compromised
    (e.g. database corruption, unrecoverable write failure).
    """
