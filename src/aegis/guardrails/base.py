"""Base guardrail classes for content inspection and transformation.

Guardrails inspect content (prompts, responses, tool calls) and decide
whether to allow, block, mask, or warn.  Concrete implementations
subclass :class:`Guardrail` and implement ``check`` / ``check_and_transform``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class GuardrailResult:
    """Result of a guardrail check.

    Attributes:
        passed: Whether the content passed the guardrail (no violation found).
        guardrail_name: Name of the guardrail that produced this result.
        action: Disposition — one of ``"allowed"``, ``"blocked"``,
            ``"masked"``, or ``"warned"``.
        details: Optional human-readable explanation of the result.
        masked_content: The content after masking, when *action* is ``"masked"``.
        original_content: The original content before masking.
        severity: Severity of the finding — ``"low"``, ``"medium"``,
            ``"high"``, or ``"critical"``.
    """

    passed: bool
    guardrail_name: str
    action: str  # "allowed", "blocked", "masked", "warned"
    details: str | None = None
    masked_content: str | None = None
    original_content: str | None = None
    severity: str = "medium"


class Guardrail(ABC):
    """Base class for all guardrails.

    Subclasses must implement :meth:`check` (inspect only) and
    :meth:`check_and_transform` (inspect + optionally rewrite content).

    Attributes:
        name: Unique identifier for this guardrail.
        description: Human-readable description of what this guardrail checks.
        severity: Default severity for findings — ``"low"``, ``"medium"``,
            ``"high"``, or ``"critical"``.
        requires_full_buffer: When ``True``, streaming engines must buffer
            the entire response before running this guardrail.  Use this
            for guardrails where partial exposure is a violation (e.g. PII
            detection).  Default ``False``.
    """

    name: str
    description: str
    severity: str
    requires_full_buffer: bool

    def __init__(
        self,
        name: str,
        description: str = "",
        severity: str = "medium",
        *,
        requires_full_buffer: bool = False,
    ) -> None:
        self.name = name
        self.description = description
        self.severity = severity
        self.requires_full_buffer = requires_full_buffer

    @abstractmethod
    def check(
        self,
        content: str,
        *,
        context: dict[str, object] | None = None,
    ) -> GuardrailResult:
        """Inspect *content* and return a result.

        This is a read-only check — the content is never modified.

        Args:
            content: The text to inspect.
            context: Optional metadata (user id, session, etc.) that
                concrete guardrails may use.
        """

    @abstractmethod
    def check_and_transform(
        self,
        content: str,
        *,
        context: dict[str, object] | None = None,
    ) -> tuple[GuardrailResult, str]:
        """Inspect *content* and optionally transform it.

        Returns a ``(result, transformed_content)`` tuple.  When no
        transformation is needed, *transformed_content* is the original
        *content* unchanged.

        Args:
            content: The text to inspect and potentially transform.
            context: Optional metadata for the check.
        """

    def __repr__(self) -> str:
        return f"{type(self).__name__}(name={self.name!r}, severity={self.severity!r})"
