"""Pattern-based and keyword-based guardrail implementations.

These are the concrete guardrails that :class:`Pack` rules compile into.
Each rule type (``"pattern"``, ``"keyword"``) has a corresponding class.
"""

from __future__ import annotations

import re

from aegis.guardrails.base import Guardrail, GuardrailResult


class PatternGuardrail(Guardrail):
    """Guardrail that matches content against a regex pattern.

    When the pattern matches:
    - ``action="block"`` → the content is blocked.
    - ``action="mask"``  → matched spans are replaced with ``***``.
    - ``action="warn"``  → a warning result is returned but content passes.
    - ``action="log"``   → content passes, result is informational.

    Args:
        name: Unique identifier.
        pattern: Regular expression string.
        action: Disposition on match — ``"block"``, ``"mask"``,
            ``"warn"``, or ``"log"``.
        severity: Severity of a finding.
        description: Human-readable description.
        mask_replacement: Text used to replace matched spans when
            *action* is ``"mask"``. Defaults to ``"***"``.
    """

    def __init__(
        self,
        name: str,
        pattern: str,
        action: str = "block",
        severity: str = "medium",
        description: str = "",
        mask_replacement: str = "***",
    ) -> None:
        super().__init__(name=name, description=description, severity=severity)
        self.pattern = pattern
        self.action_type = action
        self.mask_replacement = mask_replacement
        self._compiled: re.Pattern[str] = re.compile(pattern, re.IGNORECASE)

    def check(
        self,
        content: str,
        *,
        context: dict[str, object] | None = None,
    ) -> GuardrailResult:
        """Check *content* against the pattern."""
        match = self._compiled.search(content)
        if match is None:
            return GuardrailResult(
                passed=True,
                guardrail_name=self.name,
                action="allowed",
                severity=self.severity,
            )

        action_label = self._action_label()
        return GuardrailResult(
            passed=action_label in ("warned", "allowed", "masked"),
            guardrail_name=self.name,
            action=action_label,
            details=f"Pattern matched: {match.group()!r}",
            severity=self.severity,
        )

    def check_and_transform(
        self,
        content: str,
        *,
        context: dict[str, object] | None = None,
    ) -> tuple[GuardrailResult, str]:
        """Check *content* and apply masking if configured."""
        match = self._compiled.search(content)
        if match is None:
            return (
                GuardrailResult(
                    passed=True,
                    guardrail_name=self.name,
                    action="allowed",
                    severity=self.severity,
                ),
                content,
            )

        action_label = self._action_label()

        if self.action_type == "mask":
            masked = self._compiled.sub(self.mask_replacement, content)
            result = GuardrailResult(
                passed=True,
                guardrail_name=self.name,
                action="masked",
                details=f"Pattern matched and masked: {match.group()!r}",
                masked_content=masked,
                original_content=content,
                severity=self.severity,
            )
            return result, masked

        result = GuardrailResult(
            passed=action_label in ("warned", "allowed", "masked"),
            guardrail_name=self.name,
            action=action_label,
            details=f"Pattern matched: {match.group()!r}",
            severity=self.severity,
        )
        return result, content

    def _action_label(self) -> str:
        """Map the configured action type to a result action label."""
        mapping = {
            "block": "blocked",
            "mask": "masked",
            "warn": "warned",
            "log": "allowed",
        }
        return mapping.get(self.action_type, "blocked")


class KeywordGuardrail(Guardrail):
    """Guardrail that matches content against a list of keywords.

    Keyword matching is case-insensitive and uses word boundaries to
    avoid false positives (e.g. ``"drop"`` won't match ``"raindrop"``).

    Args:
        name: Unique identifier.
        keywords: List of keywords to match.
        action: Disposition on match — ``"block"``, ``"mask"``,
            ``"warn"``, or ``"log"``.
        severity: Severity of a finding.
        description: Human-readable description.
        mask_replacement: Text used to replace matched keywords when
            *action* is ``"mask"``.
    """

    def __init__(
        self,
        name: str,
        keywords: list[str],
        action: str = "block",
        severity: str = "medium",
        description: str = "",
        mask_replacement: str = "***",
    ) -> None:
        super().__init__(name=name, description=description, severity=severity)
        self.keywords = keywords
        self.action_type = action
        self.mask_replacement = mask_replacement
        # Build a single regex with alternation for all keywords.
        escaped = [re.escape(kw) for kw in keywords]
        pattern = r"\b(?:" + "|".join(escaped) + r")\b"
        self._compiled: re.Pattern[str] = re.compile(pattern, re.IGNORECASE)

    def check(
        self,
        content: str,
        *,
        context: dict[str, object] | None = None,
    ) -> GuardrailResult:
        """Check *content* for keyword matches."""
        match = self._compiled.search(content)
        if match is None:
            return GuardrailResult(
                passed=True,
                guardrail_name=self.name,
                action="allowed",
                severity=self.severity,
            )

        action_label = self._action_label()
        return GuardrailResult(
            passed=action_label in ("warned", "allowed", "masked"),
            guardrail_name=self.name,
            action=action_label,
            details=f"Keyword matched: {match.group()!r}",
            severity=self.severity,
        )

    def check_and_transform(
        self,
        content: str,
        *,
        context: dict[str, object] | None = None,
    ) -> tuple[GuardrailResult, str]:
        """Check *content* and apply masking if configured."""
        match = self._compiled.search(content)
        if match is None:
            return (
                GuardrailResult(
                    passed=True,
                    guardrail_name=self.name,
                    action="allowed",
                    severity=self.severity,
                ),
                content,
            )

        action_label = self._action_label()

        if self.action_type == "mask":
            masked = self._compiled.sub(self.mask_replacement, content)
            result = GuardrailResult(
                passed=True,
                guardrail_name=self.name,
                action="masked",
                details="Keywords matched and masked",
                masked_content=masked,
                original_content=content,
                severity=self.severity,
            )
            return result, masked

        result = GuardrailResult(
            passed=action_label in ("warned", "allowed", "masked"),
            guardrail_name=self.name,
            action=action_label,
            details=f"Keyword matched: {match.group()!r}",
            severity=self.severity,
        )
        return result, content

    def _action_label(self) -> str:
        """Map the configured action type to a result action label."""
        mapping = {
            "block": "blocked",
            "mask": "masked",
            "warn": "warned",
            "log": "allowed",
        }
        return mapping.get(self.action_type, "blocked")
