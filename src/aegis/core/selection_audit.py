"""Selection Audit -- selection-by-negation detection for AI agent governance.

Detects when an AI agent exercises covert power through *what it excludes*
rather than what it selects.  Based on Santander's "Selection as Power"
framework (arXiv:2602.14606): cosmetic alignment, selection-by-negation,
and framing bias.

Key concepts:

- **SelectionSet**: full record of a selection decision (chosen + eliminated
  options with reasons).
- **SelectionAuditor**: stateful engine that analyses individual and
  historical selection patterns.
- **audit_selection**: async decorator that transparently audits any
  function returning a ``SelectionSet``.
- **CommitRevealSelection**: commit-reveal pattern -- agent commits the
  full option set *before* execution is revealed/approved.
"""

from __future__ import annotations

import functools
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any, TypeVar

if TYPE_CHECKING:
    from aegis.core.policy import Policy


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class EliminationReason(StrEnum):
    """Why an option was eliminated from consideration."""

    POLICY_VIOLATION = "policy_violation"
    AGENT_PREFERENCE = "agent_preference"
    RESOURCE_CONSTRAINT = "resource_constraint"
    CAPABILITY_LIMIT = "capability_limit"
    CONTEXT_IRRELEVANT = "context_irrelevant"
    UNKNOWN = "unknown"


class FindingType(StrEnum):
    """Type of selection audit finding."""

    HIGH_ELIMINATION = "high_elimination"
    BETTER_OPTION_ELIMINATED = "better_option_eliminated"
    UNJUSTIFIED_ELIMINATION = "unjustified_elimination"
    SYSTEMATIC_EXCLUSION = "systematic_exclusion"
    FRAMING_BIAS = "framing_bias"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SelectionOption:
    """A single option in a selection set -- chosen or eliminated.

    Records every option the agent considered (or should have considered).
    """

    option_id: str
    description: str
    action_type: str
    target: str
    params: dict[str, Any] = field(default_factory=dict)
    estimated_impact: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EliminatedOption:
    """An option that was considered but not selected."""

    option: SelectionOption
    reason: EliminationReason
    agent_explanation: str = ""


@dataclass
class SelectionSet:
    """Complete record of a selection decision.

    Captures the selected option together with all eliminated options and
    the reasons for their exclusion.  This is the fundamental unit for
    selection-by-negation detection.
    """

    selection_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    agent_id: str = ""
    context: str = ""

    selected: SelectionOption | None = None
    eliminated: list[EliminatedOption] = field(default_factory=list)

    # -- Aegis-computed audit fields --
    framing_score: float = 0.0
    negation_risk: float = 0.0
    diversity_score: float = 0.0

    @property
    def total_options(self) -> int:
        """Total number of options (selected + eliminated)."""
        return (1 if self.selected else 0) + len(self.eliminated)

    @property
    def elimination_ratio(self) -> float:
        """Fraction of options that were eliminated.  Higher is more suspicious."""
        total = self.total_options
        if total == 0:
            return 0.0
        return len(self.eliminated) / total


# ---------------------------------------------------------------------------
# Audit result models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SelectionFinding:
    """A single finding from selection audit."""

    finding_type: FindingType
    severity: float  # 0.0 - 1.0
    message: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SelectionAuditResult:
    """Complete result of auditing a selection decision."""

    selection_id: str
    findings: list[SelectionFinding] = field(default_factory=list)
    overall_risk: float = 0.0

    @property
    def is_suspicious(self) -> bool:
        """``True`` when the overall risk exceeds the suspicion threshold."""
        return self.overall_risk > 0.5


# ---------------------------------------------------------------------------
# SelectionAuditor
# ---------------------------------------------------------------------------


class SelectionAuditor:
    """Selection-by-negation detection engine.

    Analyses an agent's selection patterns to detect:

    1. Abnormally high elimination ratios.
    2. Eliminated options that were objectively better than the selection.
    3. Options eliminated by agent preference without justification.
    4. Systematic exclusion of specific targets over time.
    """

    def __init__(
        self,
        *,
        elimination_threshold: float = 0.8,
        negation_risk_threshold: float = 0.5,
        history_window: int = 100,
    ) -> None:
        self._elimination_threshold = elimination_threshold
        self._negation_risk_threshold = negation_risk_threshold
        self._history_window = history_window
        self._history: list[SelectionSet] = []

    # -- Public API ---------------------------------------------------------

    def audit(self, selection: SelectionSet) -> SelectionAuditResult:
        """Audit a single selection decision and return findings."""
        findings: list[SelectionFinding] = []

        # Detection 1: High elimination ratio
        if selection.elimination_ratio > self._elimination_threshold:
            findings.append(
                SelectionFinding(
                    finding_type=FindingType.HIGH_ELIMINATION,
                    severity=selection.elimination_ratio,
                    message=(
                        f"Agent eliminated {len(selection.eliminated)}/{selection.total_options} "
                        f"options ({selection.elimination_ratio:.0%})"
                    ),
                )
            )

        # Detection 2: Better option eliminated
        if selection.selected:
            for elim in selection.eliminated:
                if self._is_better_option(elim.option, selection.selected):
                    findings.append(
                        SelectionFinding(
                            finding_type=FindingType.BETTER_OPTION_ELIMINATED,
                            severity=0.8,
                            message=(
                                f"Eliminated option '{elim.option.option_id}' has lower "
                                f"estimated impact than selected option"
                            ),
                            detail={
                                "eliminated": elim.option.option_id,
                                "reason": elim.reason.value,
                            },
                        )
                    )

        # Detection 3: Agent-preference elimination without justification
        unjustified = [
            e
            for e in selection.eliminated
            if e.reason == EliminationReason.AGENT_PREFERENCE and not e.agent_explanation
        ]
        if unjustified:
            findings.append(
                SelectionFinding(
                    finding_type=FindingType.UNJUSTIFIED_ELIMINATION,
                    severity=0.6,
                    message=(
                        f"{len(unjustified)} options eliminated by agent preference "
                        f"without explanation"
                    ),
                )
            )

        # Detection 4: Pattern analysis (historical)
        self._history.append(selection)
        if len(self._history) > self._history_window:
            self._history = self._history[-self._history_window :]
        pattern_findings = self._detect_patterns()
        findings.extend(pattern_findings)

        return SelectionAuditResult(
            selection_id=selection.selection_id,
            findings=findings,
            overall_risk=max((f.severity for f in findings), default=0.0),
        )

    # -- Internal helpers ---------------------------------------------------

    @staticmethod
    def _is_better_option(
        eliminated: SelectionOption,
        selected: SelectionOption,
    ) -> bool:
        """Return ``True`` if the eliminated option has lower estimated impact."""
        return eliminated.estimated_impact < selected.estimated_impact

    def _detect_patterns(self) -> list[SelectionFinding]:
        """Detect systematic exclusion patterns across historical selections."""
        findings: list[SelectionFinding] = []
        if len(self._history) < 10:
            return findings

        # Pattern: a specific target is repeatedly eliminated
        target_elim_counts: dict[str, int] = {}
        for sel in self._history:
            for elim in sel.eliminated:
                key = elim.option.target
                target_elim_counts[key] = target_elim_counts.get(key, 0) + 1

        for target, count in target_elim_counts.items():
            if count > len(self._history) * 0.5:
                findings.append(
                    SelectionFinding(
                        finding_type=FindingType.SYSTEMATIC_EXCLUSION,
                        severity=0.7,
                        message=(
                            f"Target '{target}' systematically excluded in "
                            f"{count}/{len(self._history)} selections"
                        ),
                    )
                )

        return findings


# ---------------------------------------------------------------------------
# Decorator API
# ---------------------------------------------------------------------------

T = TypeVar("T")

# Global auditor singleton (set via ``set_global_auditor`` or ``aegis.init``)
_global_auditor: SelectionAuditor | None = None


def _get_global_auditor() -> SelectionAuditor | None:
    return _global_auditor


def set_global_auditor(auditor: SelectionAuditor) -> None:
    """Set the module-level auditor used by ``@audit_selection`` by default."""
    global _global_auditor  # noqa: PLW0603
    _global_auditor = auditor


def audit_selection(
    *,
    auditor: SelectionAuditor | None = None,
    context: str = "",
    agent_id: str = "",
) -> Callable[..., Any]:
    """Decorator to audit agent selection functions.

    Wraps an async function that returns a :class:`SelectionSet` (or an
    object with a ``to_selection_set()`` method) and transparently runs the
    selection audit.  The audit result is attached as ``_aegis_audit`` on
    the return value when the attribute exists.

    Usage::

        @audit_selection(context="tool_selection", agent_id="planner-agent")
        async def select_tool(options: list[ToolOption]) -> SelectionSet:
            selected = options[0]
            eliminated = options[1:]
            return SelectionSet(selected=selected, eliminated=eliminated)
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            result = await func(*args, **kwargs)

            # Extract selection data from result
            if hasattr(result, "to_selection_set"):
                selection_set = result.to_selection_set()
            elif isinstance(result, SelectionSet):
                selection_set = result
            else:
                return result  # not a selection -- pass through

            selection_set.agent_id = agent_id or selection_set.agent_id
            selection_set.context = context or selection_set.context

            # Audit
            _auditor = auditor or _get_global_auditor()
            if _auditor is not None:
                audit_result = _auditor.audit(selection_set)
                # Attach audit metadata to result if it supports it
                if hasattr(result, "_aegis_audit"):
                    result._aegis_audit = audit_result

            return result

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# CommitReveal pattern
# ---------------------------------------------------------------------------


class CommitRevealSelection:
    """Commit-reveal pattern for selection governance.

    The agent must *commit* the full set of options (selected + eliminated
    + reasons) before any action is executed.  Only after the audit passes
    is the action *revealed* (approved for execution).

    Phase 1 (Commit): Agent submits the complete :class:`SelectionSet`.
    Phase 2 (Audit):  Aegis computes a :class:`SelectionAuditResult`.
    Phase 3 (Reveal): Verdict is returned -- caller decides to proceed or
                       block based on audit outcome.
    """

    def __init__(self, auditor: SelectionAuditor, policy: Policy) -> None:
        self._auditor = auditor
        self._policy = policy
        self._committed: dict[str, SelectionSet] = {}

    async def commit(self, selection: SelectionSet) -> str:
        """Phase 1: Agent commits its full selection set.

        Returns the ``selection_id`` that must be used for :meth:`reveal`.
        """
        self._committed[selection.selection_id] = selection
        return selection.selection_id

    async def reveal(self, selection_id: str) -> SelectionAuditResult:
        """Phase 2 + 3: Audit the committed selection and return the verdict.

        Raises :class:`ValueError` if the ``selection_id`` was never committed.
        """
        selection = self._committed.get(selection_id)
        if selection is None:
            raise ValueError(f"No committed selection: {selection_id}")

        audit_result = self._auditor.audit(selection)

        # Clean up committed entry
        del self._committed[selection_id]
        return audit_result
