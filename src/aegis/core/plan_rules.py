"""Plan-level governance rules — sequence detection and cumulative risk.

Adds sequence-aware evaluation to execution plans. While individual
action rules catch single-step violations, plan rules catch multi-step
attack patterns like data exfiltration (read → send) or privilege
escalation (read_credentials → authenticate → admin_action).

Example YAML::

    plan_rules:
      sequence_patterns:
        - name: data_exfiltration
          steps: ["read_*", "send_*"]
          approval: block
          risk_level: critical
        - name: privilege_escalation
          steps: ["read_credentials", "authenticate_*", "admin_*"]
          window: 5
      cumulative_risk:
        max_total_risk: 12
        on_exceed: approve

Example usage::

    from aegis.core.plan_rules import PlanRules

    rules = PlanRules.from_dict({
        "sequence_patterns": [
            {"name": "exfil", "steps": ["read_*", "send_*"]},
        ],
    })
    violations = rules.evaluate(execution_plan)
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from aegis.core.policy import Approval
from aegis.core.risk import RiskLevel

if TYPE_CHECKING:
    from aegis.core.action import Action
    from aegis.core.plan import ExecutionPlan


# ── Risk level integer mapping ───────────────────────────────────────────

_RISK_INT: dict[RiskLevel, int] = {
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


# ── Data models ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SequencePattern:
    """A forbidden or flagged sequence of action types.

    Attributes:
        name: Unique rule name.
        steps: Ordered glob patterns that form the forbidden sequence.
        approval: Governance action when matched (default: BLOCK).
        risk_level: Risk level assigned to the violation.
        description: Human-readable explanation.
        window: Maximum step distance between first and last match.
            ``0`` means unlimited (any position in the plan).
    """

    name: str
    steps: tuple[str, ...]
    approval: Approval = Approval.BLOCK
    risk_level: RiskLevel = RiskLevel.CRITICAL
    description: str = ""
    window: int = 0


@dataclass
class CumulativeRiskThreshold:
    """Threshold for total accumulated risk across a plan.

    Risk is summed as integer values: LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4.

    Attributes:
        max_total_risk: Maximum allowed total risk score.
        on_exceed: Governance action when exceeded.
        name: Rule name for violation reporting.
    """

    max_total_risk: int = 0
    on_exceed: Approval = Approval.BLOCK
    name: str = "cumulative_risk"


@dataclass(frozen=True)
class PlanViolation:
    """A violation found during plan-level evaluation.

    Attributes:
        rule_name: Name of the plan rule that was violated.
        description: Human-readable violation description.
        involved_actions: The actions that triggered the violation.
        approval: Governance action (BLOCK, APPROVE, AUTO).
        risk_level: Risk level of the violation.
    """

    rule_name: str
    description: str
    involved_actions: tuple[Action, ...]
    approval: Approval
    risk_level: RiskLevel


# ── PlanRules engine ─────────────────────────────────────────────────────

_RISK_MAP: dict[str, RiskLevel] = {
    "low": RiskLevel.LOW,
    "medium": RiskLevel.MEDIUM,
    "high": RiskLevel.HIGH,
    "critical": RiskLevel.CRITICAL,
}

_APPROVAL_MAP: dict[str, Approval] = {
    "auto": Approval.AUTO,
    "approve": Approval.APPROVE,
    "block": Approval.BLOCK,
}


@dataclass
class PlanRules:
    """Plan-level governance rules: sequence patterns and cumulative thresholds.

    Evaluates an :class:`~aegis.core.plan.ExecutionPlan` for multi-step
    attack patterns and excessive cumulative risk.
    """

    sequence_patterns: list[SequencePattern] = field(default_factory=list)
    cumulative_risk: CumulativeRiskThreshold | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> PlanRules:
        """Parse plan rules from a dictionary (e.g. YAML ``plan_rules:`` section).

        Tolerates missing keys and provides sensible defaults.
        """
        if not data:
            return cls()

        patterns: list[SequencePattern] = []
        for sp in data.get("sequence_patterns", []):
            steps_raw = sp.get("steps", [])
            patterns.append(
                SequencePattern(
                    name=sp.get("name", ""),
                    steps=tuple(steps_raw),
                    approval=_APPROVAL_MAP.get(
                        str(sp.get("approval", "block")).lower(),
                        Approval.BLOCK,
                    ),
                    risk_level=_RISK_MAP.get(
                        str(sp.get("risk_level", "critical")).lower(),
                        RiskLevel.CRITICAL,
                    ),
                    description=sp.get("description", ""),
                    window=int(sp.get("window", 0)),
                )
            )

        cumulative = None
        cr_data = data.get("cumulative_risk")
        if cr_data:
            cumulative = CumulativeRiskThreshold(
                max_total_risk=int(cr_data.get("max_total_risk", 0)),
                on_exceed=_APPROVAL_MAP.get(
                    str(cr_data.get("on_exceed", "block")).lower(),
                    Approval.BLOCK,
                ),
                name=cr_data.get("name", "cumulative_risk"),
            )

        return cls(sequence_patterns=patterns, cumulative_risk=cumulative)

    def evaluate(self, plan: ExecutionPlan) -> list[PlanViolation]:
        """Evaluate a plan against all plan-level rules.

        Returns a list of :class:`PlanViolation` objects (empty if clean).
        """
        violations: list[PlanViolation] = []
        violations.extend(self._check_sequences(plan))
        violations.extend(self._check_cumulative_risk(plan))
        return violations

    def _check_sequences(self, plan: ExecutionPlan) -> list[PlanViolation]:
        """Detect forbidden action sequences in the plan.

        For each :class:`SequencePattern`, scans the plan's decisions in
        order, matching steps sequentially with ``fnmatch``. If a window
        is set, all steps must occur within that many positions.
        """
        violations: list[PlanViolation] = []
        decisions = list(plan.decisions)

        for pattern in self.sequence_patterns:
            if len(pattern.steps) < 2:
                continue

            # Scan for each possible starting position
            for start_idx in range(len(decisions)):
                action_type = decisions[start_idx].action.type
                if not fnmatch.fnmatch(action_type, pattern.steps[0]):
                    continue

                # Try to match remaining steps
                matched_actions: list[Action] = [decisions[start_idx].action]
                step_idx = 1
                search_end = (
                    min(start_idx + pattern.window, len(decisions))
                    if pattern.window > 0
                    else len(decisions)
                )

                for scan_idx in range(start_idx + 1, search_end):
                    scan_type = decisions[scan_idx].action.type
                    if fnmatch.fnmatch(scan_type, pattern.steps[step_idx]):
                        matched_actions.append(decisions[scan_idx].action)
                        step_idx += 1
                        if step_idx >= len(pattern.steps):
                            break

                if step_idx >= len(pattern.steps):
                    desc = pattern.description or (
                        f"Forbidden sequence '{pattern.name}': "
                        + " → ".join(f"'{a.type}'" for a in matched_actions)
                    )
                    violations.append(
                        PlanViolation(
                            rule_name=pattern.name,
                            description=desc,
                            involved_actions=tuple(matched_actions),
                            approval=pattern.approval,
                            risk_level=pattern.risk_level,
                        )
                    )
                    break  # One violation per pattern is enough

        return violations

    def _check_cumulative_risk(self, plan: ExecutionPlan) -> list[PlanViolation]:
        """Check if total risk across the plan exceeds the threshold."""
        if self.cumulative_risk is None or self.cumulative_risk.max_total_risk <= 0:
            return []

        total = sum(_RISK_INT.get(d.risk_level, 0) for d in plan.decisions)

        if total > self.cumulative_risk.max_total_risk:
            all_actions = tuple(d.action for d in plan.decisions)
            return [
                PlanViolation(
                    rule_name=self.cumulative_risk.name,
                    description=(
                        f"Cumulative risk {total} exceeds threshold "
                        f"{self.cumulative_risk.max_total_risk}"
                    ),
                    involved_actions=all_actions,
                    approval=self.cumulative_risk.on_exceed,
                    risk_level=RiskLevel.CRITICAL,
                )
            ]

        return []
