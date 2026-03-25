"""Execution plan model."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from aegis.core.policy import Approval, PolicyDecision
from aegis.core.risk import RiskLevel

if TYPE_CHECKING:
    from aegis.core.plan_rules import PlanViolation


@dataclass
class ExecutionPlan:
    """A sequence of policy-evaluated actions ready for execution.

    Produced by :meth:`Runtime.plan`, consumed by :meth:`Runtime.execute`.

    Supports iteration, length, and indexing::

        plan = runtime.plan(actions)
        for decision in plan:
            print(decision.action.type, decision.approval)
    """

    decisions: list[PolicyDecision] = field(default_factory=list)
    plan_violations: list[PlanViolation] = field(default_factory=list)

    @property
    def has_plan_violations(self) -> bool:
        """Whether any plan-level violations were detected."""
        return len(self.plan_violations) > 0

    @property
    def has_blocked(self) -> bool:
        """Whether any action in the plan is blocked by policy or plan rules."""
        return any(not d.is_allowed for d in self.decisions) or any(
            v.approval == Approval.BLOCK for v in self.plan_violations
        )

    @property
    def requires_approval(self) -> bool:
        """Whether any action in the plan requires human approval."""
        return any(d.approval == Approval.APPROVE for d in self.decisions)

    @property
    def auto_only(self) -> bool:
        """Whether all actions in the plan are auto-approved (no blocks or approvals)."""
        return all(d.approval == Approval.AUTO for d in self.decisions)

    def summary(self) -> str:
        """Return a human-readable summary of the plan."""
        lines: list[str] = []
        for i, d in enumerate(self.decisions, 1):
            if not d.is_allowed:
                tag = "BLOCK"
            elif d.approval == Approval.AUTO:
                tag = "AUTO"
            else:
                tag = "APPROVE"
            lines.append(
                f"  {i}. [{tag:>7}] {d.action}  (risk={d.risk_level.name}, rule={d.matched_rule})"
            )
        if self.plan_violations:
            lines.append("  Plan violations:")
            for v in self.plan_violations:
                lines.append(
                    f"    - [{v.approval.value.upper():>7}] {v.rule_name}: {v.description}"
                )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Return a structured representation of the plan for programmatic use.

        Returns a dict with ``"decisions"`` and ``"plan_violations"`` keys.
        """
        decisions_out: list[dict[str, Any]] = []
        for d in self.decisions:
            decisions_out.append(
                {
                    "action_type": d.action.type,
                    "action_target": d.action.target,
                    "params": d.action.params,
                    "description": d.action.description,
                    "risk_level": d.risk_level.name.lower(),
                    "approval": d.approval.value,
                    "matched_rule": d.matched_rule,
                    "is_allowed": d.is_allowed,
                }
            )
        violations_out: list[dict[str, Any]] = []
        for v in self.plan_violations:
            violations_out.append(
                {
                    "rule_name": v.rule_name,
                    "description": v.description,
                    "approval": v.approval.value,
                    "risk_level": v.risk_level.name.lower(),
                    "involved_actions": [a.type for a in v.involved_actions],
                }
            )
        return {
            "decisions": decisions_out,
            "plan_violations": violations_out,
        }

    def filter(
        self,
        *,
        approval: Approval | None = None,
        risk_level: RiskLevel | None = None,
        allowed_only: bool = False,
    ) -> ExecutionPlan:
        """Return a new plan containing only decisions matching the criteria.

        Args:
            approval: Keep only decisions with this approval mode.
            risk_level: Keep only decisions with this risk level.
            allowed_only: If True, exclude blocked decisions.

        Example::

            safe_plan = plan.filter(allowed_only=True)
            results = await runtime.execute(safe_plan)
        """
        filtered = self.decisions
        if approval is not None:
            filtered = [d for d in filtered if d.approval == approval]
        if risk_level is not None:
            filtered = [d for d in filtered if d.risk_level == risk_level]
        if allowed_only:
            filtered = [d for d in filtered if d.is_allowed]
        return ExecutionPlan(decisions=filtered)

    def __len__(self) -> int:
        return len(self.decisions)

    def __iter__(self) -> Iterator[PolicyDecision]:
        return iter(self.decisions)

    def __getitem__(self, index: int) -> PolicyDecision:
        return self.decisions[index]
