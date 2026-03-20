"""Execution plan model."""

from __future__ import annotations

from dataclasses import dataclass, field

from aegis.core.policy import Approval, PolicyDecision


@dataclass
class ExecutionPlan:
    """A sequence of policy-evaluated actions ready for execution.

    Produced by :meth:`Runtime.plan`, consumed by :meth:`Runtime.execute`.
    """

    decisions: list[PolicyDecision] = field(default_factory=list)

    @property
    def has_blocked(self) -> bool:
        """Whether any action in the plan is blocked by policy."""
        return any(not d.is_allowed for d in self.decisions)

    @property
    def requires_approval(self) -> bool:
        """Whether any action in the plan requires human approval."""
        return any(d.approval == Approval.APPROVE for d in self.decisions)

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
                f"  {i}. [{tag:>7}] {d.action}  "
                f"(risk={d.risk_level.name}, rule={d.matched_rule})"
            )
        return "\n".join(lines)

    def __len__(self) -> int:
        return len(self.decisions)
