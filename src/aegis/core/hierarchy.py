"""Policy hierarchy with org -> team -> agent inheritance.

Evaluates actions against layered policies. More restrictive
decisions at higher levels cannot be overridden by lower levels.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aegis.core.action import Action
from aegis.core.policy import Approval, Policy, PolicyDecision
from aegis.core.risk import RiskLevel


@dataclass
class PolicyConflict:
    """Records a disagreement between policy layers."""

    action: Action
    layer_decisions: dict[str, PolicyDecision]  # scope -> decision
    resolved: PolicyDecision
    resolution: str  # e.g., "most_restrictive"


@dataclass
class PolicyHierarchy:
    """Layered policy evaluation: org -> team -> agent.

    Higher layers (org) take precedence -- if org blocks an action,
    team/agent cannot override. Within allowed decisions, the most
    restrictive approval wins.

    Example::

        hierarchy = PolicyHierarchy(
            org=Policy.from_yaml("org.yaml"),
            team=Policy.from_yaml("team.yaml"),
            agent=Policy.from_yaml("agent.yaml"),
        )
        decision, conflicts = hierarchy.evaluate(action)
    """

    org: Policy | None = None
    team: Policy | None = None
    agent: Policy | None = None

    def evaluate(self, action: Action) -> tuple[PolicyDecision, list[PolicyConflict]]:
        """Evaluate action against all layers, return most restrictive decision + conflicts."""
        layers: dict[str, PolicyDecision] = {}

        for name, policy in [("org", self.org), ("team", self.team), ("agent", self.agent)]:
            if policy is not None:
                layers[name] = policy.evaluate(action)

        if not layers:
            # No policies configured -- default allow
            return PolicyDecision(
                action=action,
                risk_level=RiskLevel.MEDIUM,
                approval=Approval.APPROVE,
                matched_rule="<no-policy>",
            ), []

        # Most restrictive wins
        resolved = self._most_restrictive(action, list(layers.values()))

        # Detect conflicts
        conflicts = self._detect_conflicts(action, layers, resolved)

        return resolved, conflicts

    def flatten(self) -> Policy:
        """Merge all layers into a single Policy for backward-compatible use.

        Org rules come first (highest priority in first-match-wins).
        """
        policies = [p for p in [self.org, self.team, self.agent] if p is not None]
        if not policies:
            return Policy()
        result = policies[0]
        for p in policies[1:]:
            result = result.merge(p)
        return result

    def _most_restrictive(
        self, action: Action, decisions: list[PolicyDecision]
    ) -> PolicyDecision:
        """Pick the most restrictive decision across layers."""
        _approval_severity = {Approval.AUTO: 0, Approval.APPROVE: 1, Approval.BLOCK: 2}
        _risk_severity = {
            RiskLevel.LOW: 0,
            RiskLevel.MEDIUM: 1,
            RiskLevel.HIGH: 2,
            RiskLevel.CRITICAL: 3,
        }

        most_severe_approval = max(decisions, key=lambda d: _approval_severity[d.approval])
        most_severe_risk = max(decisions, key=lambda d: _risk_severity[d.risk_level])

        return PolicyDecision(
            action=action,
            risk_level=most_severe_risk.risk_level,
            approval=most_severe_approval.approval,
            matched_rule=most_severe_approval.matched_rule,
        )

    def _detect_conflicts(
        self,
        action: Action,
        layers: dict[str, PolicyDecision],
        resolved: PolicyDecision,
    ) -> list[PolicyConflict]:
        """Detect when layers disagree on approval."""
        approvals = {name: d.approval for name, d in layers.items()}
        unique_approvals = set(approvals.values())

        if len(unique_approvals) <= 1:
            return []

        return [
            PolicyConflict(
                action=action,
                layer_decisions=layers,
                resolved=resolved,
                resolution="most_restrictive",
            )
        ]
