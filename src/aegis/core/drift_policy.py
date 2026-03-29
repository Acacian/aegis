"""Policy rules for behavioral drift enforcement.

Integrates :class:`DriftDetector` with the existing policy engine so that
drift detection results can trigger policy actions (warn, block, alert).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aegis.core.action import Action
from aegis.core.drift import (
    DriftAction,
    DriftDetector,
    DriftResult,
    DriftType,
)
from aegis.core.policy import Approval, PolicyDecision
from aegis.core.risk import RiskLevel

# ---------------------------------------------------------------------------
# Drift policy rule
# ---------------------------------------------------------------------------


@dataclass
class DriftPolicyRule:
    """A policy rule that triggers based on behavioral drift detection.

    Unlike regular :class:`PolicyRule` which matches action type/target
    patterns, a ``DriftPolicyRule`` evaluates whether the agent's
    current behavior has drifted from its baseline.

    Attributes:
        name: Human-readable name for the rule.
        metric: Which drift metric to check.
        threshold: Override threshold (uses DriftDetector config if None).
        action_on_drift: What to do when drift is detected.
        risk_level: Risk level to assign when drift is detected.
        match_agent: Glob pattern for agent_id matching.
            ``"*"`` matches all agents.
    """

    name: str = "drift_policy"
    metric: DriftType | None = None  # None = check all metrics
    threshold: float | None = None
    action_on_drift: DriftAction = DriftAction.WARN
    risk_level: RiskLevel = RiskLevel.HIGH
    match_agent: str = "*"

    def evaluate(
        self,
        action: Action,
        drift_detector: DriftDetector,
    ) -> DriftPolicyDecision | None:
        """Evaluate this rule against the current drift state.

        Returns a :class:`DriftPolicyDecision` when drift is detected,
        or ``None`` when the agent's behavior is within baseline.
        """
        agent_id = action.agent_id or "default"

        # Agent matching.
        if self.match_agent != "*" and self.match_agent != agent_id:
            return None

        if self.metric is not None:
            results = [drift_detector.check(agent_id, self.metric.value)]
        else:
            results = drift_detector.check_all(agent_id)

        # Find the most severe drift.
        drifted_results = [r for r in results if r.drifted]
        if not drifted_results:
            return None

        worst = max(drifted_results, key=lambda r: r.deviation_pct)

        # Override threshold check if configured.
        if self.threshold is not None and worst.deviation_pct <= self.threshold:
            return None

        approval = _action_to_approval(self.action_on_drift)

        return DriftPolicyDecision(
            action=action,
            risk_level=self.risk_level,
            approval=approval,
            matched_rule=self.name,
            drift_result=worst,
            all_drift_results=drifted_results,
        )


@dataclass(frozen=True)
class DriftPolicyDecision(PolicyDecision):
    """Extended policy decision that includes drift detection details.

    Inherits from :class:`PolicyDecision` so it can be used wherever
    a standard decision is expected.
    """

    drift_result: DriftResult | None = None
    all_drift_results: list[DriftResult] = field(default_factory=list)

    @property
    def drift_summary(self) -> str:
        """Human-readable summary of all detected drifts."""
        if not self.all_drift_results:
            return "No drift detected"
        lines = []
        for r in self.all_drift_results:
            lines.append(
                f"  - {r.drift_type}: deviation={r.deviation_pct:.2%}, severity={r.severity}"
            )
        return f"Drift detected ({len(self.all_drift_results)} metrics):\n" + "\n".join(lines)


# ---------------------------------------------------------------------------
# Drift policy evaluator
# ---------------------------------------------------------------------------


class DriftPolicyEvaluator:
    """Evaluates actions against a set of drift policy rules.

    Sits between the regular policy engine and the drift detector,
    providing a unified interface for drift-based enforcement.

    Parameters:
        drift_detector: The :class:`DriftDetector` to query.
        rules: List of :class:`DriftPolicyRule` to evaluate.
    """

    def __init__(
        self,
        drift_detector: DriftDetector,
        rules: list[DriftPolicyRule] | None = None,
    ) -> None:
        self._drift_detector = drift_detector
        self._rules = rules or []

    def add_rule(self, rule: DriftPolicyRule) -> None:
        """Add a drift policy rule."""
        self._rules.append(rule)

    def evaluate(self, action: Action) -> DriftPolicyDecision | None:
        """Evaluate an action against all drift policy rules.

        Returns the most severe :class:`DriftPolicyDecision`, or ``None``
        when no rule fires.
        """
        decisions: list[DriftPolicyDecision] = []
        for rule in self._rules:
            decision = rule.evaluate(action, self._drift_detector)
            if decision is not None:
                decisions.append(decision)

        if not decisions:
            return None

        # Return the most severe decision (highest risk + strictest approval).
        return max(
            decisions,
            key=lambda d: (d.risk_level, _approval_severity(d.approval)),
        )

    @classmethod
    def from_config(
        cls,
        config: dict[str, Any],
        drift_detector: DriftDetector,
    ) -> DriftPolicyEvaluator:
        """Create from a parsed YAML config dict.

        Expected format::

            drift:
              enabled: true
              baselines:
                - name: tool_distribution
                  window: 30d
                  threshold: 0.2
                  action: warn
        """
        rules: list[DriftPolicyRule] = []
        for item in config.get("baselines", []):
            rules.append(
                DriftPolicyRule(
                    name=f"drift_{item['name']}",
                    metric=DriftType(item["name"]),
                    threshold=float(item.get("threshold", 0.2)),
                    action_on_drift=DriftAction(item.get("action", "warn")),
                    risk_level=_action_to_risk_level(DriftAction(item.get("action", "warn"))),
                )
            )
        return cls(drift_detector=drift_detector, rules=rules)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _action_to_approval(action: DriftAction) -> Approval:
    """Map a :class:`DriftAction` to a :class:`Approval`."""
    if action == DriftAction.BLOCK:
        return Approval.BLOCK
    if action in (DriftAction.WARN, DriftAction.ALERT):
        return Approval.APPROVE
    return Approval.AUTO


def _action_to_risk_level(action: DriftAction) -> RiskLevel:
    """Map a :class:`DriftAction` to a :class:`RiskLevel`."""
    if action == DriftAction.BLOCK:
        return RiskLevel.CRITICAL
    if action == DriftAction.ALERT:
        return RiskLevel.HIGH
    if action == DriftAction.WARN:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _approval_severity(approval: Approval) -> int:
    """Numeric severity for sorting decisions."""
    if approval == Approval.BLOCK:
        return 3
    if approval == Approval.APPROVE:
        return 2
    return 1
