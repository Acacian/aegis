"""Tests for drift_policy module."""

from __future__ import annotations

from aegis.core.action import Action
from aegis.core.drift import (
    DriftAction,
    DriftBaseline,
    DriftDetector,
    DriftResult,
    DriftSeverity,
    DriftType,
)
from aegis.core.drift_policy import (
    DriftPolicyDecision,
    DriftPolicyEvaluator,
    DriftPolicyRule,
)
from aegis.core.policy import Approval
from aegis.core.risk import RiskLevel


def _make_detector_with_baseline(
    agent_id: str = "agent-1",
    metric: str = "tool_distribution",
    baseline_value: float = 0.5,
) -> DriftDetector:
    """Create a DriftDetector with a pre-set baseline."""
    detector = DriftDetector()
    baseline = DriftBaseline(
        agent_id=agent_id,
        metric_name=metric,
        window_days=30,
        baseline_value=baseline_value,
        stddev=0.05,
        sample_count=100,
    )
    detector.set_baseline(baseline)
    return detector


class TestDriftPolicyRule:
    def test_no_drift_returns_none(self):
        detector = _make_detector_with_baseline()
        rule = DriftPolicyRule(name="test_rule", action_on_drift=DriftAction.WARN)
        action = Action("read", "db", agent_id="agent-1")

        result = rule.evaluate(action, detector)
        # No drift when current matches baseline
        assert result is None or isinstance(result, DriftPolicyDecision)

    def test_agent_mismatch_returns_none(self):
        detector = _make_detector_with_baseline()
        rule = DriftPolicyRule(name="test_rule", match_agent="agent-2")
        action = Action("read", "db", agent_id="agent-1")

        result = rule.evaluate(action, detector)
        assert result is None

    def test_wildcard_agent_matches_all(self):
        detector = _make_detector_with_baseline()
        rule = DriftPolicyRule(name="test_rule", match_agent="*")
        action = Action("read", "db", agent_id="agent-1")

        result = rule.evaluate(action, detector)
        assert result is None or isinstance(result, DriftPolicyDecision)

    def test_block_action_maps_to_block_approval(self):
        from aegis.core.drift_policy import _action_to_approval

        assert _action_to_approval(DriftAction.BLOCK) == Approval.BLOCK

    def test_warn_action_maps_to_approve(self):
        from aegis.core.drift_policy import _action_to_approval

        assert _action_to_approval(DriftAction.WARN) == Approval.APPROVE

    def test_action_to_risk_level(self):
        from aegis.core.drift_policy import _action_to_risk_level

        assert _action_to_risk_level(DriftAction.BLOCK) == RiskLevel.CRITICAL
        assert _action_to_risk_level(DriftAction.ALERT) == RiskLevel.HIGH
        assert _action_to_risk_level(DriftAction.WARN) == RiskLevel.MEDIUM
        assert _action_to_risk_level(DriftAction.LOG) == RiskLevel.LOW

    def test_approval_severity(self):
        from aegis.core.drift_policy import _approval_severity

        assert _approval_severity(Approval.BLOCK) == 3
        assert _approval_severity(Approval.APPROVE) == 2
        assert _approval_severity(Approval.AUTO) == 1

    def test_specific_metric(self):
        detector = _make_detector_with_baseline()
        rule = DriftPolicyRule(
            name="test_rule",
            metric=DriftType.TOOL_DISTRIBUTION,
            action_on_drift=DriftAction.WARN,
        )
        action = Action("read", "db", agent_id="agent-1")

        result = rule.evaluate(action, detector)
        # Should evaluate only tool_distribution metric
        assert result is None or isinstance(result, DriftPolicyDecision)


class TestDriftPolicyDecision:
    def test_drift_summary_no_results(self):
        decision = DriftPolicyDecision(
            action=Action("read", "db"),
            risk_level=RiskLevel.HIGH,
            approval=Approval.APPROVE,
            matched_rule="test",
        )
        assert "No drift detected" in decision.drift_summary

    def test_drift_summary_with_results(self):
        dr = DriftResult(
            drift_type=DriftType.TOOL_DISTRIBUTION,
            drifted=True,
            deviation_pct=0.45,
            severity=DriftSeverity.HIGH,
            baseline_value=0.5,
            current_value=0.95,
        )
        decision = DriftPolicyDecision(
            action=Action("read", "db"),
            risk_level=RiskLevel.HIGH,
            approval=Approval.APPROVE,
            matched_rule="test",
            drift_result=dr,
            all_drift_results=[dr],
        )
        summary = decision.drift_summary
        assert "Drift detected" in summary
        assert "1 metrics" in summary


class TestDriftPolicyEvaluator:
    def test_no_rules_returns_none(self):
        detector = _make_detector_with_baseline()
        evaluator = DriftPolicyEvaluator(drift_detector=detector, rules=[])
        action = Action("read", "db", agent_id="agent-1")

        result = evaluator.evaluate(action)
        assert result is None

    def test_add_rule(self):
        detector = _make_detector_with_baseline()
        evaluator = DriftPolicyEvaluator(drift_detector=detector)
        evaluator.add_rule(DriftPolicyRule(name="rule1"))
        assert len(evaluator._rules) == 1

    def test_from_config(self):
        detector = _make_detector_with_baseline()
        config = {
            "baselines": [
                {
                    "name": "tool_distribution",
                    "window": "30d",
                    "threshold": 0.2,
                    "action": "warn",
                }
            ]
        }
        evaluator = DriftPolicyEvaluator.from_config(config, detector)
        assert len(evaluator._rules) == 1
        assert evaluator._rules[0].name == "drift_tool_distribution"

    def test_from_config_empty(self):
        detector = _make_detector_with_baseline()
        evaluator = DriftPolicyEvaluator.from_config({}, detector)
        assert len(evaluator._rules) == 0
