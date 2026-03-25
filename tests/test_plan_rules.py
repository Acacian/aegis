"""Tests for plan-level governance rules."""

from __future__ import annotations

import pytest

from aegis.core.action import Action
from aegis.core.plan import ExecutionPlan
from aegis.core.plan_rules import (
    CumulativeRiskThreshold,
    PlanRules,
    PlanViolation,
    SequencePattern,
)
from aegis.core.policy import Approval, Policy, PolicyDecision
from aegis.core.risk import RiskLevel

# ── Helpers ──────────────────────────────────────────────────────────────


def _decision(action_type: str, risk: RiskLevel = RiskLevel.MEDIUM) -> PolicyDecision:
    """Create a simple PolicyDecision for testing."""
    return PolicyDecision(
        action=Action(type=action_type, target="test"),
        risk_level=risk,
        approval=Approval.AUTO,
        matched_rule="test",
    )


def _plan(*types: str) -> ExecutionPlan:
    """Create an ExecutionPlan from action type names."""
    return ExecutionPlan(decisions=[_decision(t) for t in types])


# ── SequencePattern ──────────────────────────────────────────────────────


class TestSequencePattern:
    def test_creation(self) -> None:
        sp = SequencePattern(name="exfil", steps=("read_*", "send_*"))
        assert sp.name == "exfil"
        assert sp.steps == ("read_*", "send_*")
        assert sp.approval == Approval.BLOCK
        assert sp.risk_level == RiskLevel.CRITICAL
        assert sp.window == 0

    def test_frozen(self) -> None:
        sp = SequencePattern(name="test", steps=("a", "b"))
        with pytest.raises(AttributeError):
            sp.name = "changed"  # type: ignore[misc]


# ── PlanRules.from_dict ─────────────────────────────────────────────────


class TestPlanRulesFromDict:
    def test_full_dict(self) -> None:
        data = {
            "sequence_patterns": [
                {
                    "name": "exfil",
                    "steps": ["read_*", "send_*"],
                    "approval": "block",
                    "risk_level": "critical",
                    "description": "Data exfiltration",
                    "window": 3,
                },
            ],
            "cumulative_risk": {
                "max_total_risk": 10,
                "on_exceed": "approve",
            },
        }
        rules = PlanRules.from_dict(data)
        assert len(rules.sequence_patterns) == 1
        assert rules.sequence_patterns[0].name == "exfil"
        assert rules.sequence_patterns[0].window == 3
        assert rules.cumulative_risk is not None
        assert rules.cumulative_risk.max_total_risk == 10
        assert rules.cumulative_risk.on_exceed == Approval.APPROVE

    def test_empty_dict(self) -> None:
        rules = PlanRules.from_dict({})
        assert rules.sequence_patterns == []
        assert rules.cumulative_risk is None

    def test_none(self) -> None:
        rules = PlanRules.from_dict(None)
        assert rules.sequence_patterns == []


# ── Sequence Detection ───────────────────────────────────────────────────


class TestSequenceDetection:
    def test_simple_two_step_match(self) -> None:
        rules = PlanRules(
            sequence_patterns=[
                SequencePattern(name="exfil", steps=("read_*", "send_*")),
            ]
        )
        plan = _plan("read_file", "process", "send_email")
        violations = rules.evaluate(plan)
        assert len(violations) == 1
        assert violations[0].rule_name == "exfil"
        assert len(violations[0].involved_actions) == 2

    def test_three_step_match(self) -> None:
        rules = PlanRules(
            sequence_patterns=[
                SequencePattern(
                    name="priv_esc",
                    steps=("read_credentials", "authenticate_*", "admin_*"),
                ),
            ]
        )
        plan = _plan("read_credentials", "authenticate_ldap", "admin_delete")
        violations = rules.evaluate(plan)
        assert len(violations) == 1
        assert violations[0].rule_name == "priv_esc"

    def test_no_match(self) -> None:
        rules = PlanRules(
            sequence_patterns=[
                SequencePattern(name="exfil", steps=("read_*", "send_*")),
            ]
        )
        plan = _plan("read_file", "process_data", "write_report")
        violations = rules.evaluate(plan)
        assert len(violations) == 0

    def test_window_constraint_within(self) -> None:
        rules = PlanRules(
            sequence_patterns=[
                SequencePattern(name="exfil", steps=("read_*", "send_*"), window=3),
            ]
        )
        plan = _plan("read_file", "step2", "send_email")
        violations = rules.evaluate(plan)
        assert len(violations) == 1

    def test_window_constraint_exceeded(self) -> None:
        rules = PlanRules(
            sequence_patterns=[
                SequencePattern(name="exfil", steps=("read_*", "send_*"), window=2),
            ]
        )
        plan = _plan("read_file", "step2", "step3", "send_email")
        violations = rules.evaluate(plan)
        assert len(violations) == 0  # send_email is at index 3, outside window of 2

    def test_glob_matching(self) -> None:
        rules = PlanRules(
            sequence_patterns=[
                SequencePattern(name="test", steps=("get_*", "put_*")),
            ]
        )
        plan = _plan("get_data", "transform", "put_result")
        violations = rules.evaluate(plan)
        assert len(violations) == 1

    def test_single_step_pattern_skipped(self) -> None:
        rules = PlanRules(
            sequence_patterns=[
                SequencePattern(name="bad", steps=("read_*",)),
            ]
        )
        plan = _plan("read_file")
        violations = rules.evaluate(plan)
        assert len(violations) == 0  # < 2 steps, skipped

    def test_multiple_patterns(self) -> None:
        rules = PlanRules(
            sequence_patterns=[
                SequencePattern(name="exfil", steps=("read_*", "send_*")),
                SequencePattern(name="destroy", steps=("read_*", "delete_*")),
            ]
        )
        plan = _plan("read_file", "send_email")
        violations = rules.evaluate(plan)
        assert len(violations) == 1
        assert violations[0].rule_name == "exfil"


# ── Cumulative Risk ──────────────────────────────────────────────────────


class TestCumulativeRisk:
    def test_below_threshold(self) -> None:
        rules = PlanRules(cumulative_risk=CumulativeRiskThreshold(max_total_risk=10))
        plan = ExecutionPlan(
            decisions=[
                _decision("a", RiskLevel.LOW),  # 1
                _decision("b", RiskLevel.MEDIUM),  # 2
                _decision("c", RiskLevel.LOW),  # 1
            ]
        )
        violations = rules.evaluate(plan)
        assert len(violations) == 0

    def test_exceeds_threshold(self) -> None:
        rules = PlanRules(cumulative_risk=CumulativeRiskThreshold(max_total_risk=5))
        plan = ExecutionPlan(
            decisions=[
                _decision("a", RiskLevel.HIGH),  # 3
                _decision("b", RiskLevel.HIGH),  # 3
            ]
        )
        violations = rules.evaluate(plan)
        assert len(violations) == 1
        assert violations[0].rule_name == "cumulative_risk"
        assert "6 exceeds threshold 5" in violations[0].description

    def test_exact_threshold_passes(self) -> None:
        rules = PlanRules(cumulative_risk=CumulativeRiskThreshold(max_total_risk=6))
        plan = ExecutionPlan(
            decisions=[
                _decision("a", RiskLevel.HIGH),  # 3
                _decision("b", RiskLevel.HIGH),  # 3
            ]
        )
        violations = rules.evaluate(plan)
        assert len(violations) == 0  # 6 == 6, not exceeded

    def test_cumulative_approve_mode(self) -> None:
        rules = PlanRules(
            cumulative_risk=CumulativeRiskThreshold(
                max_total_risk=3,
                on_exceed=Approval.APPROVE,
            )
        )
        plan = ExecutionPlan(
            decisions=[
                _decision("a", RiskLevel.CRITICAL),  # 4
            ]
        )
        violations = rules.evaluate(plan)
        assert len(violations) == 1
        assert violations[0].approval == Approval.APPROVE


# ── Policy Integration ───────────────────────────────────────────────────


class TestPolicyIntegration:
    def test_policy_from_dict_with_plan_rules(self) -> None:
        data = {
            "version": "2",
            "defaults": {"risk_level": "medium", "approval": "auto"},
            "rules": [
                {
                    "name": "read",
                    "match": {"type": "read_*"},
                    "risk_level": "low",
                    "approval": "auto",
                },
            ],
            "plan_rules": {
                "sequence_patterns": [
                    {"name": "exfil", "steps": ["read_*", "send_*"]},
                ],
            },
        }
        policy = Policy.from_dict(data)
        assert policy.plan_rules is not None
        assert len(policy.plan_rules.sequence_patterns) == 1
        assert policy.plan_rules.sequence_patterns[0].name == "exfil"

    def test_policy_from_dict_without_plan_rules(self) -> None:
        data = {
            "version": "1",
            "defaults": {"risk_level": "medium", "approval": "auto"},
            "rules": [],
        }
        policy = Policy.from_dict(data)
        assert policy.plan_rules is None

    def test_policy_merge_plan_rules(self) -> None:
        p1 = Policy.from_dict(
            {
                "rules": [],
                "plan_rules": {
                    "sequence_patterns": [{"name": "a", "steps": ["x", "y"]}],
                },
            }
        )
        p2 = Policy.from_dict(
            {
                "rules": [],
                "plan_rules": {
                    "sequence_patterns": [{"name": "b", "steps": ["m", "n"]}],
                },
            }
        )
        merged = p1.merge(p2)
        assert merged.plan_rules is not None
        assert len(merged.plan_rules.sequence_patterns) == 2

    def test_policy_merge_cumulative_risk(self) -> None:
        p1 = Policy.from_dict(
            {
                "rules": [],
                "plan_rules": {"cumulative_risk": {"max_total_risk": 10}},
            }
        )
        p2 = Policy.from_dict(
            {
                "rules": [],
                "plan_rules": {"cumulative_risk": {"max_total_risk": 5}},
            }
        )
        merged = p1.merge(p2)
        assert merged.plan_rules is not None
        assert merged.plan_rules.cumulative_risk is not None
        assert merged.plan_rules.cumulative_risk.max_total_risk == 5  # more restrictive


# ── ExecutionPlan Integration ────────────────────────────────────────────


class TestExecutionPlanIntegration:
    def test_plan_violations_field(self) -> None:
        plan = _plan("read_file")
        assert plan.plan_violations == []
        assert plan.has_plan_violations is False

    def test_has_blocked_with_violation(self) -> None:
        plan = _plan("read_file")
        plan.plan_violations = [
            PlanViolation(
                rule_name="test",
                description="test",
                involved_actions=(),
                approval=Approval.BLOCK,
                risk_level=RiskLevel.CRITICAL,
            )
        ]
        assert plan.has_blocked is True
        assert plan.has_plan_violations is True

    def test_summary_includes_violations(self) -> None:
        plan = _plan("read_file")
        plan.plan_violations = [
            PlanViolation(
                rule_name="exfil",
                description="Data exfiltration detected",
                involved_actions=(),
                approval=Approval.BLOCK,
                risk_level=RiskLevel.CRITICAL,
            )
        ]
        summary = plan.summary()
        assert "Plan violations:" in summary
        assert "exfil" in summary

    def test_to_dict_includes_violations(self) -> None:
        plan = _plan("read_file")
        plan.plan_violations = [
            PlanViolation(
                rule_name="test",
                description="test desc",
                involved_actions=(Action(type="read_file", target="test"),),
                approval=Approval.BLOCK,
                risk_level=RiskLevel.CRITICAL,
            )
        ]
        d = plan.to_dict()
        assert "plan_violations" in d
        assert len(d["plan_violations"]) == 1
        assert d["plan_violations"][0]["rule_name"] == "test"
