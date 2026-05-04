"""Tests for PolicyHierarchy."""

from __future__ import annotations

from aegis.core.action import Action
from aegis.core.hierarchy import PolicyConflict, PolicyHierarchy
from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.risk import RiskLevel


def _make_policy(
    match_type: str = "*",
    risk: RiskLevel = RiskLevel.LOW,
    approval: Approval = Approval.AUTO,
) -> Policy:
    rule = PolicyRule(
        name="test_rule",
        match_type=match_type,
        risk_level=risk,
        approval=approval,
    )
    return Policy(rules=[rule])


class TestPolicyHierarchy:
    def test_single_layer(self):
        hierarchy = PolicyHierarchy(org=_make_policy())
        action = Action("read", "db")
        decision, conflicts = hierarchy.evaluate(action)
        assert decision.approval == Approval.AUTO
        assert conflicts == []

    def test_no_policies_blocks(self):
        hierarchy = PolicyHierarchy()
        action = Action("read", "db")
        decision, conflicts = hierarchy.evaluate(action)
        assert decision.approval == Approval.BLOCK
        assert decision.matched_rule == "<no-policy-configured>"

    def test_org_blocks_overrides_agent_allow(self):
        hierarchy = PolicyHierarchy(
            org=_make_policy(risk=RiskLevel.CRITICAL, approval=Approval.BLOCK),
            agent=_make_policy(risk=RiskLevel.LOW, approval=Approval.AUTO),
        )
        action = Action("delete", "db")
        decision, conflicts = hierarchy.evaluate(action)
        assert decision.approval == Approval.BLOCK

    def test_most_restrictive_risk(self):
        hierarchy = PolicyHierarchy(
            org=_make_policy(risk=RiskLevel.LOW),
            team=_make_policy(risk=RiskLevel.HIGH),
        )
        action = Action("read", "db")
        decision, _ = hierarchy.evaluate(action)
        assert decision.risk_level == RiskLevel.HIGH

    def test_conflict_detected(self):
        hierarchy = PolicyHierarchy(
            org=_make_policy(approval=Approval.BLOCK),
            agent=_make_policy(approval=Approval.AUTO),
        )
        action = Action("read", "db")
        _, conflicts = hierarchy.evaluate(action)
        assert len(conflicts) == 1
        assert isinstance(conflicts[0], PolicyConflict)
        assert conflicts[0].resolution == "most_restrictive"

    def test_no_conflict_when_agree(self):
        hierarchy = PolicyHierarchy(
            org=_make_policy(approval=Approval.AUTO),
            team=_make_policy(approval=Approval.AUTO),
        )
        action = Action("read", "db")
        _, conflicts = hierarchy.evaluate(action)
        assert conflicts == []

    def test_flatten_no_policies(self):
        hierarchy = PolicyHierarchy()
        merged = hierarchy.flatten()
        assert isinstance(merged, Policy)

    def test_flatten_merges_layers(self):
        hierarchy = PolicyHierarchy(
            org=_make_policy(),
            team=_make_policy(risk=RiskLevel.MEDIUM),
        )
        merged = hierarchy.flatten()
        assert isinstance(merged, Policy)

    def test_three_layers(self):
        hierarchy = PolicyHierarchy(
            org=_make_policy(approval=Approval.AUTO),
            team=_make_policy(approval=Approval.APPROVE),
            agent=_make_policy(approval=Approval.AUTO),
        )
        action = Action("write", "db")
        decision, conflicts = hierarchy.evaluate(action)
        # Most restrictive approval is APPROVE
        assert decision.approval == Approval.APPROVE
        # Conflict exists because layers disagree
        assert len(conflicts) == 1
