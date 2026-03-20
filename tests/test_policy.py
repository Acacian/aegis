"""Tests for the policy engine."""

import textwrap
from pathlib import Path

from aegis.core.action import Action
from aegis.core.policy import Approval, Policy, PolicyDecision, PolicyRule
from aegis.core.risk import RiskLevel


# -- PolicyRule ----------------------------------------------------------


def test_rule_matches_exact():
    rule = PolicyRule(match_type="read", match_target="salesforce")
    assert rule.matches(Action("read", "salesforce"))
    assert not rule.matches(Action("write", "salesforce"))
    assert not rule.matches(Action("read", "stripe"))


def test_rule_matches_wildcard_type():
    rule = PolicyRule(match_type="*", match_target="salesforce")
    assert rule.matches(Action("read", "salesforce"))
    assert rule.matches(Action("delete", "salesforce"))
    assert not rule.matches(Action("read", "stripe"))


def test_rule_matches_wildcard_target():
    rule = PolicyRule(match_type="read", match_target="*")
    assert rule.matches(Action("read", "salesforce"))
    assert rule.matches(Action("read", "stripe"))
    assert not rule.matches(Action("write", "salesforce"))


def test_rule_matches_glob_pattern():
    rule = PolicyRule(match_type="bulk_*", match_target="*")
    assert rule.matches(Action("bulk_update", "salesforce"))
    assert rule.matches(Action("bulk_delete", "stripe"))
    assert not rule.matches(Action("update", "salesforce"))


# -- Policy evaluation ---------------------------------------------------


def test_policy_first_match_wins():
    policy = Policy(
        rules=[
            PolicyRule(
                match_type="read",
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
                name="read_auto",
            ),
            PolicyRule(
                match_type="read",
                risk_level=RiskLevel.HIGH,
                approval=Approval.BLOCK,
                name="read_block",
            ),
        ]
    )
    decision = policy.evaluate(Action("read", "salesforce"))
    assert decision.risk_level == RiskLevel.LOW
    assert decision.approval == Approval.AUTO
    assert decision.matched_rule == "read_auto"


def test_policy_falls_back_to_defaults():
    policy = Policy(
        rules=[PolicyRule(match_type="read", approval=Approval.AUTO)],
        default_risk_level=RiskLevel.HIGH,
        default_approval=Approval.BLOCK,
    )
    decision = policy.evaluate(Action("unknown_action", "some_target"))
    assert decision.risk_level == RiskLevel.HIGH
    assert decision.approval == Approval.BLOCK
    assert decision.matched_rule == "<default>"


def test_policy_decision_is_allowed():
    allowed = PolicyDecision(
        action=Action("read", "sf"),
        risk_level=RiskLevel.LOW,
        approval=Approval.AUTO,
    )
    assert allowed.is_allowed

    blocked = PolicyDecision(
        action=Action("delete", "sf"),
        risk_level=RiskLevel.CRITICAL,
        approval=Approval.BLOCK,
    )
    assert not blocked.is_allowed


# -- YAML loading --------------------------------------------------------


def test_policy_from_dict():
    data = {
        "defaults": {"risk_level": "high", "approval": "block"},
        "rules": [
            {
                "name": "read_safe",
                "match": {"type": "read"},
                "risk_level": "low",
                "approval": "auto",
            },
            {
                "name": "write_approve",
                "match": {"type": "write", "target": "salesforce"},
                "risk_level": "medium",
                "approval": "approve",
            },
        ],
    }
    policy = Policy.from_dict(data)
    assert len(policy.rules) == 2
    assert policy.default_risk_level == RiskLevel.HIGH
    assert policy.default_approval == Approval.BLOCK
    assert policy.rules[0].name == "read_safe"


def test_policy_from_yaml(tmp_path: Path):
    yaml_content = textwrap.dedent("""\
        version: "1"
        defaults:
          risk_level: medium
          approval: approve
        rules:
          - name: read_ops
            match:
              type: read
            risk_level: low
            approval: auto
          - name: delete_block
            match:
              type: delete
            risk_level: critical
            approval: block
    """)
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(yaml_content)

    policy = Policy.from_yaml(policy_file)
    assert len(policy.rules) == 2

    # Test read -> auto
    decision = policy.evaluate(Action("read", "anything"))
    assert decision.approval == Approval.AUTO
    assert decision.risk_level == RiskLevel.LOW

    # Test delete -> block
    decision = policy.evaluate(Action("delete", "anything"))
    assert decision.approval == Approval.BLOCK
    assert decision.risk_level == RiskLevel.CRITICAL

    # Test unknown -> default
    decision = policy.evaluate(Action("deploy", "anything"))
    assert decision.approval == Approval.APPROVE
    assert decision.risk_level == RiskLevel.MEDIUM


def test_policy_from_yaml_missing_defaults():
    data = {
        "rules": [
            {"match": {"type": "read"}, "risk_level": "low", "approval": "auto"},
        ]
    }
    policy = Policy.from_dict(data)
    assert policy.default_risk_level == RiskLevel.MEDIUM
    assert policy.default_approval == Approval.APPROVE
