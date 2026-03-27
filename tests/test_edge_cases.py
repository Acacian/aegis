"""Edge case tests for the policy engine and conditions."""

from __future__ import annotations

from datetime import UTC, datetime

from aegis.core.action import Action
from aegis.core.conditions import evaluate_conditions
from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.risk import RiskLevel

# -- Empty / minimal policies -----------------------------------------------


def test_policy_with_no_rules_uses_defaults():
    policy = Policy(rules=[])
    decision = policy.evaluate(Action("anything", "anywhere"))
    assert decision.matched_rule == "<default>"
    assert decision.risk_level == RiskLevel.MEDIUM
    assert decision.approval == Approval.BLOCK


def test_policy_from_dict_empty_rules():
    policy = Policy.from_dict({"rules": []})
    decision = policy.evaluate(Action("read", "db"))
    assert decision.matched_rule == "<default>"


def test_policy_from_dict_no_rules_key():
    policy = Policy.from_dict({})
    decision = policy.evaluate(Action("read", "db"))
    assert decision.matched_rule == "<default>"


# -- Unicode in actions ------------------------------------------------------


def test_action_with_unicode_description():
    action = Action("read", "crm", description="연락처 조회")
    rule = PolicyRule(match_type="read", match_target="crm", approval=Approval.AUTO)
    assert rule.matches(action)


def test_action_with_unicode_target():
    action = Action("read", "데이터베이스")
    rule = PolicyRule(match_type="read", match_target="데이터베이스", approval=Approval.AUTO)
    assert rule.matches(action)


# -- Wildcard edge cases -----------------------------------------------------


def test_double_wildcard_matches_everything():
    rule = PolicyRule(match_type="*", match_target="*", approval=Approval.AUTO)
    assert rule.matches(Action("anything", "anywhere"))
    assert rule.matches(Action("", ""))


def test_empty_action_type_and_target():
    rule = PolicyRule(match_type="read", match_target="crm", approval=Approval.AUTO)
    assert not rule.matches(Action("", ""))


def test_glob_with_question_mark():
    rule = PolicyRule(match_type="read_?", match_target="*", approval=Approval.AUTO)
    assert rule.matches(Action("read_a", "db"))
    assert not rule.matches(Action("read_ab", "db"))


# -- Condition edge cases ----------------------------------------------------


def test_param_gt_with_equal_value():
    """Greater-than should NOT match equal values."""
    assert evaluate_conditions({"param_gt": {"count": 100}}, {"count": 100}) is False


def test_param_lt_with_equal_value():
    """Less-than should NOT match equal values."""
    assert evaluate_conditions({"param_lt": {"count": 100}}, {"count": 100}) is False


def test_param_contains_with_string():
    """Contains should work with string values too."""
    assert (
        evaluate_conditions({"param_contains": {"name": "admin"}}, {"name": "superadmin"}) is True
    )


def test_param_matches_with_empty_string():
    assert evaluate_conditions({"param_matches": {"field": ".*"}}, {"field": ""}) is True


def test_param_eq_with_none_param():
    """Missing param should return False, not raise."""
    assert evaluate_conditions({"param_eq": {"missing": "val"}}, {}) is False


def test_param_eq_with_numeric_types():
    """Equality check across numeric types."""
    assert evaluate_conditions({"param_eq": {"count": 1}}, {"count": 1}) is True
    assert evaluate_conditions({"param_eq": {"count": 1}}, {"count": 1.0}) is True


def test_multiple_params_in_single_condition():
    """All params in a single condition dict must match."""
    cond = {"param_eq": {"status": "active", "role": "admin"}}
    assert evaluate_conditions(cond, {"status": "active", "role": "admin"}) is True
    assert evaluate_conditions(cond, {"status": "active", "role": "user"}) is False


def test_time_at_exact_boundary():
    """time_after at exact boundary should pass (>=)."""
    now = datetime(2026, 3, 21, 18, 0, tzinfo=UTC)
    assert evaluate_conditions({"time_after": "18:00"}, {}, now=now) is True
    assert evaluate_conditions({"time_before": "18:00"}, {}, now=now) is False


def test_weekdays_with_sunday():
    """Sunday = isoweekday 7."""
    now = datetime(2026, 3, 22, 12, 0, tzinfo=UTC)  # Sunday
    assert evaluate_conditions({"weekdays": [7]}, {}, now=now) is True
    assert evaluate_conditions({"weekdays": [1, 2, 3, 4, 5]}, {}, now=now) is False


# -- Policy rule ordering with conditions -----------------------------------


def test_condition_failure_falls_through():
    """If a rule's conditions fail, evaluation should fall through to next rule."""
    policy = Policy(
        rules=[
            PolicyRule(
                match_type="update",
                conditions={"param_gt": {"count": 100}},
                risk_level=RiskLevel.HIGH,
                approval=Approval.APPROVE,
                name="big_update",
            ),
            PolicyRule(
                match_type="update",
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
                name="small_update",
            ),
        ]
    )
    # Small count → falls through to second rule
    d = policy.evaluate(Action("update", "db", params={"count": 10}))
    assert d.matched_rule == "small_update"
    assert d.approval == Approval.AUTO


# -- Regex safety in param_matches ------------------------------------------


def test_param_matches_invalid_regex_does_not_crash():
    """Invalid regex in param_matches should not crash the engine."""
    # Invalid regex patterns should return False instead of raising
    result = evaluate_conditions({"param_matches": {"field": "[invalid"}}, {"field": "test"})
    assert result is False


def test_param_matches_with_special_chars():
    """Regex special characters in the value being matched."""
    assert (
        evaluate_conditions(
            {"param_matches": {"url": r"https://example\.com"}},
            {"url": "https://example.com/path"},
        )
        is True
    )


# -- PolicyDecision properties -----------------------------------------------


def test_policy_decision_str_repr():
    from aegis.core.policy import PolicyDecision

    d = PolicyDecision(
        action=Action("read", "crm"),
        risk_level=RiskLevel.LOW,
        approval=Approval.AUTO,
        matched_rule="read_auto",
    )
    text = str(d)
    assert "read" in text
