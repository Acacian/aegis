"""Tests for policy conditions."""

from __future__ import annotations

from datetime import UTC, datetime

from aegis.core.action import Action
from aegis.core.conditions import evaluate_conditions
from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.risk import RiskLevel

# -- evaluate_conditions unit tests ---


def test_empty_conditions_always_pass():
    assert evaluate_conditions({}, {}) is True


def test_time_after_passes():
    now = datetime(2026, 3, 21, 20, 0, tzinfo=UTC)  # 20:00
    assert evaluate_conditions({"time_after": "18:00"}, {}, now=now) is True


def test_time_after_fails():
    now = datetime(2026, 3, 21, 10, 0, tzinfo=UTC)  # 10:00
    assert evaluate_conditions({"time_after": "18:00"}, {}, now=now) is False


def test_time_before_passes():
    now = datetime(2026, 3, 21, 6, 0, tzinfo=UTC)  # 06:00
    assert evaluate_conditions({"time_before": "08:00"}, {}, now=now) is True


def test_time_before_fails():
    now = datetime(2026, 3, 21, 10, 0, tzinfo=UTC)  # 10:00
    assert evaluate_conditions({"time_before": "08:00"}, {}, now=now) is False


def test_weekdays_passes():
    # 2026-03-20 is a Friday (isoweekday=5)
    now = datetime(2026, 3, 20, 12, 0, tzinfo=UTC)
    assert evaluate_conditions({"weekdays": [1, 2, 3, 4, 5]}, {}, now=now) is True


def test_weekdays_fails():
    # 2026-03-21 is a Saturday (isoweekday=6)
    now = datetime(2026, 3, 21, 12, 0, tzinfo=UTC)
    assert evaluate_conditions({"weekdays": [1, 2, 3, 4, 5]}, {}, now=now) is False


def test_param_eq():
    assert evaluate_conditions({"param_eq": {"status": "active"}}, {"status": "active"}) is True
    assert evaluate_conditions({"param_eq": {"status": "active"}}, {"status": "inactive"}) is False


def test_param_gt():
    assert evaluate_conditions({"param_gt": {"count": 100}}, {"count": 150}) is True
    assert evaluate_conditions({"param_gt": {"count": 100}}, {"count": 50}) is False


def test_param_lt():
    assert evaluate_conditions({"param_lt": {"count": 100}}, {"count": 50}) is True
    assert evaluate_conditions({"param_lt": {"count": 100}}, {"count": 150}) is False


def test_param_gte():
    assert evaluate_conditions({"param_gte": {"count": 100}}, {"count": 100}) is True
    assert evaluate_conditions({"param_gte": {"count": 100}}, {"count": 99}) is False


def test_param_lte():
    assert evaluate_conditions({"param_lte": {"count": 100}}, {"count": 100}) is True
    assert evaluate_conditions({"param_lte": {"count": 100}}, {"count": 101}) is False


def test_param_contains():
    assert evaluate_conditions({"param_contains": {"tags": "admin"}}, {"tags": ["admin", "user"]})
    assert not evaluate_conditions({"param_contains": {"tags": "root"}}, {"tags": ["admin"]})


def test_param_matches_regex():
    assert evaluate_conditions(
        {"param_matches": {"email": r"@example\.com$"}},
        {"email": "alice@example.com"},
    )
    assert not evaluate_conditions(
        {"param_matches": {"email": r"@example\.com$"}},
        {"email": "alice@other.com"},
    )


def test_param_missing_returns_false():
    assert evaluate_conditions({"param_eq": {"missing_key": "val"}}, {}) is False


def test_multiple_conditions_all_must_pass():
    now = datetime(2026, 3, 20, 14, 0, tzinfo=UTC)  # Friday 14:00
    conditions = {
        "weekdays": [1, 2, 3, 4, 5],
        "time_after": "09:00",
        "param_gt": {"count": 10},
    }
    assert evaluate_conditions(conditions, {"count": 50}, now=now) is True


def test_multiple_conditions_one_fails():
    now = datetime(2026, 3, 21, 14, 0, tzinfo=UTC)  # Saturday 14:00
    conditions = {
        "weekdays": [1, 2, 3, 4, 5],
        "time_after": "09:00",
    }
    assert evaluate_conditions(conditions, {}, now=now) is False


def test_unknown_condition_ignored():
    assert evaluate_conditions({"unknown_key": "val"}, {}) is True


# -- Integration with PolicyRule ---


def test_rule_with_conditions():
    rule = PolicyRule(
        match_type="update*",
        risk_level=RiskLevel.HIGH,
        approval=Approval.APPROVE,
        name="bulk_ops",
        conditions={"param_gt": {"count": 100}},
    )
    # Glob matches + condition matches
    assert rule.matches(Action("update", "db", params={"count": 150}))
    # Glob matches but condition fails
    assert not rule.matches(Action("update", "db", params={"count": 50}))
    # Glob doesn't match
    assert not rule.matches(Action("delete", "db", params={"count": 150}))


def test_rule_without_conditions_backward_compat():
    """Rules without conditions should work exactly as before."""
    rule = PolicyRule(match_type="read", approval=Approval.AUTO)
    assert rule.matches(Action("read", "db"))
    assert not rule.matches(Action("write", "db"))


def test_policy_from_dict_with_conditions():
    """Conditions should be loaded from dict/YAML."""
    policy = Policy.from_dict({
        "version": "1",
        "defaults": {"risk_level": "medium", "approval": "approve"},
        "rules": [
            {
                "name": "bulk_block",
                "match": {"type": "update*"},
                "conditions": {"param_gt": {"count": 1000}},
                "risk_level": "critical",
                "approval": "block",
            },
            {
                "name": "update_ok",
                "match": {"type": "update*"},
                "risk_level": "low",
                "approval": "auto",
            },
        ],
    })

    # Bulk update (count > 1000) → blocked
    d1 = policy.evaluate(Action("update", "db", params={"count": 5000}))
    assert d1.approval == Approval.BLOCK
    assert d1.matched_rule == "bulk_block"

    # Small update → falls through to second rule
    d2 = policy.evaluate(Action("update", "db", params={"count": 10}))
    assert d2.approval == Approval.AUTO
    assert d2.matched_rule == "update_ok"
