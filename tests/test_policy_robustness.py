"""Tests for Policy engine edge cases: empty YAML, invalid data, large rule sets."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from aegis.core.action import Action
from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.risk import RiskLevel

# -- Empty / None YAML data --------------------------------------------------


def test_from_dict_none_returns_default() -> None:
    """from_dict(None) should return a default policy (not crash)."""
    policy = Policy.from_dict(None)
    assert policy.default_risk_level == RiskLevel.MEDIUM
    assert policy.default_approval == Approval.BLOCK
    assert len(policy.rules) == 0


def test_from_dict_with_list_raises_type_error() -> None:
    """from_dict with a list should raise TypeError."""
    with pytest.raises(TypeError, match="Expected a dict"):
        Policy.from_dict(["rule1", "rule2"])  # type: ignore[arg-type]


def test_from_dict_with_string_raises_type_error() -> None:
    """from_dict with a string should raise TypeError."""
    with pytest.raises(TypeError, match="Expected a dict"):
        Policy.from_dict("not a dict")  # type: ignore[arg-type]


def test_from_dict_with_none_defaults() -> None:
    """defaults: null in YAML should not crash."""
    policy = Policy.from_dict({"defaults": None, "rules": []})
    assert policy.default_risk_level == RiskLevel.MEDIUM
    assert policy.default_approval == Approval.BLOCK


def test_from_dict_with_none_rules() -> None:
    """rules: null in YAML should not crash."""
    policy = Policy.from_dict({"rules": None})
    assert len(policy.rules) == 0


def test_from_yaml_empty_file(tmp_path: Path) -> None:
    """An empty YAML file should return a default policy."""
    f = tmp_path / "empty.yaml"
    f.write_text("")
    policy = Policy.from_yaml(f)
    assert len(policy.rules) == 0
    assert policy.default_risk_level == RiskLevel.MEDIUM


def test_from_yaml_nonexistent_file(tmp_path: Path) -> None:
    """Loading a nonexistent file should raise FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        Policy.from_yaml(tmp_path / "missing.yaml")


def test_from_yaml_syntax_error(tmp_path: Path) -> None:
    """A YAML file with syntax errors should raise an exception."""
    import yaml

    f = tmp_path / "bad.yaml"
    f.write_text(": : : broken {{{{")
    with pytest.raises(yaml.YAMLError):
        Policy.from_yaml(f)


def test_from_yaml_list_content(tmp_path: Path) -> None:
    """A YAML file containing a list should raise TypeError."""
    f = tmp_path / "list.yaml"
    f.write_text("- item1\n- item2\n")
    with pytest.raises(TypeError, match="Expected a dict"):
        Policy.from_yaml(f)


# -- Large rule sets --------------------------------------------------------


def test_policy_with_many_rules() -> None:
    """Policy with 1000+ rules should work correctly."""
    rules = []
    for i in range(1500):
        rules.append(
            PolicyRule(
                match_type=f"type_{i}",
                match_target=f"target_{i}",
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
                name=f"rule_{i}",
            )
        )

    policy = Policy(rules=rules)
    assert len(policy.rules) == 1500

    # First rule should match
    d = policy.evaluate(Action("type_0", "target_0"))
    assert d.matched_rule == "rule_0"

    # Last rule should match
    d = policy.evaluate(Action("type_1499", "target_1499"))
    assert d.matched_rule == "rule_1499"

    # No match -> default
    d = policy.evaluate(Action("unknown", "unknown"))
    assert d.matched_rule == "<default>"


def test_policy_many_rules_from_yaml(tmp_path: Path) -> None:
    """Large policy loaded from YAML should parse correctly."""
    rules_yaml = ""
    for i in range(200):
        rules_yaml += textwrap.dedent(f"""\
          - name: rule_{i}
            match:
              type: "type_{i}"
              target: "target_{i}"
            risk_level: low
            approval: auto
        """)

    yaml_content = f'version: "1"\nrules:\n{rules_yaml}'
    f = tmp_path / "big.yaml"
    f.write_text(yaml_content)

    policy = Policy.from_yaml(f)
    assert len(policy.rules) == 200


# -- Empty string in Action fields ------------------------------------------


def test_empty_action_type_matches_star() -> None:
    """Empty string action type should match wildcard '*'."""
    rule = PolicyRule(match_type="*", match_target="*", approval=Approval.AUTO)
    assert rule.matches(Action("", ""))


def test_empty_action_type_no_match_specific_rule() -> None:
    """Empty string action type should not match a specific rule."""
    rule = PolicyRule(match_type="read", match_target="db", approval=Approval.AUTO)
    assert not rule.matches(Action("", ""))


def test_action_str_with_empty_fields() -> None:
    """Action.__str__ with empty type/target should not crash."""
    a = Action("", "")
    s = str(a)
    assert "Action" in s


# -- Policy merge edge cases ------------------------------------------------


def test_merge_two_empty_policies() -> None:
    """Merging two empty policies should produce an empty policy."""
    p1 = Policy()
    p2 = Policy()
    merged = p1.merge(p2)
    assert len(merged.rules) == 0


def test_from_yaml_files_empty() -> None:
    """from_yaml_files with no paths should return an empty policy."""
    policy = Policy.from_yaml_files()
    assert len(policy.rules) == 0


def test_from_yaml_files_single(tmp_path: Path) -> None:
    """from_yaml_files with a single path should work like from_yaml."""
    f = tmp_path / "policy.yaml"
    f.write_text(
        textwrap.dedent("""\
        version: "1"
        rules:
          - name: test
            match: { type: read }
            risk_level: low
            approval: auto
    """)
    )

    policy = Policy.from_yaml_files(f)
    assert len(policy.rules) == 1


# -- Invalid risk_level/approval values ------------------------------------


def test_from_dict_invalid_risk_level() -> None:
    """Invalid risk_level string should raise KeyError."""
    with pytest.raises(KeyError):
        Policy.from_dict({"rules": [{"match": {"type": "read"}, "risk_level": "nonexistent"}]})


def test_from_dict_invalid_approval() -> None:
    """Invalid approval string should raise ValueError."""
    with pytest.raises(ValueError):
        Policy.from_dict({"rules": [{"match": {"type": "read"}, "approval": "nonexistent"}]})
