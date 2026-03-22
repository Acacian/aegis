"""Tests for aegis.core.diff — policy diff and impact analysis engine."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from aegis.core.action import Action
from aegis.core.diff import (
    ImpactEntry,
    PolicyDiffResult,
    RuleDiff,
    analyze_impact,
    diff_policies,
)
from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.risk import RiskLevel

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE_YAML = textwrap.dedent("""\
    version: "1"
    defaults:
      risk_level: low
      approval: auto
    rules:
      - name: read_ops
        match: { type: "read*" }
        risk_level: low
        approval: auto
      - name: write_crm
        match: { type: "write*", target: "crm" }
        risk_level: medium
        approval: auto
      - name: old_legacy
        match: { type: "legacy_*" }
        risk_level: low
        approval: auto
""")

_NEW_YAML = textwrap.dedent("""\
    version: "1"
    defaults:
      risk_level: medium
      approval: approve
    rules:
      - name: read_ops
        match: { type: "read*" }
        risk_level: low
        approval: auto
      - name: write_crm
        match: { type: "write*", target: "crm" }
        risk_level: medium
        approval: approve
      - name: strict_delete
        match: { type: "delete_*" }
        risk_level: critical
        approval: block
      - name: review_bulk
        match: { type: "bulk_*" }
        risk_level: high
        approval: approve
""")


def _load(tmp_path: Path, content: str, name: str = "policy.yaml") -> Policy:
    p = tmp_path / name
    p.write_text(content)
    return Policy.from_yaml(p)


# ---------------------------------------------------------------------------
# diff_policies tests
# ---------------------------------------------------------------------------


class TestDiffPolicies:
    """Test suite for diff_policies()."""

    def test_identical_policies(self) -> None:
        policy = Policy(
            rules=[
                PolicyRule(
                    name="r1",
                    match_type="read*",
                    risk_level=RiskLevel.LOW,
                    approval=Approval.AUTO,
                ),
            ],
            default_risk_level=RiskLevel.MEDIUM,
            default_approval=Approval.APPROVE,
        )
        result = diff_policies(policy, policy)

        assert result.rules_added == []
        assert result.rules_removed == []
        assert result.rules_modified == []
        assert result.defaults_changed == {}
        assert result.impact_summary == "no changes"

    def test_added_rules(self, tmp_path: Path) -> None:
        old = _load(tmp_path, _BASE_YAML, "old.yaml")
        new = _load(tmp_path, _NEW_YAML, "new.yaml")
        result = diff_policies(old, new)

        added_names = [r.rule_name for r in result.rules_added]
        assert "strict_delete" in added_names
        assert "review_bulk" in added_names
        assert len(result.rules_added) == 2

        for rd in result.rules_added:
            assert rd.change_type == "added"
            assert rd.old_value is None
            assert rd.new_value is not None

    def test_removed_rules(self, tmp_path: Path) -> None:
        old = _load(tmp_path, _BASE_YAML, "old.yaml")
        new = _load(tmp_path, _NEW_YAML, "new.yaml")
        result = diff_policies(old, new)

        removed_names = [r.rule_name for r in result.rules_removed]
        assert "old_legacy" in removed_names
        assert len(result.rules_removed) == 1

        for rd in result.rules_removed:
            assert rd.change_type == "removed"
            assert rd.old_value is not None
            assert rd.new_value is None

    def test_modified_rules(self, tmp_path: Path) -> None:
        old = _load(tmp_path, _BASE_YAML, "old.yaml")
        new = _load(tmp_path, _NEW_YAML, "new.yaml")
        result = diff_policies(old, new)

        modified_names = [r.rule_name for r in result.rules_modified]
        assert "write_crm" in modified_names
        assert len(result.rules_modified) == 1

        wr = result.rules_modified[0]
        assert wr.change_type == "modified"
        assert "approval" in wr.fields_changed

    def test_defaults_changed(self, tmp_path: Path) -> None:
        old = _load(tmp_path, _BASE_YAML, "old.yaml")
        new = _load(tmp_path, _NEW_YAML, "new.yaml")
        result = diff_policies(old, new)

        assert "risk_level" in result.defaults_changed
        assert result.defaults_changed["risk_level"] == ("low", "medium")
        assert "approval" in result.defaults_changed
        assert result.defaults_changed["approval"] == ("auto", "approve")

    def test_impact_summary_text(self, tmp_path: Path) -> None:
        old = _load(tmp_path, _BASE_YAML, "old.yaml")
        new = _load(tmp_path, _NEW_YAML, "new.yaml")
        result = diff_policies(old, new)

        assert "added" in result.impact_summary
        assert "removed" in result.impact_summary
        assert "modified" in result.impact_summary
        assert "default" in result.impact_summary

    def test_no_defaults_change_when_same(self) -> None:
        policy = Policy(
            default_risk_level=RiskLevel.MEDIUM,
            default_approval=Approval.APPROVE,
        )
        result = diff_policies(policy, policy)
        assert result.defaults_changed == {}

    def test_only_defaults_changed(self) -> None:
        old = Policy(
            default_risk_level=RiskLevel.LOW,
            default_approval=Approval.AUTO,
        )
        new = Policy(
            default_risk_level=RiskLevel.HIGH,
            default_approval=Approval.BLOCK,
        )
        result = diff_policies(old, new)

        assert result.rules_added == []
        assert result.rules_removed == []
        assert result.rules_modified == []
        assert result.defaults_changed["risk_level"] == ("low", "high")
        assert result.defaults_changed["approval"] == ("auto", "block")


# ---------------------------------------------------------------------------
# analyze_impact tests
# ---------------------------------------------------------------------------


class TestAnalyzeImpact:
    """Test suite for analyze_impact()."""

    def test_unchanged_actions(self) -> None:
        policy = Policy(
            rules=[
                PolicyRule(
                    name="r1",
                    match_type="read*",
                    risk_level=RiskLevel.LOW,
                    approval=Approval.AUTO,
                ),
            ],
        )
        actions = [Action(type="read", target="crm")]
        entries = analyze_impact(policy, policy, actions)

        assert len(entries) == 1
        assert entries[0].change == "unchanged"
        assert entries[0].old_decision == "auto"
        assert entries[0].new_decision == "auto"

    def test_restricted_actions(self, tmp_path: Path) -> None:
        old = _load(tmp_path, _BASE_YAML, "old.yaml")
        new = _load(tmp_path, _NEW_YAML, "new.yaml")

        actions = [Action(type="write", target="crm")]
        entries = analyze_impact(old, new, actions)

        assert len(entries) == 1
        assert entries[0].old_decision == "auto"
        assert entries[0].new_decision == "approve"
        assert entries[0].change == "restricted"

    def test_promoted_actions(self) -> None:
        old = Policy(
            rules=[
                PolicyRule(name="r1", match_type="read*", approval=Approval.APPROVE),
            ],
        )
        new = Policy(
            rules=[
                PolicyRule(name="r1", match_type="read*", approval=Approval.AUTO),
            ],
        )
        actions = [Action(type="read", target="db")]
        entries = analyze_impact(old, new, actions)

        assert entries[0].change == "promoted"
        assert entries[0].old_decision == "approve"
        assert entries[0].new_decision == "auto"

    def test_blocked_actions(self, tmp_path: Path) -> None:
        old = _load(tmp_path, _BASE_YAML, "old.yaml")
        new = _load(tmp_path, _NEW_YAML, "new.yaml")

        actions = [Action(type="delete_user", target="db")]
        entries = analyze_impact(old, new, actions)

        assert len(entries) == 1
        # Old policy: falls to default (auto), new: strict_delete -> block
        assert entries[0].new_decision == "block"
        assert entries[0].change == "restricted"

    def test_multiple_actions(self, tmp_path: Path) -> None:
        old = _load(tmp_path, _BASE_YAML, "old.yaml")
        new = _load(tmp_path, _NEW_YAML, "new.yaml")

        actions = [
            Action(type="read", target="crm"),
            Action(type="write", target="crm"),
            Action(type="delete_user", target="db"),
            Action(type="legacy_op", target="sys"),
        ]
        entries = analyze_impact(old, new, actions)

        assert len(entries) == 4

        changes = {e.action_type: e.change for e in entries}
        assert changes["read"] == "unchanged"
        assert changes["write"] == "restricted"
        assert changes["delete_user"] == "restricted"

    def test_empty_actions(self) -> None:
        policy = Policy()
        entries = analyze_impact(policy, policy, [])
        assert entries == []

    def test_default_fallback_impact(self) -> None:
        """Actions not matching any rule use defaults."""
        old = Policy(default_approval=Approval.AUTO)
        new = Policy(default_approval=Approval.BLOCK)

        actions = [Action(type="anything", target="anywhere")]
        entries = analyze_impact(old, new, actions)

        assert entries[0].old_decision == "auto"
        assert entries[0].new_decision == "block"
        assert entries[0].change == "restricted"


# ---------------------------------------------------------------------------
# Dataclass tests
# ---------------------------------------------------------------------------


class TestDataclasses:
    """Verify frozen dataclass behavior."""

    def test_rule_diff_frozen(self) -> None:
        rd = RuleDiff(rule_name="x", change_type="added", old_value=None, new_value={})
        with pytest.raises(AttributeError):
            rd.rule_name = "y"  # type: ignore[misc]

    def test_policy_diff_result_frozen(self) -> None:
        pdr = PolicyDiffResult(
            rules_added=[],
            rules_removed=[],
            rules_modified=[],
            defaults_changed={},
            impact_summary="",
        )
        with pytest.raises(AttributeError):
            pdr.impact_summary = "changed"  # type: ignore[misc]

    def test_impact_entry_frozen(self) -> None:
        ie = ImpactEntry(
            action_type="read",
            target="db",
            old_decision="auto",
            new_decision="block",
            change="restricted",
        )
        with pytest.raises(AttributeError):
            ie.change = "promoted"  # type: ignore[misc]
