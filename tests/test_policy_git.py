"""Tests for policy-as-code Git integration."""

from __future__ import annotations

from aegis.core.policy_git import (
    PolicyDiffFormatter,
    PolicyDriftDetector,
    PolicyImpactAnalyzer,
    export_policy_yaml,
)
from aegis.core.versioning import PolicyDelta

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_policy_dict(
    rules: list[dict] | None = None,
    defaults: dict | None = None,
) -> dict:
    """Build a minimal policy dict."""
    return {
        "version": "1",
        "defaults": defaults or {"risk_level": "medium", "approval": "approve"},
        "scope": "global",
        "scope_id": "",
        "rules": rules or [],
    }


def _make_rule(name: str, risk: str = "medium", approval: str = "auto") -> dict:
    return {
        "name": name,
        "match": {"type": "*", "target": "*", "agent": "*"},
        "risk_level": risk,
        "approval": approval,
    }


def _make_delta(
    added: list[str] | None = None,
    removed: list[str] | None = None,
    modified: list[str] | None = None,
    defaults_changed: dict | None = None,
) -> PolicyDelta:
    return PolicyDelta(
        version_from="aaa11111",
        version_to="bbb22222",
        rules_added=added or [],
        rules_removed=removed or [],
        rules_modified=modified or [],
        defaults_changed=defaults_changed or {},
    )


# ---------------------------------------------------------------------------
# PolicyDiffFormatter
# ---------------------------------------------------------------------------


class TestPolicyDiffFormatter:
    def test_empty_delta_text(self) -> None:
        fmt = PolicyDiffFormatter()
        text = fmt.to_text(_make_delta())
        assert "No changes detected" in text

    def test_empty_delta_markdown(self) -> None:
        fmt = PolicyDiffFormatter()
        md = fmt.to_markdown(_make_delta())
        assert "No policy changes detected" in md

    def test_added_rules_text(self) -> None:
        fmt = PolicyDiffFormatter()
        delta = _make_delta(added=["rule-a", "rule-b"])
        text = fmt.to_text(delta)
        assert "+ Rules Added (2)" in text
        assert "rule-a" in text
        assert "rule-b" in text

    def test_removed_rules_text(self) -> None:
        fmt = PolicyDiffFormatter()
        delta = _make_delta(removed=["old-rule"])
        text = fmt.to_text(delta)
        assert "- Rules Removed (1)" in text
        assert "old-rule" in text

    def test_modified_rules_text(self) -> None:
        fmt = PolicyDiffFormatter()
        delta = _make_delta(modified=["changed-rule"])
        text = fmt.to_text(delta)
        assert "~ Rules Modified" in text
        assert "changed-rule" in text

    def test_defaults_changed_text(self) -> None:
        fmt = PolicyDiffFormatter()
        delta = _make_delta(defaults_changed={"risk_level": ("low", "high")})
        text = fmt.to_text(delta)
        assert "Defaults Changed" in text
        assert "low" in text
        assert "high" in text

    def test_markdown_summary(self) -> None:
        fmt = PolicyDiffFormatter()
        delta = _make_delta(added=["a"], removed=["b"], modified=["c"])
        md = fmt.to_markdown(delta)
        assert "**Summary:**" in md
        assert "+1 added" in md
        assert "-1 removed" in md
        assert "~1 modified" in md

    def test_markdown_tables(self) -> None:
        fmt = PolicyDiffFormatter()
        delta = _make_delta(defaults_changed={"approval": ("auto", "block")})
        md = fmt.to_markdown(delta)
        assert "| Setting | Before | After |" in md
        assert "`approval`" in md


# ---------------------------------------------------------------------------
# PolicyImpactAnalyzer
# ---------------------------------------------------------------------------


class TestPolicyImpactAnalyzer:
    def test_no_changes(self) -> None:
        analyzer = PolicyImpactAnalyzer()
        policy = _make_policy_dict(rules=[_make_rule("r1")])
        report = analyzer.analyze(policy, policy)
        assert report.severity == "info"
        assert not report.affected_action_types

    def test_added_blocking_rule(self) -> None:
        analyzer = PolicyImpactAnalyzer()
        old = _make_policy_dict(rules=[])
        new = _make_policy_dict(rules=[_make_rule("block-web", approval="block")])
        report = analyzer.analyze(old, new)
        assert "block-web" in report.affected_action_types
        assert "block-web" in report.newly_blocked
        assert report.severity in ("warning", "critical")

    def test_removed_blocking_rule(self) -> None:
        analyzer = PolicyImpactAnalyzer()
        old = _make_policy_dict(rules=[_make_rule("block-web", approval="block")])
        new = _make_policy_dict(rules=[])
        report = analyzer.analyze(old, new)
        assert "block-web" in report.newly_allowed

    def test_risk_escalation(self) -> None:
        analyzer = PolicyImpactAnalyzer()
        old = _make_policy_dict(rules=[_make_rule("r1", risk="low")])
        new = _make_policy_dict(rules=[_make_rule("r1", risk="high")])
        report = analyzer.analyze(old, new)
        assert "r1" in report.risk_escalations
        assert report.severity == "warning"

    def test_risk_deescalation(self) -> None:
        analyzer = PolicyImpactAnalyzer()
        old = _make_policy_dict(rules=[_make_rule("r1", risk="high")])
        new = _make_policy_dict(rules=[_make_rule("r1", risk="low")])
        report = analyzer.analyze(old, new)
        assert "r1" in report.risk_deescalations

    def test_approval_change(self) -> None:
        analyzer = PolicyImpactAnalyzer()
        old = _make_policy_dict(rules=[_make_rule("r1", approval="auto")])
        new = _make_policy_dict(rules=[_make_rule("r1", approval="approve")])
        report = analyzer.analyze(old, new)
        assert "r1" in report.approval_changes

    def test_critical_severity(self) -> None:
        analyzer = PolicyImpactAnalyzer()
        old = _make_policy_dict(rules=[])
        new = _make_policy_dict(
            rules=[_make_rule(f"block-{i}", approval="block") for i in range(5)]
        )
        report = analyzer.analyze(old, new)
        assert report.severity == "critical"


# ---------------------------------------------------------------------------
# PolicyDriftDetector (dict-based)
# ---------------------------------------------------------------------------


class TestPolicyDriftDetector:
    def test_no_drift(self) -> None:
        detector = PolicyDriftDetector()
        policy = _make_policy_dict(rules=[_make_rule("r1")])
        result = detector.detect_from_dicts(policy, policy)
        assert not result.has_drift
        assert result.file_hash == result.running_hash
        assert result.delta is None

    def test_drift_detected(self) -> None:
        detector = PolicyDriftDetector()
        running = _make_policy_dict(rules=[_make_rule("r1")])
        on_disk = _make_policy_dict(rules=[_make_rule("r1"), _make_rule("r2")])
        result = detector.detect_from_dicts(on_disk, running)
        assert result.has_drift
        assert result.file_hash != result.running_hash
        assert result.delta is not None
        assert "r2" in result.delta.rules_added

    def test_drift_with_removed_rule(self) -> None:
        detector = PolicyDriftDetector()
        running = _make_policy_dict(rules=[_make_rule("r1"), _make_rule("r2")])
        on_disk = _make_policy_dict(rules=[_make_rule("r1")])
        result = detector.detect_from_dicts(on_disk, running)
        assert result.has_drift
        assert "r2" in result.delta.rules_removed

    def test_drift_with_defaults_change(self) -> None:
        detector = PolicyDriftDetector()
        running = _make_policy_dict(
            rules=[],
            defaults={"risk_level": "low", "approval": "auto"},
        )
        on_disk = _make_policy_dict(
            rules=[],
            defaults={"risk_level": "high", "approval": "auto"},
        )
        result = detector.detect_from_dicts(on_disk, running)
        assert result.has_drift
        assert "risk_level" in result.delta.defaults_changed


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


class TestPolicyExport:
    def test_export_basic(self) -> None:
        """Export produces valid YAML-like string."""
        from types import SimpleNamespace

        policy = SimpleNamespace(
            version=1,
            default_risk_level="medium",
            default_approval="approve",
            scope="global",
            scope_id="",
            rules=[],
        )
        yaml_str = export_policy_yaml(policy)
        assert "version:" in yaml_str
        assert "defaults:" in yaml_str
        assert "risk_level: medium" in yaml_str

    def test_export_with_rules(self) -> None:
        from types import SimpleNamespace

        rule = SimpleNamespace(
            name="read-rule",
            match_type="read",
            match_target="*",
            match_agent="*",
            risk_level=SimpleNamespace(name="LOW"),
            approval=SimpleNamespace(value="auto"),
            conditions=None,
        )
        policy = SimpleNamespace(
            version=1,
            default_risk_level="medium",
            default_approval="approve",
            scope="global",
            scope_id="",
            rules=[rule],
        )
        yaml_str = export_policy_yaml(policy)
        assert "read-rule" in yaml_str
        assert "approval: auto" in yaml_str
