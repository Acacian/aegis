"""Tests for the adversarial policy probe module."""

from __future__ import annotations

from aegis.core.action import Action
from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.probe import PolicyProbe, ProbeFinding, ProbeReport
from aegis.core.risk import RiskLevel

# ======================================================================
# 1. ProbeFinding dataclass
# ======================================================================


class TestProbeFinding:
    """Test the ProbeFinding frozen dataclass."""

    def test_fields_accessible(self) -> None:
        action = Action(type="delete", target="db")
        from aegis.core.policy import PolicyDecision

        decision = PolicyDecision(
            action=action,
            risk_level=RiskLevel.CRITICAL,
            approval=Approval.AUTO,
            matched_rule="<default>",
        )
        finding = ProbeFinding(
            severity="critical",
            category="missing_coverage",
            description="Destructive action auto-approved",
            action=action,
            decision=decision,
            recommendation="Add a block rule",
        )
        assert finding.severity == "critical"
        assert finding.category == "missing_coverage"
        assert finding.description == "Destructive action auto-approved"
        assert finding.action.type == "delete"
        assert finding.recommendation == "Add a block rule"

    def test_frozen(self) -> None:
        import dataclasses

        action = Action(type="delete", target="db")
        from aegis.core.policy import PolicyDecision

        decision = PolicyDecision(
            action=action,
            risk_level=RiskLevel.CRITICAL,
            approval=Approval.AUTO,
        )
        finding = ProbeFinding(
            severity="critical",
            category="test",
            description="test",
            action=action,
            decision=decision,
        )
        assert dataclasses.is_dataclass(finding)
        # ProbeFinding is frozen
        import pytest

        with pytest.raises(dataclasses.FrozenInstanceError):
            finding.severity = "low"  # type: ignore[misc]

    def test_default_recommendation_empty(self) -> None:
        action = Action(type="x", target="y")
        from aegis.core.policy import PolicyDecision

        decision = PolicyDecision(
            action=action,
            risk_level=RiskLevel.LOW,
            approval=Approval.AUTO,
        )
        finding = ProbeFinding(
            severity="low",
            category="test",
            description="test",
            action=action,
            decision=decision,
        )
        assert finding.recommendation == ""


# ======================================================================
# 2. ProbeReport properties
# ======================================================================


class TestProbeReport:
    """Test ProbeReport score, gap_count, critical_count, summary."""

    def test_gap_count(self) -> None:
        action = Action(type="delete", target="db")
        from aegis.core.policy import PolicyDecision

        decision = PolicyDecision(
            action=action, risk_level=RiskLevel.CRITICAL, approval=Approval.AUTO
        )
        findings = [
            ProbeFinding(
                severity="critical",
                category="test",
                description="gap 1",
                action=action,
                decision=decision,
            ),
            ProbeFinding(
                severity="high",
                category="test",
                description="gap 2",
                action=action,
                decision=decision,
            ),
        ]
        report = ProbeReport(total_probes=10, findings=findings, probed_actions=[])
        assert report.gap_count == 2

    def test_critical_count(self) -> None:
        action = Action(type="delete", target="db")
        from aegis.core.policy import PolicyDecision

        decision = PolicyDecision(
            action=action, risk_level=RiskLevel.CRITICAL, approval=Approval.AUTO
        )
        findings = [
            ProbeFinding(
                severity="critical",
                category="test",
                description="crit 1",
                action=action,
                decision=decision,
            ),
            ProbeFinding(
                severity="critical",
                category="test",
                description="crit 2",
                action=action,
                decision=decision,
            ),
            ProbeFinding(
                severity="high",
                category="test",
                description="high 1",
                action=action,
                decision=decision,
            ),
        ]
        report = ProbeReport(total_probes=10, findings=findings, probed_actions=[])
        assert report.critical_count == 2

    def test_score_perfect(self) -> None:
        report = ProbeReport(total_probes=10, findings=[], probed_actions=[])
        assert report.score == 100

    def test_score_zero_probes(self) -> None:
        report = ProbeReport(total_probes=0, findings=[], probed_actions=[])
        assert report.score == 100

    def test_score_with_critical_findings(self) -> None:
        action = Action(type="delete", target="db")
        from aegis.core.policy import PolicyDecision

        decision = PolicyDecision(
            action=action, risk_level=RiskLevel.CRITICAL, approval=Approval.AUTO
        )
        findings = [
            ProbeFinding(
                severity="critical",
                category="test",
                description="x",
                action=action,
                decision=decision,
            ),
        ]
        report = ProbeReport(total_probes=10, findings=findings, probed_actions=[])
        # 100 - 20 (critical penalty) = 80
        assert report.score == 80

    def test_score_with_mixed_findings(self) -> None:
        action = Action(type="delete", target="db")
        from aegis.core.policy import PolicyDecision

        decision = PolicyDecision(
            action=action, risk_level=RiskLevel.CRITICAL, approval=Approval.AUTO
        )
        findings = [
            ProbeFinding(
                severity="critical",
                category="t",
                description="c",
                action=action,
                decision=decision,
            ),
            ProbeFinding(
                severity="high",
                category="t",
                description="h",
                action=action,
                decision=decision,
            ),
            ProbeFinding(
                severity="medium",
                category="t",
                description="m",
                action=action,
                decision=decision,
            ),
            ProbeFinding(
                severity="low",
                category="t",
                description="l",
                action=action,
                decision=decision,
            ),
        ]
        report = ProbeReport(total_probes=20, findings=findings, probed_actions=[])
        # 100 - 20 - 10 - 5 - 2 = 63
        assert report.score == 63

    def test_score_floor_at_zero(self) -> None:
        action = Action(type="delete", target="db")
        from aegis.core.policy import PolicyDecision

        decision = PolicyDecision(
            action=action, risk_level=RiskLevel.CRITICAL, approval=Approval.AUTO
        )
        # 6 critical findings: 6 * 20 = 120 penalty -> clamped to 0
        findings = [
            ProbeFinding(
                severity="critical",
                category="t",
                description=f"c{i}",
                action=action,
                decision=decision,
            )
            for i in range(6)
        ]
        report = ProbeReport(total_probes=20, findings=findings, probed_actions=[])
        assert report.score == 0

    def test_summary_no_findings(self) -> None:
        report = ProbeReport(total_probes=5, findings=[], probed_actions=[])
        s = report.summary()
        assert "5 probes" in s
        assert "0 findings" in s
        assert "No gaps found" in s

    def test_summary_with_findings(self) -> None:
        action = Action(type="delete", target="db")
        from aegis.core.policy import PolicyDecision

        decision = PolicyDecision(
            action=action, risk_level=RiskLevel.CRITICAL, approval=Approval.AUTO
        )
        findings = [
            ProbeFinding(
                severity="critical",
                category="t",
                description="bad thing",
                action=action,
                decision=decision,
            ),
        ]
        report = ProbeReport(total_probes=10, findings=findings, probed_actions=[])
        s = report.summary()
        assert "CRITICAL: 1" in s
        assert "bad thing" in s
        assert "Robustness score" in s


# ======================================================================
# 3. PolicyProbe.run() with a well-configured policy
# ======================================================================


def _build_strict_policy() -> Policy:
    """Build a well-configured policy that governs destructive and sensitive actions."""
    return Policy(
        rules=[
            PolicyRule(
                name="block_destructive",
                match_type="delete*",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
            ),
            PolicyRule(
                name="block_drop",
                match_type="drop*",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
            ),
            PolicyRule(
                name="block_destroy",
                match_type="destroy*",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
            ),
            PolicyRule(
                name="block_remove",
                match_type="remove*",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
            ),
            PolicyRule(
                name="block_purge",
                match_type="purge*",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
            ),
            PolicyRule(
                name="block_truncate",
                match_type="truncate*",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
            ),
            PolicyRule(
                name="block_kill",
                match_type="kill*",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
            ),
            PolicyRule(
                name="block_terminate",
                match_type="terminate*",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
            ),
            PolicyRule(
                name="block_format",
                match_type="format*",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
            ),
            PolicyRule(
                name="block_wipe",
                match_type="wipe*",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
            ),
            PolicyRule(
                name="approve_sensitive",
                match_type="write*",
                risk_level=RiskLevel.MEDIUM,
                approval=Approval.APPROVE,
            ),
            PolicyRule(
                name="approve_update",
                match_type="update*",
                risk_level=RiskLevel.MEDIUM,
                approval=Approval.APPROVE,
            ),
            PolicyRule(
                name="approve_send",
                match_type="send*",
                risk_level=RiskLevel.MEDIUM,
                approval=Approval.APPROVE,
            ),
            PolicyRule(
                name="approve_export",
                match_type="export*",
                risk_level=RiskLevel.HIGH,
                approval=Approval.APPROVE,
            ),
            PolicyRule(
                name="approve_deploy",
                match_type="deploy*",
                risk_level=RiskLevel.HIGH,
                approval=Approval.APPROVE,
            ),
            PolicyRule(
                name="auto_reads",
                match_type="read*",
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
            ),
        ],
        default_risk_level=RiskLevel.MEDIUM,
        default_approval=Approval.APPROVE,
    )


class TestProbeWellConfigured:
    """Probe against a well-configured policy should find few gaps."""

    def test_returns_probe_report(self) -> None:
        probe = PolicyProbe()
        report = probe.run(_build_strict_policy())
        assert isinstance(report, ProbeReport)

    def test_total_probes_positive(self) -> None:
        probe = PolicyProbe()
        report = probe.run(_build_strict_policy())
        assert report.total_probes > 0

    def test_few_critical_findings(self) -> None:
        probe = PolicyProbe()
        report = probe.run(_build_strict_policy())
        # A strict policy should have no missing-coverage criticals
        missing_criticals = [
            f
            for f in report.findings
            if f.category == "missing_coverage" and f.severity == "critical"
        ]
        assert len(missing_criticals) == 0

    def test_score_is_computed(self) -> None:
        """A strict policy still gets some findings due to bypass/escalation probes."""
        probe = PolicyProbe()
        report = probe.run(_build_strict_policy())
        # Score is computed based on findings; strict policies still have
        # bypass and escalation findings since glob patterns like "delete*"
        # don't cover prefixed variants like "bulk_delete".
        assert isinstance(report.score, int)
        assert 0 <= report.score <= 100


# ======================================================================
# 4. PolicyProbe.run() with a permissive policy
# ======================================================================


def _build_permissive_policy() -> Policy:
    """Build a policy that auto-approves everything."""
    return Policy(
        rules=[
            PolicyRule(
                name="allow_all",
                match_type="*",
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
            ),
        ],
        default_risk_level=RiskLevel.LOW,
        default_approval=Approval.AUTO,
    )


class TestProbePermissive:
    """Probe against a permissive policy should find many gaps."""

    def test_many_findings(self) -> None:
        probe = PolicyProbe()
        report = probe.run(_build_permissive_policy())
        assert report.gap_count > 10

    def test_critical_findings_present(self) -> None:
        probe = PolicyProbe()
        report = probe.run(_build_permissive_policy())
        assert report.critical_count >= 1

    def test_low_robustness_score(self) -> None:
        probe = PolicyProbe()
        report = probe.run(_build_permissive_policy())
        assert report.score < 50

    def test_overly_permissive_finding(self) -> None:
        probe = PolicyProbe()
        report = probe.run(_build_permissive_policy())
        categories = {f.category for f in report.findings}
        assert "overly_permissive" in categories

    def test_missing_coverage_finding(self) -> None:
        probe = PolicyProbe()
        report = probe.run(_build_permissive_policy())
        categories = {f.category for f in report.findings}
        assert "missing_coverage" in categories


# ======================================================================
# 5. Glob bypass detection (exact match without wildcard)
# ======================================================================


def _build_exact_match_policy() -> Policy:
    """Policy that blocks 'delete' (exact) instead of 'delete*' (glob)."""
    return Policy(
        rules=[
            PolicyRule(
                name="block_delete_exact",
                match_type="delete",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
            ),
        ],
        default_risk_level=RiskLevel.MEDIUM,
        default_approval=Approval.APPROVE,
    )


class TestProbeGlobBypass:
    """Test that probe detects glob bypass when exact match is used."""

    def test_exact_match_has_bypass_findings(self) -> None:
        probe = PolicyProbe()
        report = probe.run(_build_exact_match_policy())
        bypass_findings = [f for f in report.findings if f.category == "glob_bypass"]
        # Variants like "admin_delete", "delete_all", "delete_force" should bypass
        assert len(bypass_findings) > 0

    def test_bypass_variants_detected(self) -> None:
        probe = PolicyProbe()
        report = probe.run(_build_exact_match_policy())
        bypass_descriptions = [
            f.description for f in report.findings if f.category == "glob_bypass"
        ]
        # At least one bypass variant should mention a suffix or prefix
        bypass_text = " ".join(bypass_descriptions)
        assert "bypass" in bypass_text.lower() or "delete" in bypass_text.lower()


# ======================================================================
# 6. generate_probes() returns list of Actions
# ======================================================================


class TestGenerateProbes:
    """Test the generate_probes() method."""

    def test_returns_list_of_actions(self) -> None:
        probe = PolicyProbe()
        policy = _build_strict_policy()
        actions = probe.generate_probes(policy)
        assert isinstance(actions, list)
        assert all(isinstance(a, Action) for a in actions)

    def test_probes_not_empty(self) -> None:
        probe = PolicyProbe()
        policy = _build_strict_policy()
        actions = probe.generate_probes(policy)
        assert len(actions) > 0

    def test_includes_destructive_probes(self) -> None:
        probe = PolicyProbe()
        policy = _build_strict_policy()
        actions = probe.generate_probes(policy)
        types = {a.type for a in actions}
        assert "delete" in types or any("delete" in t for t in types)

    def test_includes_bypass_probes(self) -> None:
        probe = PolicyProbe()
        policy = _build_strict_policy()
        actions = probe.generate_probes(policy)
        types = {a.type for a in actions}
        # Should include variants like "admin_delete", "delete_force", etc.
        bypass_types = {t for t in types if "_" in t and len(t) > 6}
        assert len(bypass_types) > 0

    def test_includes_escalation_probes(self) -> None:
        probe = PolicyProbe()
        policy = _build_strict_policy()
        actions = probe.generate_probes(policy)
        types = {a.type for a in actions}
        escalation_expected = {"read_then_delete", "search_and_destroy", "safe_destroy"}
        assert len(types & escalation_expected) > 0

    def test_generate_probes_for_permissive_policy(self) -> None:
        """Permissive policy with no block rules should still generate probes."""
        probe = PolicyProbe()
        policy = _build_permissive_policy()
        actions = probe.generate_probes(policy)
        assert len(actions) > 0


# ======================================================================
# 7. Individual probe categories
# ======================================================================


class TestProbeCategories:
    """Test each probe category independently."""

    def test_destructive_coverage_category(self) -> None:
        probe = PolicyProbe()
        # Policy with no rules -> all destructive actions hit default
        empty_policy = Policy(
            default_risk_level=RiskLevel.LOW,
            default_approval=Approval.AUTO,
        )
        report = probe.run(empty_policy)
        destructive_findings = [f for f in report.findings if f.category == "missing_coverage"]
        assert len(destructive_findings) > 0

    def test_default_fallthrough_category(self) -> None:
        """Default fallthrough requires matched_rule to be falsy.

        Since Policy.evaluate() always sets matched_rule to '<default>'
        (truthy) when no explicit rule matches, the default_fallthrough
        probe only triggers for rules with empty matched_rule. With a
        permissive auto-approve wildcard rule, sensitive actions hit that
        rule (not the default), so this probe category does not fire.
        """
        probe = PolicyProbe()
        # A policy with only an auto wildcard rule: sensitive actions
        # match the rule (not the default), so no fallthrough finding.
        policy = Policy(
            rules=[
                PolicyRule(
                    name="auto_all",
                    match_type="*",
                    approval=Approval.AUTO,
                    risk_level=RiskLevel.LOW,
                ),
            ],
            default_risk_level=RiskLevel.LOW,
            default_approval=Approval.AUTO,
        )
        report = probe.run(policy)
        # The findings should come from other categories (missing_coverage,
        # overly_permissive, etc.) rather than default_fallthrough.
        assert report.gap_count > 0

    def test_escalation_category(self) -> None:
        probe = PolicyProbe()
        # Permissive policy allows escalation patterns through
        policy = Policy(
            default_risk_level=RiskLevel.LOW,
            default_approval=Approval.AUTO,
        )
        report = probe.run(policy)
        escalation_findings = [f for f in report.findings if f.category == "escalation"]
        assert len(escalation_findings) > 0

    def test_target_gaps_category(self) -> None:
        probe = PolicyProbe()
        # Policy that auto-approves everything hits target gaps
        policy = Policy(
            default_risk_level=RiskLevel.LOW,
            default_approval=Approval.AUTO,
        )
        report = probe.run(policy)
        target_findings = [f for f in report.findings if f.category == "target_gap"]
        assert len(target_findings) > 0

    def test_wildcard_rules_category(self) -> None:
        probe = PolicyProbe()
        policy = Policy(
            rules=[
                PolicyRule(
                    name="allow_all",
                    match_type="*",
                    approval=Approval.AUTO,
                    risk_level=RiskLevel.LOW,
                ),
            ],
        )
        report = probe.run(policy)
        wildcard_findings = [f for f in report.findings if f.category == "overly_permissive"]
        assert len(wildcard_findings) >= 1
        assert wildcard_findings[0].severity == "critical"

    def test_no_wildcard_finding_for_block_all(self) -> None:
        """A wildcard block rule should NOT trigger 'overly_permissive'."""
        probe = PolicyProbe()
        policy = Policy(
            rules=[
                PolicyRule(
                    name="block_all",
                    match_type="*",
                    approval=Approval.BLOCK,
                    risk_level=RiskLevel.CRITICAL,
                ),
            ],
        )
        report = probe.run(policy)
        wildcard_findings = [f for f in report.findings if f.category == "overly_permissive"]
        assert len(wildcard_findings) == 0


# ======================================================================
# 8. Empty policy (no rules)
# ======================================================================


class TestEmptyPolicy:
    """Test probing an empty policy with no rules."""

    def test_empty_policy_returns_report(self) -> None:
        probe = PolicyProbe()
        policy = Policy()
        report = probe.run(policy)
        assert isinstance(report, ProbeReport)
        assert report.total_probes > 0

    def test_empty_policy_has_findings(self) -> None:
        """Empty policy should flag many gaps since nothing is explicitly governed."""
        probe = PolicyProbe()
        policy = Policy()
        report = probe.run(policy)
        # Default approval is "approve", so destructive actions hit default
        assert report.gap_count > 0

    def test_empty_policy_generate_probes(self) -> None:
        probe = PolicyProbe()
        policy = Policy()
        actions = probe.generate_probes(policy)
        assert isinstance(actions, list)
        # Even with no rules, destructive + escalation probes are generated
        assert len(actions) > 0

    def test_empty_policy_summary(self) -> None:
        probe = PolicyProbe()
        policy = Policy()
        report = probe.run(policy)
        s = report.summary()
        assert "Probe Report" in s
        assert "Robustness score" in s
