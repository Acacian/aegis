"""Tests for Justification Gap computation modules."""

from __future__ import annotations

import pytest

from aegis.core.action_claim import (
    ActionClaim,
    ChainFields,
    ClaimVerdict,
    DeclaredFields,
    DelegationChainEntry,
    ImpactVector,
)
from aegis.core.justification_gap import (
    ClaimAssessor,
    CongruenceChecker,
    ImpactRule,
    JustificationGapComputer,
    RuleBasedImpactScorer,
)

# -- Helpers -------------------------------------------------------------


def _make_claim(
    action_type: str = "read",
    target: str = "api",
    params: dict | None = None,
    justification: str = "",
    declared_impact: ImpactVector | None = None,
    chain_depth: int = 0,
    delegation_chain: tuple[DelegationChainEntry, ...] = (),
) -> ActionClaim:
    """Build an ActionClaim for testing."""
    return ActionClaim(
        declared=DeclaredFields(
            proposed_transition=action_type,
            target=target,
            justification=justification,
            preconditions=params or {},
            declared_impact=declared_impact or ImpactVector(),
        ),
        chain=ChainFields(
            chain_depth=chain_depth,
            delegation_chain=delegation_chain,
        ),
    )


# -- RuleBasedImpactScorer: destructivity --------------------------------


class TestDestructivityScoring:
    def test_read_zero(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("read_data", "db")
        result = scorer.score(claim)
        assert result.destructivity == 0.0

    def test_get_zero(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("get_user", "api")
        result = scorer.score(claim)
        assert result.destructivity == 0.0

    def test_write_single(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("write_record", "db")
        result = scorer.score(claim)
        assert result.destructivity == 0.3

    def test_write_bulk(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("write_record", "db", params={"bulk": True})
        result = scorer.score(claim)
        assert result.destructivity == 0.5

    def test_update_with_high_count(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("update_records", "db", params={"count": 50})
        result = scorer.score(claim)
        assert result.destructivity == 0.5

    def test_delete_single(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("delete_record", "db")
        result = scorer.score(claim)
        assert result.destructivity == 0.7

    def test_delete_bulk(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("delete_records", "db", params={"bulk": True})
        result = scorer.score(claim)
        assert result.destructivity == 0.9

    def test_destroy_max(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("destroy_environment", "infra")
        result = scorer.score(claim)
        assert result.destructivity == 1.0

    def test_drop_database(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("drop_database", "production")
        result = scorer.score(claim)
        assert result.destructivity == 1.0

    def test_unknown_action_baseline(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("foobar_custom", "somewhere")
        result = scorer.score(claim)
        assert result.destructivity == 0.2


# -- RuleBasedImpactScorer: data_exposure --------------------------------


class TestDataExposureScoring:
    def test_no_export_no_pii(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("read_data", "internal_db")
        result = scorer.score(claim)
        assert result.data_exposure == 0.0

    def test_export_only(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("export_data", "internal_db")
        result = scorer.score(claim)
        assert result.data_exposure == 0.5

    def test_export_to_external(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("export_data", "s3_bucket")
        result = scorer.score(claim)
        assert result.data_exposure == 0.7

    def test_export_external_with_pii(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("send_data", "email_service", params={"ssn": "123-45-6789"})
        result = scorer.score(claim)
        assert result.data_exposure == 0.9

    def test_export_external_pii_bulk(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim(
            "send_data",
            "email_service",
            params={"ssn": "123-45-6789", "bulk": True},
        )
        result = scorer.score(claim)
        assert result.data_exposure == 1.0

    def test_pii_in_values_only(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("read_data", "internal_db", params={"field": "ssn"})
        result = scorer.score(claim)
        assert result.data_exposure == 0.3


# -- RuleBasedImpactScorer: resource_consumption -------------------------


class TestResourceConsumptionScoring:
    def test_single_item(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("read", "api", params={"count": 1})
        result = scorer.score(claim)
        assert result.resource_consumption == 0.0

    def test_small_batch(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("read", "api", params={"count": 5})
        result = scorer.score(claim)
        assert result.resource_consumption == 0.1

    def test_medium_batch(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("read", "api", params={"count": 50})
        result = scorer.score(claim)
        assert result.resource_consumption == 0.3

    def test_large_batch(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("read", "api", params={"count": 500})
        result = scorer.score(claim)
        assert result.resource_consumption == 0.5

    def test_very_large_batch(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("read", "api", params={"count": 5000})
        result = scorer.score(claim)
        assert result.resource_consumption == 0.7

    def test_massive_batch(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("read", "api", params={"count": 50000})
        result = scorer.score(claim)
        assert result.resource_consumption == 0.9

    def test_limit_parameter(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("read", "api", params={"limit": 100})
        result = scorer.score(claim)
        assert result.resource_consumption == 0.3

    def test_batch_size_parameter(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("read", "api", params={"batch_size": 1000})
        result = scorer.score(claim)
        assert result.resource_consumption == 0.5

    def test_string_count_parsed(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("read", "api", params={"count": "100"})
        result = scorer.score(claim)
        assert result.resource_consumption == 0.3

    def test_invalid_string_count(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("read", "api", params={"count": "all"})
        result = scorer.score(claim)
        assert result.resource_consumption == 0.2


# -- RuleBasedImpactScorer: privilege_escalation -------------------------


class TestPrivilegeEscalationScoring:
    def test_normal_action_zero(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("read_data", "internal_db")
        result = scorer.score(claim)
        assert result.privilege_escalation == 0.0

    def test_bypass_in_type(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("bypass_auth", "gateway")
        result = scorer.score(claim)
        assert result.privilege_escalation == 1.0

    def test_admin_in_target(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("update_user", "admin_panel")
        result = scorer.score(claim)
        assert result.privilege_escalation == 0.7

    def test_role_in_type(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("grant_permission", "iam")
        result = scorer.score(claim)
        assert result.privilege_escalation == 0.5

    def test_escalation_in_params(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("update_user", "users", params={"role": "admin"})
        result = scorer.score(claim)
        assert result.privilege_escalation >= 0.5


# -- RuleBasedImpactScorer: reversibility --------------------------------


class TestReversibilityScoring:
    def test_read_zero(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("read_data", "db")
        result = scorer.score(claim)
        assert result.reversibility == 0.0

    def test_write_low(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("write_record", "db")
        result = scorer.score(claim)
        assert result.reversibility == 0.3

    def test_delete_without_backup(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("delete_record", "db")
        result = scorer.score(claim)
        assert result.reversibility == 0.7

    def test_delete_with_backup(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("delete_record", "db", params={"backup": True})
        result = scorer.score(claim)
        assert result.reversibility == 0.4

    def test_delete_soft_delete(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("delete_record", "db", params={"soft_delete": True})
        result = scorer.score(claim)
        assert result.reversibility == 0.4

    def test_truncate_high(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("truncate_table", "db")
        result = scorer.score(claim)
        assert result.reversibility == 0.9

    def test_drop_database_irreversible(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("drop_database", "production")
        result = scorer.score(claim)
        assert result.reversibility == 1.0

    def test_wipe_irreversible(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("wipe_storage", "volumes")
        result = scorer.score(claim)
        assert result.reversibility == 1.0


# -- RuleBasedImpactScorer: autonomy_depth -------------------------------


class TestAutonomyDepthScoring:
    def test_depth_zero(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("read", "api", chain_depth=0)
        result = scorer.score(claim)
        assert result.autonomy_depth == 0.0

    def test_depth_one(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("read", "api", chain_depth=1)
        result = scorer.score(claim)
        assert result.autonomy_depth == 0.2

    def test_depth_two(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("read", "api", chain_depth=2)
        result = scorer.score(claim)
        assert result.autonomy_depth == 0.4

    def test_depth_three(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("read", "api", chain_depth=3)
        result = scorer.score(claim)
        assert result.autonomy_depth == 0.6

    def test_depth_five(self):
        scorer = RuleBasedImpactScorer()
        claim = _make_claim("read", "api", chain_depth=5)
        result = scorer.score(claim)
        assert result.autonomy_depth == 1.0


# -- ImpactRule ----------------------------------------------------------


class TestImpactRule:
    def test_wildcard_matches_all(self):
        rule = ImpactRule(name="default", match_type="*", match_target="*")
        assert rule.matches("read", "api", {}) is True
        assert rule.matches("delete", "db", {"x": 1}) is True

    def test_specific_type_match(self):
        rule = ImpactRule(name="delete_rule", match_type="delete*", match_target="*")
        assert rule.matches("delete_record", "db", {}) is True
        assert rule.matches("read_data", "db", {}) is False

    def test_specific_target_match(self):
        rule = ImpactRule(name="prod_rule", match_type="*", match_target="production*")
        assert rule.matches("read", "production_db", {}) is True
        assert rule.matches("read", "staging_db", {}) is False

    def test_overrides_applied(self):
        rule = ImpactRule(
            name="critical",
            match_type="delete*",
            match_target="production*",
            overrides={"destructivity": 1.0, "reversibility": 1.0},
        )
        scorer = RuleBasedImpactScorer(rules=[rule])
        claim = _make_claim("delete_record", "production_db")
        result = scorer.score(claim)
        assert result.destructivity == 1.0
        assert result.reversibility == 1.0

    def test_overrides_use_max(self):
        """Rule overrides take max of computed and override value."""
        rule = ImpactRule(
            name="low_override",
            match_type="*",
            match_target="*",
            overrides={"destructivity": 0.1},
        )
        scorer = RuleBasedImpactScorer(rules=[rule])
        # destroy has computed destructivity=1.0, override is 0.1 -> max=1.0
        claim = _make_claim("destroy_env", "infra")
        result = scorer.score(claim)
        assert result.destructivity == 1.0

    def test_multiple_rules_all_apply(self):
        rules = [
            ImpactRule(
                name="r1",
                match_type="*",
                match_target="*",
                overrides={"data_exposure": 0.5},
            ),
            ImpactRule(
                name="r2",
                match_type="*",
                match_target="*",
                overrides={"data_exposure": 0.8},
            ),
        ]
        scorer = RuleBasedImpactScorer(rules=rules)
        claim = _make_claim("read", "api")
        result = scorer.score(claim)
        # Both match; each takes max -> final is 0.8
        assert result.data_exposure == 0.8


# -- CongruenceChecker ---------------------------------------------------


class TestCongruenceChecker:
    def test_read_action_congruent(self):
        checker = CongruenceChecker()
        claim = _make_claim("read_data", "db")
        assert checker.check(claim) == 1.0

    def test_write_action_congruent(self):
        checker = CongruenceChecker()
        claim = _make_claim("write_record", "db", params={"value": "new"})
        assert checker.check(claim) == 1.0

    def test_unknown_action_defaults_congruent(self):
        checker = CongruenceChecker()
        claim = _make_claim("custom_op", "service")
        assert checker.check(claim) == 1.0

    def test_read_with_delete_params_contradictory(self):
        checker = CongruenceChecker()
        claim = _make_claim("read_data", "db", params={"action": "delete everything"})
        score = checker.check(claim)
        assert score < 1.0

    def test_read_with_write_params_contradictory(self):
        checker = CongruenceChecker()
        claim = _make_claim("read_data", "db", params={"op": "update the table"})
        score = checker.check(claim)
        assert score < 1.0

    def test_write_with_delete_params_contradictory(self):
        checker = CongruenceChecker()
        claim = _make_claim("write_record", "db", params={"op": "destroy records"})
        score = checker.check(claim)
        assert score < 1.0

    def test_congruence_never_negative(self):
        checker = CongruenceChecker()
        claim = _make_claim("read_data", "db", params={"x": "delete purge destroy"})
        score = checker.check(claim)
        assert score >= 0.0


# -- JustificationGapComputer -------------------------------------------


class TestJustificationGapComputer:
    def test_identical_vectors_approve(self):
        computer = JustificationGapComputer()
        v = ImpactVector(destructivity=0.5, data_exposure=0.3)
        result = computer.compute(v, v)
        assert result.gap == pytest.approx(0.0, abs=1e-9)
        assert result.verdict == ClaimVerdict.APPROVE

    def test_small_gap_approve(self):
        computer = JustificationGapComputer()
        declared = ImpactVector(destructivity=0.5)
        assessed = ImpactVector(destructivity=0.55)
        result = computer.compute(declared, assessed)
        assert result.gap <= 0.15
        assert result.verdict == ClaimVerdict.APPROVE

    def test_medium_gap_escalate(self):
        computer = JustificationGapComputer()
        declared = ImpactVector(destructivity=0.1)
        assessed = ImpactVector(destructivity=0.7)
        result = computer.compute(declared, assessed)
        assert 0.15 < result.gap <= 0.40
        assert result.verdict == ClaimVerdict.ESCALATE
        assert "escalation" in result.explanation.lower()

    def test_large_gap_block(self):
        computer = JustificationGapComputer()
        declared = ImpactVector()
        assessed = ImpactVector(destructivity=1.0, data_exposure=1.0, reversibility=1.0)
        result = computer.compute(declared, assessed)
        assert result.gap > 0.40
        assert result.verdict == ClaimVerdict.BLOCK
        assert "block" in result.explanation.lower()

    def test_per_dimension_gap_populated(self):
        computer = JustificationGapComputer()
        declared = ImpactVector(destructivity=0.2)
        assessed = ImpactVector(destructivity=0.8, data_exposure=0.5)
        result = computer.compute(declared, assessed)
        assert result.per_dimension_gap["destructivity"] == pytest.approx(0.6)
        assert result.per_dimension_gap["data_exposure"] == pytest.approx(0.5)
        assert result.per_dimension_gap["resource_consumption"] == 0.0

    def test_over_reporting_ignored(self):
        """Over-reporting (declared > assessed) has zero per-dim gap."""
        computer = JustificationGapComputer()
        declared = ImpactVector(destructivity=0.9)
        assessed = ImpactVector(destructivity=0.1)
        result = computer.compute(declared, assessed)
        assert result.per_dimension_gap["destructivity"] == 0.0
        assert result.gap == 0.0

    def test_custom_thresholds(self):
        computer = JustificationGapComputer(approve_threshold=0.05, escalate_threshold=0.10)
        declared = ImpactVector()
        assessed = ImpactVector(destructivity=0.3)
        result = computer.compute(declared, assessed)
        # gap = 0.3 / sqrt(6) ~ 0.122 -> exceeds both thresholds
        assert result.verdict == ClaimVerdict.BLOCK

    def test_asymmetric_gap_invariant(self):
        """Over-reporting should not increase gap vs honest reporting."""
        computer = JustificationGapComputer()
        assessed = ImpactVector(destructivity=0.5, data_exposure=0.5)

        honest = ImpactVector(destructivity=0.5, data_exposure=0.5)
        over = ImpactVector(destructivity=0.9, data_exposure=0.9)

        result_honest = computer.compute(honest, assessed)
        result_over = computer.compute(over, assessed)

        assert result_over.gap <= result_honest.gap

    def test_asymmetric_gap_invariant_extended(self):
        """Systematically: increasing declared should never increase gap."""
        computer = JustificationGapComputer()
        assessed = ImpactVector(destructivity=0.6, data_exposure=0.4, reversibility=0.5)
        prev_gap = float("inf")
        for level in [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]:
            declared = ImpactVector(destructivity=level, data_exposure=level, reversibility=level)
            result = computer.compute(declared, assessed)
            assert result.gap <= prev_gap + 1e-9
            prev_gap = result.gap


# -- ClaimAssessor -------------------------------------------------------


class TestClaimAssessor:
    def test_end_to_end_assessment(self):
        assessor = ClaimAssessor()
        claim = _make_claim(
            "delete_record",
            "production_db",
            params={"count": 100},
            declared_impact=ImpactVector(),  # agent declares zero impact
        )
        result = assessor.assess(claim)

        assert result.is_assessed is True
        assert result.assessed.assessed_at is not None
        assert result.assessed.assessor_version == "0.9.0"
        assert result.assessed.impact_profile.destructivity > 0
        assert result.assessed.justification_gap > 0
        assert result.assessed.risk_level >= 1

    def test_honest_claim_approved(self):
        """An agent that honestly declares high impact should be approved."""
        assessor = ClaimAssessor()
        claim = _make_claim(
            "read_data",
            "internal_db",
            declared_impact=ImpactVector(),  # read -> low impact
        )
        result = assessor.assess(claim)
        assert result.verdict == ClaimVerdict.APPROVE

    def test_deceptive_claim_blocked(self):
        """Agent claims zero impact for destructive action -> BLOCK."""
        assessor = ClaimAssessor()
        claim = _make_claim(
            "drop_database",
            "production",
            declared_impact=ImpactVector(),  # declares no impact
        )
        result = assessor.assess(claim)
        assert result.verdict == ClaimVerdict.BLOCK

    def test_congruence_score_set(self):
        assessor = ClaimAssessor()
        claim = _make_claim("read_data", "db")
        result = assessor.assess(claim)
        assert 0.0 <= result.assessed.congruence_score <= 1.0

    def test_risk_level_low(self):
        assessor = ClaimAssessor()
        claim = _make_claim("read_data", "db")
        result = assessor.assess(claim)
        assert result.assessed.risk_level == 1

    def test_risk_level_scales_with_impact(self):
        assessor = ClaimAssessor()
        low_claim = _make_claim("read_data", "db")
        high_claim = _make_claim("drop_database", "production")
        low_result = assessor.assess(low_claim)
        high_result = assessor.assess(high_claim)
        assert high_result.assessed.risk_level > low_result.assessed.risk_level

    def test_monotone_violation_forces_block(self):
        """Monotone constraint violation overrides any gap-based verdict."""
        assessor = ClaimAssessor()
        # Invalid chain: trust increases
        chain = (
            DelegationChainEntry(agent_id="root", trust_level=30),
            DelegationChainEntry(agent_id="child", trust_level=90),
        )
        claim = _make_claim(
            "read_data",
            "internal_db",
            declared_impact=ImpactVector(),
            chain_depth=1,
            delegation_chain=chain,
        )
        result = assessor.assess(claim)
        # Even though read is low-impact, monotone violation -> BLOCK
        assert result.verdict == ClaimVerdict.BLOCK

    def test_valid_chain_does_not_override_verdict(self):
        """Valid chain should not force BLOCK."""
        assessor = ClaimAssessor()
        chain = (
            DelegationChainEntry(agent_id="root", trust_level=100),
            DelegationChainEntry(agent_id="child", trust_level=60),
        )
        claim = _make_claim(
            "read_data",
            "internal_db",
            declared_impact=ImpactVector(),
            chain_depth=1,
            delegation_chain=chain,
        )
        result = assessor.assess(claim)
        assert result.verdict != ClaimVerdict.BLOCK

    def test_custom_scorer(self):
        """ClaimAssessor accepts custom ImpactScorer."""

        class FixedScorer:
            def score(self, claim: ActionClaim) -> ImpactVector:
                return ImpactVector(destructivity=0.99)

        assessor = ClaimAssessor(impact_scorer=FixedScorer())
        claim = _make_claim("read_data", "db", declared_impact=ImpactVector())
        result = assessor.assess(claim)
        assert result.assessed.impact_profile.destructivity == 0.99

    def test_custom_gap_computer(self):
        """ClaimAssessor accepts custom JustificationGapComputer."""
        strict_computer = JustificationGapComputer(approve_threshold=0.01, escalate_threshold=0.02)
        assessor = ClaimAssessor(gap_computer=strict_computer)
        # Even small gap should escalate/block with strict thresholds
        claim = _make_claim("write_record", "db", declared_impact=ImpactVector())
        result = assessor.assess(claim)
        assert result.verdict in (ClaimVerdict.ESCALATE, ClaimVerdict.BLOCK)
