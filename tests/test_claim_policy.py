"""Tests for ClaimPolicy — ActionClaim-aware policy evaluation."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis.core.action_claim import (
    ActionClaim,
    ChainFields,
    ClaimVerdict,
    DeclaredFields,
    DelegationChainEntry,
    ImpactVector,
)
from aegis.core.claim_policy import ClaimPolicy, ClaimPolicyDecision
from aegis.core.policy import Approval, Policy

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DEFAULT_YAML = """\
version: "1"
defaults:
  risk_level: medium
  approval: approve
rules:
  - name: block_delete
    match: { type: "delete*" }
    risk_level: critical
    approval: block
  - name: auto_read
    match: { type: "read*" }
    risk_level: low
    approval: auto
"""


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    p = tmp_path / "policy.yaml"
    p.write_text(_DEFAULT_YAML)
    return p


def _policy_from_path(path: Path) -> Policy:
    return Policy.from_yaml(str(path))


def _claim(
    action: str = "read_file",
    target: str = "database",
    justification: str = "need data",
    declared_impact: ImpactVector | None = None,
    chain: ChainFields | None = None,
) -> ActionClaim:
    return ActionClaim(
        declared=DeclaredFields(
            proposed_transition=action,
            target=target,
            justification=justification,
            declared_impact=declared_impact or ImpactVector(),
        ),
        chain=chain or ChainFields(principal="user"),
    )


# ---------------------------------------------------------------------------
# Basic evaluation
# ---------------------------------------------------------------------------


class TestClaimPolicyEvaluation:
    def test_read_allowed(self, policy_path: Path) -> None:
        cp = ClaimPolicy(_policy_from_path(policy_path))
        claim = _claim("read_file")
        decision = cp.evaluate(claim)
        assert decision.is_allowed is True
        assert decision.policy_decision.approval == Approval.AUTO

    def test_delete_blocked_by_policy(self, policy_path: Path) -> None:
        cp = ClaimPolicy(_policy_from_path(policy_path))
        claim = _claim("delete_users")
        decision = cp.evaluate(claim)
        assert decision.is_allowed is False
        assert decision.policy_decision.approval == Approval.BLOCK
        assert "block_delete" in decision.explanation

    def test_claim_assessed_after_evaluate(self, policy_path: Path) -> None:
        cp = ClaimPolicy(_policy_from_path(policy_path))
        claim = _claim("update_record")
        assert not claim.is_assessed
        cp.evaluate(claim)
        assert claim.is_assessed

    def test_skip_assessment_if_already_assessed(self, policy_path: Path) -> None:
        cp = ClaimPolicy(_policy_from_path(policy_path))
        claim = _claim("read_file")
        cp.evaluate(claim)
        assessed_at = claim.assessed.assessed_at
        # Evaluate again
        cp.evaluate(claim)
        # Should not re-assess (already assessed)
        assert claim.assessed.assessed_at == assessed_at


# ---------------------------------------------------------------------------
# Justification gap verdicts
# ---------------------------------------------------------------------------


class TestJustificationGapVerdicts:
    def test_honest_claim_approved(self, policy_path: Path) -> None:
        """Honest impact declaration → low gap → approved."""
        cp = ClaimPolicy(_policy_from_path(policy_path))
        # Declare accurate impact
        claim = _claim(
            "update_record",
            declared_impact=ImpactVector(
                destructivity=0.3,
                reversibility=0.3,
            ),
        )
        cp.evaluate(claim)
        # Should not be blocked by gap (honest declaration)
        assert claim.verdict in (ClaimVerdict.APPROVE, ClaimVerdict.ESCALATE)

    def test_under_reported_impact_blocks(self, policy_path: Path) -> None:
        """Agent declares zero impact but action is destructive → BLOCK."""
        cp = ClaimPolicy(_policy_from_path(policy_path))
        claim = _claim(
            "drop_database",
            declared_impact=ImpactVector(),  # declares zero impact
        )
        decision = cp.evaluate(claim)
        # Policy blocks "delete*" but also gap should be high
        assert decision.is_allowed is False

    def test_escalation_requires_approval(self, policy_path: Path) -> None:
        """Escalated claim needs human approval even if policy says auto."""
        cp = ClaimPolicy(_policy_from_path(policy_path))
        claim = _claim("read_data")
        cp.evaluate(claim)
        if claim.verdict == ClaimVerdict.ESCALATE:
            decision = cp.evaluate(claim)
            assert decision.requires_escalation is True
            assert decision.final_approval in (Approval.APPROVE, Approval.AUTO)


# ---------------------------------------------------------------------------
# Monotone constraint
# ---------------------------------------------------------------------------


class TestMonotoneConstraint:
    def test_valid_chain_allowed(self, policy_path: Path) -> None:
        cp = ClaimPolicy(_policy_from_path(policy_path))
        chain = ChainFields(
            principal="admin",
            delegation_chain=(
                DelegationChainEntry(agent_id="admin", trust_level=100),
                DelegationChainEntry(agent_id="worker", trust_level=70),
            ),
            chain_depth=1,
        )
        claim = _claim("read_file", chain=chain)
        decision = cp.evaluate(claim)
        assert decision.monotone_valid is True

    def test_violated_chain_blocked(self, policy_path: Path) -> None:
        cp = ClaimPolicy(_policy_from_path(policy_path))
        chain = ChainFields(
            principal="admin",
            delegation_chain=(
                DelegationChainEntry(agent_id="admin", trust_level=100),
                DelegationChainEntry(agent_id="worker", trust_level=70),
                DelegationChainEntry(agent_id="sub-worker", trust_level=90),  # violation!
            ),
            chain_depth=2,
        )
        claim = _claim("read_file", chain=chain)
        decision = cp.evaluate(claim)
        assert decision.monotone_valid is False
        assert decision.is_allowed is False
        assert decision.final_approval == Approval.BLOCK
        assert "Monotone constraint" in decision.explanation


# ---------------------------------------------------------------------------
# ClaimPolicyDecision properties
# ---------------------------------------------------------------------------


class TestClaimPolicyDecisionProperties:
    def test_final_approval_block_on_gap(self) -> None:
        from aegis.core.action import Action
        from aegis.core.policy import PolicyDecision

        pd = PolicyDecision(
            action=Action(type="read", target="db"),
            risk_level="low",
            approval=Approval.AUTO,
        )
        d = ClaimPolicyDecision(
            policy_decision=pd,
            claim_verdict=ClaimVerdict.BLOCK,
            monotone_valid=True,
            justification_gap=0.5,
            congruence_score=1.0,
        )
        assert d.final_approval == Approval.BLOCK
        assert d.is_allowed is False

    def test_final_approval_escalate_overrides_auto(self) -> None:
        from aegis.core.action import Action
        from aegis.core.policy import PolicyDecision

        pd = PolicyDecision(
            action=Action(type="read", target="db"),
            risk_level="low",
            approval=Approval.AUTO,
        )
        d = ClaimPolicyDecision(
            policy_decision=pd,
            claim_verdict=ClaimVerdict.ESCALATE,
            monotone_valid=True,
            justification_gap=0.2,
            congruence_score=1.0,
        )
        assert d.final_approval == Approval.APPROVE  # escalated from AUTO
        assert d.requires_escalation is True
        assert d.is_allowed is True

    def test_both_policy_and_claim_must_agree(self) -> None:
        from aegis.core.action import Action
        from aegis.core.policy import PolicyDecision

        pd = PolicyDecision(
            action=Action(type="delete", target="db"),
            risk_level="critical",
            approval=Approval.BLOCK,
        )
        d = ClaimPolicyDecision(
            policy_decision=pd,
            claim_verdict=ClaimVerdict.APPROVE,
            monotone_valid=True,
            justification_gap=0.0,
            congruence_score=1.0,
        )
        assert d.is_allowed is False  # policy blocks even if claim approves


# ---------------------------------------------------------------------------
# Assess=False mode
# ---------------------------------------------------------------------------


class TestNoAssessMode:
    def test_no_assess_skips_assessment(self, policy_path: Path) -> None:
        cp = ClaimPolicy(_policy_from_path(policy_path), assess=False)
        claim = _claim("read_file")
        cp.evaluate(claim)
        # Claim should NOT be assessed
        assert not claim.is_assessed
        assert claim.verdict == ClaimVerdict.PENDING


# ---------------------------------------------------------------------------
# Selection audit integration (P0-1)
# ---------------------------------------------------------------------------


def _selection_set(
    *,
    selected_impact: float = 0.5,
    num_eliminated: int = 3,
    eliminated_impact: float = 0.9,
    reason: object | None = None,
    explanation: str = "legitimate constraint",
):
    from aegis.core.selection_audit import (
        EliminatedOption,
        EliminationReason,
        SelectionOption,
        SelectionSet,
    )

    selected = SelectionOption(
        option_id="picked",
        description="picked",
        action_type="read",
        target="db",
        estimated_impact=selected_impact,
    )
    eliminated = [
        EliminatedOption(
            option=SelectionOption(
                option_id=f"e{i}",
                description=f"alt_{i}",
                action_type="read",
                target="db",
                estimated_impact=eliminated_impact,
            ),
            reason=reason or EliminationReason.POLICY_VIOLATION,
            agent_explanation=explanation,
        )
        for i in range(num_eliminated)
    ]
    return SelectionSet(selected=selected, eliminated=eliminated)


class TestClaimPolicySelectionAudit:
    """Integration of SelectionAuditor with ClaimPolicy.evaluate()."""

    def test_no_selection_context_leaves_result_none(self, policy_path: Path) -> None:
        cp = ClaimPolicy(_policy_from_path(policy_path))
        claim = _claim("read_file")
        decision = cp.evaluate(claim)
        assert decision.selection_audit_result is None

    def test_clean_selection_does_not_raise_verdict(self, policy_path: Path) -> None:
        # Clean: agent picks the safer (lower-impact) option and eliminates
        # the riskier ones. No HIGH_ELIMINATION, no BETTER_OPTION_ELIMINATED.
        cp = ClaimPolicy(_policy_from_path(policy_path))
        claim = _claim("read_file")
        claim.selection_context = _selection_set(
            selected_impact=0.2,
            num_eliminated=2,
            eliminated_impact=0.9,
        )
        decision = cp.evaluate(claim)
        assert decision.selection_audit_result is not None
        assert decision.selection_audit_result.overall_risk <= 0.5
        assert claim.verdict != ClaimVerdict.BLOCK

    def test_high_elimination_escalates_to_block(self, policy_path: Path) -> None:
        from aegis.core.selection_audit import EliminationReason

        cp = ClaimPolicy(_policy_from_path(policy_path))
        claim = _claim("read_file")
        # 9/10 elimination ratio with agent_preference + no explanation →
        # severity 0.9 → BLOCK. Eliminated impact is lower than selected,
        # which also triggers BETTER_OPTION_ELIMINATED (severity 0.8) —
        # this is the cosmetic-alignment / risk-maximising pattern.
        claim.selection_context = _selection_set(
            selected_impact=0.9,
            num_eliminated=9,
            eliminated_impact=0.1,
            reason=EliminationReason.AGENT_PREFERENCE,
            explanation="",
        )
        decision = cp.evaluate(claim)

        assert decision.selection_audit_result is not None
        assert decision.selection_audit_result.overall_risk >= 0.8
        assert claim.verdict == ClaimVerdict.BLOCK
        assert decision.claim_verdict == ClaimVerdict.BLOCK
        assert decision.is_allowed is False
        assert "Selection audit" in decision.explanation

    def test_suspicious_selection_escalates(self, policy_path: Path) -> None:
        from aegis.core.selection_audit import EliminationReason

        cp = ClaimPolicy(
            _policy_from_path(policy_path),
            selection_block_threshold=0.95,  # raise bar so 0.8 ≠ block
        )
        claim = _claim("read_file")
        # One better (safer) option eliminated → BETTER_OPTION_ELIMINATED
        # severity exactly 0.8 → below the 0.95 block threshold but still
        # > 0.5 → is_suspicious → ESCALATE.
        claim.selection_context = _selection_set(
            selected_impact=0.9,
            num_eliminated=1,
            eliminated_impact=0.1,
            reason=EliminationReason.POLICY_VIOLATION,
            explanation="blocked by policy",
        )
        decision = cp.evaluate(claim)

        assert decision.selection_audit_result is not None
        assert decision.selection_audit_result.is_suspicious
        assert claim.verdict == ClaimVerdict.ESCALATE
        assert decision.requires_escalation

    def test_existing_block_is_not_downgraded(self, policy_path: Path) -> None:
        from datetime import UTC, datetime

        from aegis.core.action_claim import AssessedFields

        cp = ClaimPolicy(_policy_from_path(policy_path))
        claim = _claim("read_file")
        # Mark as already assessed so ClaimPolicy skips assess() which
        # would otherwise overwrite the verdict.
        claim.assessed = AssessedFields(assessed_at=datetime.now(UTC))
        claim.verdict = ClaimVerdict.BLOCK
        # Clean selection (picks safer option) — should NOT relax the BLOCK
        claim.selection_context = _selection_set(
            selected_impact=0.2,
            num_eliminated=1,
            eliminated_impact=0.9,
        )
        cp.evaluate(claim)
        assert claim.verdict == ClaimVerdict.BLOCK

    def test_explicit_auditor_is_used(self, policy_path: Path) -> None:
        from aegis.core.selection_audit import SelectionAuditor

        # Very permissive auditor — threshold must be > 1.0 so ratio never
        # triggers a finding. Use a safe-pick set so BETTER_OPTION_ELIMINATED
        # does not fire either.
        auditor = SelectionAuditor(elimination_threshold=1.1)
        cp = ClaimPolicy(
            _policy_from_path(policy_path),
            selection_auditor=auditor,
        )
        claim = _claim("read_file")
        claim.selection_context = _selection_set(
            selected_impact=0.2,
            num_eliminated=1,
            eliminated_impact=0.9,
        )
        decision = cp.evaluate(claim)
        assert decision.selection_audit_result is not None
        # With the permissive threshold there should be zero findings of
        # type HIGH_ELIMINATION.
        from aegis.core.selection_audit import FindingType

        assert not any(
            f.finding_type == FindingType.HIGH_ELIMINATION
            for f in decision.selection_audit_result.findings
        )

    def test_default_auditor_auto_created(self, policy_path: Path) -> None:
        cp = ClaimPolicy(_policy_from_path(policy_path))
        claim = _claim("read_file")
        claim.selection_context = _selection_set(num_eliminated=1)
        # Should not raise even though no global auditor was set.
        decision = cp.evaluate(claim)
        assert decision.selection_audit_result is not None
