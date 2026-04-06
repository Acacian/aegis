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
