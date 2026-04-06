"""ActionClaim-aware policy evaluation.

Extends the existing :class:`~aegis.core.policy.Policy` engine to work
with :class:`~aegis.core.action_claim.ActionClaim` objects.

The evaluation pipeline:
1. Convert ActionClaim → Action (via ``to_action()``)
2. Run standard Policy evaluation (first-match-wins)
3. Overlay justification gap verdict (BLOCK/ESCALATE override)
4. Overlay monotone constraint check (violation → BLOCK)
5. Return :class:`ClaimPolicyDecision`
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from aegis.core.policy import Approval, Policy, PolicyDecision

if TYPE_CHECKING:
    from aegis.core.action_claim import ActionClaim, ClaimVerdict


@dataclass(frozen=True)
class ClaimPolicyDecision:
    """Result of evaluating an ActionClaim against the policy.

    Extends PolicyDecision with claim-specific fields.
    """

    policy_decision: PolicyDecision
    claim_verdict: ClaimVerdict
    monotone_valid: bool
    justification_gap: float
    congruence_score: float
    explanation: str = ""

    @property
    def is_allowed(self) -> bool:
        """Action is allowed only if both policy and claim verdict agree."""
        from aegis.core.action_claim import ClaimVerdict

        if not self.policy_decision.is_allowed:
            return False
        if self.claim_verdict == ClaimVerdict.BLOCK:
            return False
        return self.monotone_valid

    @property
    def requires_escalation(self) -> bool:
        from aegis.core.action_claim import ClaimVerdict

        return self.claim_verdict == ClaimVerdict.ESCALATE

    @property
    def final_approval(self) -> Approval:
        """Compute the strictest approval across policy + claim."""
        from aegis.core.action_claim import ClaimVerdict

        if not self.monotone_valid or self.claim_verdict == ClaimVerdict.BLOCK:
            return Approval.BLOCK
        if self.claim_verdict == ClaimVerdict.ESCALATE:
            # Escalation requires human approval at minimum
            if self.policy_decision.approval == Approval.AUTO:
                return Approval.APPROVE
            return self.policy_decision.approval
        return self.policy_decision.approval


class ClaimPolicy:
    """ActionClaim-aware policy evaluation.

    Wraps a standard :class:`Policy` with claim assessment logic.
    """

    def __init__(
        self,
        policy: Policy,
        *,
        assess: bool = True,
    ) -> None:
        self._policy = policy
        self._assess = assess
        self._assessor: Any = None

    def _get_assessor(self) -> Any:
        if self._assessor is None:
            from aegis.core.justification_gap import ClaimAssessor

            self._assessor = ClaimAssessor()
        return self._assessor

    def evaluate(self, claim: ActionClaim) -> ClaimPolicyDecision:
        """Evaluate an ActionClaim against the policy."""
        # Step 1: Assess if needed
        if self._assess and not claim.is_assessed:
            self._get_assessor().assess(claim)

        # Step 2: Standard policy evaluation via Action bridge
        action = claim.to_action()
        policy_decision = self._policy.evaluate(action)

        # Step 3: Build composite decision
        return ClaimPolicyDecision(
            policy_decision=policy_decision,
            claim_verdict=claim.verdict,
            monotone_valid=claim.is_monotone_valid,
            justification_gap=claim.assessed.justification_gap,
            congruence_score=claim.assessed.congruence_score,
            explanation=self._build_explanation(claim, policy_decision),
        )

    @staticmethod
    def _build_explanation(claim: ActionClaim, policy_decision: PolicyDecision) -> str:
        parts: list[str] = []
        if not policy_decision.is_allowed:
            parts.append(f"Policy blocked by rule: {policy_decision.matched_rule}")
        if not claim.is_monotone_valid:
            parts.append("Monotone constraint violated in delegation chain")
        from aegis.core.action_claim import ClaimVerdict

        if claim.verdict == ClaimVerdict.BLOCK:
            parts.append(
                f"Justification gap {claim.assessed.justification_gap:.3f} exceeds block threshold"
            )
        elif claim.verdict == ClaimVerdict.ESCALATE:
            parts.append(
                f"Justification gap {claim.assessed.justification_gap:.3f} requires human review"
            )
        if claim.assessed.congruence_score < 0.5:
            parts.append(
                f"Low congruence ({claim.assessed.congruence_score:.2f}): "
                f"declared intent may contradict parameters"
            )
        return "; ".join(parts) if parts else "Approved"
