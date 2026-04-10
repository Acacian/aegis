"""ActionClaim-aware policy evaluation.

Extends the existing :class:`~aegis.core.policy.Policy` engine to work
with :class:`~aegis.core.action_claim.ActionClaim` objects.

The evaluation pipeline:
1. Assess the claim (compute independent impact_profile / justification_gap)
2. Convert ActionClaim → Action (via ``to_action()``)
3. Run standard Policy evaluation (first-match-wins)
4. If ``claim.selection_context`` is set, run SelectionAuditor and overlay
   the verdict onto the claim (BLOCK on severe findings, ESCALATE on
   suspicious findings). Detects selection-by-negation / cosmetic
   alignment (Santander, arXiv:2602.14606).
5. Overlay justification gap verdict (BLOCK/ESCALATE override)
6. Overlay monotone constraint check (violation → BLOCK)
7. Return :class:`ClaimPolicyDecision`
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from aegis.core.policy import Approval, Policy, PolicyDecision

if TYPE_CHECKING:
    from aegis.core.action_claim import ActionClaim, ClaimVerdict
    from aegis.core.selection_audit import SelectionAuditor, SelectionAuditResult


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
    selection_audit_result: SelectionAuditResult | None = None
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

    Wraps a standard :class:`Policy` with claim assessment logic and
    optional selection auditing.

    Args:
        policy: The underlying :class:`Policy` for rule evaluation.
        assess: Run :class:`ClaimAssessor` automatically when the claim
            has not been assessed yet.
        selection_auditor: Optional :class:`SelectionAuditor`. If *None*,
            the module-level global auditor (set via
            :func:`aegis.core.selection_audit.set_global_auditor`) is
            used. Pass a fresh auditor instance here to opt out of the
            global singleton.
        selection_block_threshold: Maximum severity score before a
            selection-audit finding escalates to
            :attr:`ClaimVerdict.BLOCK`. Default ``0.8``.
    """

    def __init__(
        self,
        policy: Policy,
        *,
        assess: bool = True,
        selection_auditor: SelectionAuditor | None = None,
        selection_block_threshold: float = 0.8,
    ) -> None:
        self._policy = policy
        self._assess = assess
        self._assessor: Any = None
        self._selection_auditor = selection_auditor
        self._selection_block_threshold = selection_block_threshold

    def _get_assessor(self) -> Any:
        if self._assessor is None:
            from aegis.core.justification_gap import ClaimAssessor

            self._assessor = ClaimAssessor()
        return self._assessor

    def _resolve_selection_auditor(self) -> SelectionAuditor | None:
        """Return the auditor to use: explicit instance > global singleton."""
        if self._selection_auditor is not None:
            return self._selection_auditor
        from aegis.core.selection_audit import _get_global_auditor

        return _get_global_auditor()

    def _apply_selection_verdict(
        self,
        claim: ActionClaim,
        audit_result: SelectionAuditResult,
    ) -> None:
        """Escalate the claim verdict based on a selection audit result.

        Rules (only *raises* severity; never relaxes an existing BLOCK):

        - ``overall_risk >= selection_block_threshold`` → ``BLOCK``
        - ``is_suspicious`` (risk > 0.5)                → ``ESCALATE``
        - otherwise: leave verdict untouched
        """
        from aegis.core.action_claim import ClaimVerdict

        if claim.verdict == ClaimVerdict.BLOCK:
            return  # already hardest verdict

        if audit_result.overall_risk >= self._selection_block_threshold:
            claim.verdict = ClaimVerdict.BLOCK
            return

        if audit_result.is_suspicious and claim.verdict != ClaimVerdict.ESCALATE:
            claim.verdict = ClaimVerdict.ESCALATE

    def evaluate(self, claim: ActionClaim) -> ClaimPolicyDecision:
        """Evaluate an ActionClaim against the policy."""
        # Step 1: Assess if needed
        if self._assess and not claim.is_assessed:
            self._get_assessor().assess(claim)

        # Step 2: Standard policy evaluation via Action bridge
        action = claim.to_action()
        policy_decision = self._policy.evaluate(action)

        # Step 3: Selection audit (if context provided)
        selection_audit_result: SelectionAuditResult | None = None
        if claim.selection_context is not None:
            auditor = self._resolve_selection_auditor()
            if auditor is None:
                # Lazy-construct a default auditor so that passing a
                # selection_context "just works" without requiring the
                # caller to wire a global singleton.
                from aegis.core.selection_audit import SelectionAuditor

                auditor = SelectionAuditor()
                self._selection_auditor = auditor
            selection_audit_result = auditor.audit(claim.selection_context)
            self._apply_selection_verdict(claim, selection_audit_result)

        # Step 4: Build composite decision
        return ClaimPolicyDecision(
            policy_decision=policy_decision,
            claim_verdict=claim.verdict,
            monotone_valid=claim.is_monotone_valid,
            justification_gap=claim.assessed.justification_gap,
            congruence_score=claim.assessed.congruence_score,
            selection_audit_result=selection_audit_result,
            explanation=self._build_explanation(claim, policy_decision, selection_audit_result),
        )

    @staticmethod
    def _build_explanation(
        claim: ActionClaim,
        policy_decision: PolicyDecision,
        selection_audit_result: SelectionAuditResult | None = None,
    ) -> str:
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
        if selection_audit_result is not None and selection_audit_result.findings:
            finding_summary = ", ".join(
                f.finding_type.value for f in selection_audit_result.findings
            )
            parts.append(
                f"Selection audit risk {selection_audit_result.overall_risk:.2f} "
                f"({finding_summary})"
            )
        return "; ".join(parts) if parts else "Approved"
