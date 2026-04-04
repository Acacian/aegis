"""Justification Gap computation for ActionClaim governance.

Quantifies the distance between agent-declared impact and
independently assessed impact. Asymmetric: only under-reporting
counts toward the gap.

Theoretical basis:
- COA-MAS (Carvalho): Justification Gap concept
- Santander "Selection as Power" (arXiv:2602.14606): CEFL framework
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from aegis.core.action_claim import ActionClaim, ClaimVerdict, ImpactVector


# -- Impact Scorer Protocol ---------------------------------------------------


@runtime_checkable
class ImpactScorer(Protocol):
    """Protocol for computing ImpactVector from action parameters.

    Implementations MUST score based on actual parameters only.
    Agent's declared_impact MUST NOT be referenced.
    """

    def score(self, claim: ActionClaim) -> ImpactVector: ...


# -- Impact Rules -------------------------------------------------------------


@dataclass(frozen=True)
class ImpactRule:
    """Custom impact scoring rule (YAML-configurable)."""

    name: str
    match_type: str = "*"
    match_target: str = "*"
    overrides: dict[str, float] = field(default_factory=dict)

    def matches(self, action_type: str, target: str, params: dict[str, Any]) -> bool:
        return fnmatch.fnmatch(action_type, self.match_type) and fnmatch.fnmatch(
            target, self.match_target
        )


# -- Rule-Based Impact Scorer -------------------------------------------------


class RuleBasedImpactScorer:
    """Rule-based impact scorer (Tier 1, no external deps).

    Scores impact from action parameters via pattern matching.
    """

    def __init__(self, rules: list[ImpactRule] | None = None) -> None:
        self._rules = rules or []

    def score(self, claim: ActionClaim) -> ImpactVector:
        from aegis.core.action_claim import ImpactVector

        scores: dict[str, float] = {
            "destructivity": 0.0,
            "data_exposure": 0.0,
            "resource_consumption": 0.0,
            "privilege_escalation": 0.0,
            "reversibility": 0.0,
            "autonomy_depth": 0.0,
        }

        action_type = claim.declared.proposed_transition.lower()
        target = claim.declared.target.lower()
        params = claim.declared.preconditions

        scores["destructivity"] = self._score_destructivity(action_type, params)
        scores["data_exposure"] = self._score_data_exposure(action_type, target, params)
        scores["resource_consumption"] = self._score_resource_consumption(params)
        scores["privilege_escalation"] = self._score_privilege_escalation(
            action_type, target, params
        )
        scores["reversibility"] = self._score_reversibility(action_type, params)
        scores["autonomy_depth"] = self._score_autonomy_depth(claim)

        for rule in self._rules:
            if rule.matches(action_type, target, params):
                for dim, val in rule.overrides.items():
                    if dim in scores:
                        scores[dim] = max(scores[dim], val)

        return ImpactVector(**scores)

    @staticmethod
    def _score_destructivity(action_type: str, params: dict[str, Any]) -> float:
        _DESTROY = {"drop_database", "destroy", "format", "wipe"}
        _DELETE = {"delete", "remove", "drop", "truncate", "purge"}
        _WRITE = {"update", "modify", "patch", "write", "set"}
        _READ = {"read", "list", "get", "search", "query", "fetch", "find"}

        if any(kw in action_type for kw in _DESTROY):
            return 1.0
        if any(kw in action_type for kw in _DELETE):
            is_bulk = params.get("bulk", False) or params.get("count", 1) > 10
            return 0.9 if is_bulk else 0.7
        if any(kw in action_type for kw in _WRITE):
            is_bulk = params.get("bulk", False) or params.get("count", 1) > 10
            return 0.5 if is_bulk else 0.3
        if any(kw in action_type for kw in _READ):
            return 0.0
        return 0.2

    @staticmethod
    def _score_data_exposure(action_type: str, target: str, params: dict[str, Any]) -> float:
        _EXPORT = {"export", "download", "send", "email", "share", "upload", "transfer"}
        _PII = {"ssn", "passport", "credit_card", "phone", "address"}
        _EXTERNAL = {"email", "slack", "webhook", "s3", "gcs", "external", "api"}

        is_export = any(kw in action_type for kw in _EXPORT)
        is_external = any(kw in target for kw in _EXTERNAL)

        param_keys = {str(k).lower() for k in params}
        param_vals = {str(v).lower() for v in params.values() if isinstance(v, str)}
        has_pii = bool((param_keys | param_vals) & _PII)

        if is_export and is_external and has_pii:
            return 1.0 if params.get("bulk", False) else 0.9
        if is_export and is_external:
            return 0.7
        if is_export:
            return 0.5
        if has_pii:
            return 0.3
        return 0.0

    @staticmethod
    def _score_resource_consumption(params: dict[str, Any]) -> float:
        count = params.get("count", params.get("limit", params.get("batch_size", 1)))
        if isinstance(count, str):
            try:
                count = int(count)
            except ValueError:
                return 0.2
        if count <= 1:
            return 0.0
        if count <= 10:
            return 0.1
        if count <= 100:
            return 0.3
        if count <= 1000:
            return 0.5
        if count <= 10000:
            return 0.7
        return 0.9

    @staticmethod
    def _score_privilege_escalation(
        action_type: str, target: str, params: dict[str, Any]
    ) -> float:
        _BYPASS = {"bypass", "override", "disable_security", "skip_auth"}
        _ADMIN = {"admin", "root", "sudo", "superuser"}
        _ROLE = {"role", "permission", "grant", "revoke", "escalate"}

        combined = f"{action_type} {target} {' '.join(str(v) for v in params.values())}".lower()

        if any(kw in combined for kw in _BYPASS):
            return 1.0
        if any(kw in combined for kw in _ADMIN):
            return 0.7
        if any(kw in combined for kw in _ROLE):
            return 0.5
        return 0.0

    @staticmethod
    def _score_reversibility(action_type: str, params: dict[str, Any]) -> float:
        _IRREVERSIBLE = {"drop_database", "format", "wipe", "destroy"}
        _HARD = {"truncate", "purge", "bulk_delete"}
        _DELETE = {"delete", "remove", "drop"}

        if any(kw in action_type for kw in _IRREVERSIBLE):
            return 1.0
        if any(kw in action_type for kw in _HARD):
            return 0.9
        if any(kw in action_type for kw in _DELETE):
            has_backup = params.get("backup", False) or params.get("soft_delete", False)
            return 0.4 if has_backup else 0.7
        if "update" in action_type or "write" in action_type:
            return 0.3
        return 0.0

    @staticmethod
    def _score_autonomy_depth(claim: ActionClaim) -> float:
        depth = claim.chain.chain_depth
        if depth == 0:
            return 0.0
        if depth <= 1:
            return 0.2
        if depth <= 2:
            return 0.4
        if depth <= 3:
            return 0.6
        return min(0.2 * depth, 1.0)


# -- Congruence Checker -------------------------------------------------------


class CongruenceChecker:
    """Checks consistency between declared intent and actual parameters.

    Returns 0.0 (contradictory) to 1.0 (fully congruent).
    """

    _READ = frozenset({"read", "get", "list", "fetch", "query", "search"})
    _WRITE = frozenset({"write", "update", "modify", "patch", "set", "create"})
    _DELETE = frozenset({"delete", "remove", "drop", "truncate", "purge", "destroy"})

    def check(self, claim: ActionClaim) -> float:
        declared_intent = claim.declared.proposed_transition.lower()
        params = claim.declared.preconditions

        category = self._categorize(declared_intent)
        if category == "unknown":
            return 1.0

        param_str = " ".join(str(v) for v in params.values()).lower()

        contradictions = 0
        if category == "read":
            if any(kw in param_str for kw in self._DELETE | self._WRITE):
                contradictions += 1
        elif category == "write" and any(kw in param_str for kw in self._DELETE):
            contradictions += 1

        return max(0.0, 1.0 - contradictions * 0.5)

    def _categorize(self, intent: str) -> str:
        for kw in self._READ:
            if kw in intent:
                return "read"
        for kw in self._WRITE:
            if kw in intent:
                return "write"
        for kw in self._DELETE:
            if kw in intent:
                return "delete"
        return "unknown"


# -- Justification Gap Result -------------------------------------------------


@dataclass(frozen=True)
class JustificationGapResult:
    """Result of justification gap computation."""

    gap: float
    per_dimension_gap: dict[str, float]
    verdict: ClaimVerdict
    explanation: str


# -- Justification Gap Computer -----------------------------------------------


class JustificationGapComputer:
    """Computes justification gap between declared and assessed impact.

    Thresholds:
      gap <= 0.15  -> APPROVE
      0.15 < gap <= 0.40 -> ESCALATE
      gap > 0.40  -> BLOCK
    """

    def __init__(
        self,
        *,
        approve_threshold: float = 0.15,
        escalate_threshold: float = 0.40,
    ) -> None:
        self._approve = approve_threshold
        self._escalate = escalate_threshold

    def compute(
        self,
        declared: ImpactVector,
        assessed: ImpactVector,
    ) -> JustificationGapResult:
        """Compute gap. Only under-reporting counts (asymmetric)."""
        from aegis.core.action_claim import ClaimVerdict
        from aegis.core.action_claim import ImpactVector as _IV

        dims = _IV._DIMS
        per_dim: dict[str, float] = {}
        for d in dims:
            per_dim[d] = max(0.0, getattr(assessed, d) - getattr(declared, d))

        raw = sum(v**2 for v in per_dim.values()) ** 0.5
        gap = min(raw / (len(dims) ** 0.5), 1.0)

        if gap <= self._approve:
            verdict = ClaimVerdict.APPROVE
            explanation = f"Gap {gap:.3f} within tolerance (<={self._approve})"
        elif gap <= self._escalate:
            verdict = ClaimVerdict.ESCALATE
            worst = max(per_dim, key=lambda k: per_dim[k])
            explanation = (
                f"Gap {gap:.3f} requires escalation. "
                f"Largest under-report: {worst} "
                f"(declared={getattr(declared, worst):.2f}, "
                f"assessed={getattr(assessed, worst):.2f})"
            )
        else:
            verdict = ClaimVerdict.BLOCK
            worst = max(per_dim, key=lambda k: per_dim[k])
            explanation = (
                f"Gap {gap:.3f} exceeds block threshold (>{self._escalate}). "
                f"Worst: {worst} "
                f"(declared={getattr(declared, worst):.2f}, "
                f"assessed={getattr(assessed, worst):.2f})"
            )

        return JustificationGapResult(
            gap=gap,
            per_dimension_gap=per_dim,
            verdict=verdict,
            explanation=explanation,
        )


# -- Claim Assessor -----------------------------------------------------------


class ClaimAssessor:
    """Fills assessed fields on an ActionClaim.

    INVARIANT: Only ClaimAssessor may set assessed fields.
    """

    def __init__(
        self,
        impact_scorer: ImpactScorer | None = None,
        congruence_checker: CongruenceChecker | None = None,
        gap_computer: JustificationGapComputer | None = None,
    ) -> None:
        self._scorer = impact_scorer or RuleBasedImpactScorer()
        self._congruence = congruence_checker or CongruenceChecker()
        self._gap_computer = gap_computer or JustificationGapComputer()

    def assess(self, claim: ActionClaim) -> ActionClaim:
        """Assess the claim and fill assessed fields."""
        from aegis.core.action_claim import AssessedFields

        assessed_impact = self._scorer.score(claim)
        gap_result = self._gap_computer.compute(claim.declared.declared_impact, assessed_impact)
        congruence = self._congruence.check(claim)

        claim.assessed = AssessedFields(
            impact_profile=assessed_impact,
            justification_gap=gap_result.gap,
            risk_level=self._risk_from_magnitude(assessed_impact.magnitude),
            congruence_score=congruence,
            assessed_at=datetime.now(UTC),
            assessor_version="0.9.0",
        )
        claim.verdict = gap_result.verdict

        # Monotone constraint violation overrides to BLOCK
        if not claim.is_monotone_valid:
            from aegis.core.action_claim import ClaimVerdict

            claim.verdict = ClaimVerdict.BLOCK

        return claim

    @staticmethod
    def _risk_from_magnitude(magnitude: float) -> int:
        if magnitude <= 0.25:
            return 1  # LOW
        if magnitude <= 0.50:
            return 2  # MEDIUM
        if magnitude <= 0.75:
            return 3  # HIGH
        return 4  # CRITICAL
