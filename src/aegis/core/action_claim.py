"""ActionClaim -- tripartite action structure for selection governance.

Separates agent-declared intent from system-assessed impact, enabling
detection of cosmetic alignment (Santander "Selection as Power", arXiv:2602.14606)
and justification gap computation (COA-MAS, Carvalho).

Three field groups:
- Declared: agent-authored (untrusted)
- Assessed: Aegis-computed (independent verification)
- Chain: delegation infrastructure
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aegis.core.action import Action
    from aegis.core.selection_audit import SelectionSet


# -- Impact Vector (6-dimensional) -------------------------------------------


@dataclass(frozen=True)
class ImpactVector:
    """6-dimensional impact assessment vector.

    Each dimension is scored 0.0 (none) to 1.0 (maximum).
    """

    destructivity: float = 0.0
    data_exposure: float = 0.0
    resource_consumption: float = 0.0
    privilege_escalation: float = 0.0
    reversibility: float = 0.0
    autonomy_depth: float = 0.0

    _DIMS = (
        "destructivity",
        "data_exposure",
        "resource_consumption",
        "privilege_escalation",
        "reversibility",
        "autonomy_depth",
    )

    def __post_init__(self) -> None:
        for name in self._DIMS:
            val = getattr(self, name)
            if not (0.0 <= val <= 1.0):
                raise ValueError(f"{name} must be 0.0-1.0, got {val}")

    @property
    def magnitude(self) -> float:
        """L2 norm normalized to 0.0-1.0."""
        raw = float(sum(getattr(self, d) ** 2 for d in self._DIMS) ** 0.5)
        norm = len(self._DIMS) ** 0.5
        return float(min(raw / norm, 1.0))

    def distance(self, other: ImpactVector) -> float:
        """Euclidean distance normalized to 0.0-1.0."""
        raw = float(sum((getattr(self, d) - getattr(other, d)) ** 2 for d in self._DIMS) ** 0.5)
        norm = len(self._DIMS) ** 0.5
        return float(min(raw / norm, 1.0))

    def asymmetric_gap(self, other: ImpactVector) -> float:
        """Asymmetric gap: only counts dimensions where other > self.

        Used for justification gap where under-reporting (assessed > declared)
        is the concern. Over-reporting is conservative and safe.
        """
        diffs: list[float] = []
        for d in self._DIMS:
            diff = float(getattr(other, d)) - float(getattr(self, d))
            if diff > 0:
                diffs.append(diff**2)
        if not diffs:
            return 0.0
        raw = float(sum(diffs) ** 0.5)
        norm = len(self._DIMS) ** 0.5
        return float(min(raw / norm, 1.0))

    def as_tuple(self) -> tuple[float, ...]:
        return tuple(getattr(self, d) for d in self._DIMS)

    def as_dict(self) -> dict[str, float]:
        return {d: getattr(self, d) for d in self._DIMS}


# -- Delegation Chain --------------------------------------------------------


@dataclass(frozen=True)
class DelegationChainEntry:
    """Single link in the delegation chain."""

    agent_id: str
    trust_level: int  # 0-100
    capabilities: frozenset[str] = frozenset()
    delegated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    reason: str = ""


def validate_monotone_constraint(
    chain: tuple[DelegationChainEntry, ...],
) -> bool:
    """Verify trust levels are non-increasing along the chain.

    Returns True if monotone constraint is satisfied.
    """
    if len(chain) < 2:
        return True
    return all(chain[i].trust_level <= chain[i - 1].trust_level for i in range(1, len(chain)))


# -- Claim Verdict -----------------------------------------------------------


class ClaimVerdict(StrEnum):
    """Governance verdict for an ActionClaim."""

    APPROVE = "approve"
    ESCALATE = "escalate"
    BLOCK = "block"
    PENDING = "pending"


# -- Tripartite Field Groups -------------------------------------------------


@dataclass(frozen=True)
class DeclaredFields:
    """Agent-authored fields (untrusted).

    The agent declares what it intends to do. These fields are
    structurally separated from assessed fields to enable
    independent verification.
    """

    proposed_transition: str
    target: str
    justification: str = ""
    originating_goal: str = ""
    preconditions: dict[str, Any] = field(default_factory=dict)
    declared_impact: ImpactVector = field(default_factory=ImpactVector)


@dataclass
class AssessedFields:
    """Aegis-computed fields. Agent MUST NOT author these.

    The justification gap is the distance between declared_impact
    and the independently computed impact_profile.
    """

    impact_profile: ImpactVector = field(default_factory=ImpactVector)
    justification_gap: float = 0.0
    risk_level: int = 0
    congruence_score: float = 1.0
    assessed_at: datetime | None = None
    assessor_version: str = ""


@dataclass(frozen=True)
class ChainFields:
    """Delegation chain infrastructure fields.

    Authority must be monotone non-increasing along the chain.
    """

    delegation_chain: tuple[DelegationChainEntry, ...] = ()
    chain_depth: int = 0
    principal: str = ""
    monotone_constraint: bool = True
    chain_id: str = ""


# -- ActionClaim -------------------------------------------------------------


@dataclass
class ActionClaim:
    """Tripartite action structure for selection governance.

    Separates agent declaration from system assessment to detect
    cosmetic alignment and compute justification gap.
    """

    claim_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    declared: DeclaredFields = field(
        default_factory=lambda: DeclaredFields(
            proposed_transition="",
            target="",
        )
    )
    assessed: AssessedFields = field(default_factory=AssessedFields)
    chain: ChainFields = field(default_factory=ChainFields)

    # Optional selection context: when set, ClaimPolicy auto-runs SelectionAuditor
    # on this set and overlays the verdict onto the claim. Detects selection-by-
    # negation and cosmetic alignment (Santander, arXiv:2602.14606).
    selection_context: SelectionSet | None = None

    verdict: ClaimVerdict = ClaimVerdict.PENDING

    def to_action(self) -> Action:
        """Convert to Action for backward compatibility with existing pipeline."""
        from aegis.core.action import Action

        agent_id = ""
        if self.chain.delegation_chain:
            agent_id = self.chain.delegation_chain[-1].agent_id

        return Action(
            type=self.declared.proposed_transition,
            target=self.declared.target,
            params=self.declared.preconditions,
            description=self.declared.justification,
            agent_id=agent_id,
            chain_id=self.chain.chain_id,
            chain_depth=self.chain.chain_depth,
        )

    @classmethod
    def from_action(cls, action: Action, **kwargs: Any) -> ActionClaim:
        """Promote an Action to ActionClaim (migration path)."""
        return cls(
            declared=DeclaredFields(
                proposed_transition=action.type,
                target=action.target,
                justification=action.description,
                originating_goal=kwargs.get("originating_goal", ""),
                preconditions=action.params,
            ),
            chain=ChainFields(
                chain_id=action.chain_id,
                chain_depth=action.chain_depth,
                principal=kwargs.get("principal", ""),
            ),
        )

    @property
    def is_assessed(self) -> bool:
        return self.assessed.assessed_at is not None

    @property
    def is_monotone_valid(self) -> bool:
        if not self.chain.delegation_chain:
            return True
        return validate_monotone_constraint(self.chain.delegation_chain)
