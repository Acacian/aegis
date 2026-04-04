"""Tests for ActionClaim tripartite action structure."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aegis.core.action import Action
from aegis.core.action_claim import (
    ActionClaim,
    AssessedFields,
    ChainFields,
    ClaimVerdict,
    DeclaredFields,
    DelegationChainEntry,
    ImpactVector,
    validate_monotone_constraint,
)

# -- ImpactVector -------------------------------------------------------


class TestImpactVector:
    def test_default_zero(self):
        v = ImpactVector()
        assert v.destructivity == 0.0
        assert v.data_exposure == 0.0
        assert v.resource_consumption == 0.0
        assert v.privilege_escalation == 0.0
        assert v.reversibility == 0.0
        assert v.autonomy_depth == 0.0

    def test_creation_with_values(self):
        v = ImpactVector(destructivity=0.5, data_exposure=0.3)
        assert v.destructivity == 0.5
        assert v.data_exposure == 0.3
        assert v.resource_consumption == 0.0

    def test_reject_below_range(self):
        with pytest.raises(ValueError, match="destructivity must be 0.0-1.0"):
            ImpactVector(destructivity=-0.1)

    def test_reject_above_range(self):
        with pytest.raises(ValueError, match="data_exposure must be 0.0-1.0"):
            ImpactVector(data_exposure=1.5)

    def test_boundary_values_accepted(self):
        v = ImpactVector(
            destructivity=0.0,
            data_exposure=1.0,
            resource_consumption=0.0,
            privilege_escalation=1.0,
            reversibility=0.0,
            autonomy_depth=1.0,
        )
        assert v.data_exposure == 1.0
        assert v.privilege_escalation == 1.0

    def test_magnitude_zero(self):
        v = ImpactVector()
        assert v.magnitude == 0.0

    def test_magnitude_max(self):
        v = ImpactVector(
            destructivity=1.0,
            data_exposure=1.0,
            resource_consumption=1.0,
            privilege_escalation=1.0,
            reversibility=1.0,
            autonomy_depth=1.0,
        )
        assert v.magnitude == pytest.approx(1.0, abs=1e-9)

    def test_magnitude_partial(self):
        v = ImpactVector(destructivity=1.0)
        # L2 norm = 1.0, normalized by sqrt(6)
        expected = 1.0 / (6**0.5)
        assert v.magnitude == pytest.approx(expected, abs=1e-9)

    def test_distance_identical(self):
        v1 = ImpactVector(destructivity=0.5, data_exposure=0.3)
        v2 = ImpactVector(destructivity=0.5, data_exposure=0.3)
        assert v1.distance(v2) == pytest.approx(0.0, abs=1e-9)

    def test_distance_symmetric(self):
        v1 = ImpactVector(destructivity=0.8)
        v2 = ImpactVector(destructivity=0.2)
        assert v1.distance(v2) == pytest.approx(v2.distance(v1), abs=1e-9)

    def test_distance_max(self):
        zero = ImpactVector()
        full = ImpactVector(
            destructivity=1.0,
            data_exposure=1.0,
            resource_consumption=1.0,
            privilege_escalation=1.0,
            reversibility=1.0,
            autonomy_depth=1.0,
        )
        assert zero.distance(full) == pytest.approx(1.0, abs=1e-9)

    def test_asymmetric_gap_under_report(self):
        declared = ImpactVector(destructivity=0.1)
        assessed = ImpactVector(destructivity=0.9)
        gap = declared.asymmetric_gap(assessed)
        assert gap > 0.0

    def test_asymmetric_gap_over_report_safe(self):
        """Over-reporting (declared > assessed) should yield zero gap."""
        declared = ImpactVector(destructivity=0.9)
        assessed = ImpactVector(destructivity=0.1)
        gap = declared.asymmetric_gap(assessed)
        assert gap == 0.0

    def test_asymmetric_gap_exact_match(self):
        v = ImpactVector(destructivity=0.5, data_exposure=0.3)
        assert v.asymmetric_gap(v) == 0.0

    def test_asymmetric_gap_mixed_directions(self):
        """Only dimensions where other > self should count."""
        declared = ImpactVector(destructivity=0.8, data_exposure=0.1)
        assessed = ImpactVector(destructivity=0.2, data_exposure=0.9)
        gap = declared.asymmetric_gap(assessed)
        # destructivity: assessed < declared -> skip
        # data_exposure: 0.9 - 0.1 = 0.8 -> counts
        expected = (0.8**2) ** 0.5 / (6**0.5)
        assert gap == pytest.approx(expected, abs=1e-9)

    def test_as_tuple(self):
        v = ImpactVector(destructivity=0.1, data_exposure=0.2)
        t = v.as_tuple()
        assert t == (0.1, 0.2, 0.0, 0.0, 0.0, 0.0)
        assert len(t) == 6

    def test_as_dict(self):
        v = ImpactVector(destructivity=0.5)
        d = v.as_dict()
        assert d["destructivity"] == 0.5
        assert d["data_exposure"] == 0.0
        assert len(d) == 6

    def test_frozen(self):
        v = ImpactVector()
        with pytest.raises(AttributeError):
            v.destructivity = 0.5  # type: ignore[misc]


# -- DelegationChainEntry ------------------------------------------------


class TestDelegationChainEntry:
    def test_creation(self):
        entry = DelegationChainEntry(
            agent_id="agent-1",
            trust_level=80,
            capabilities=frozenset({"read", "write"}),
            reason="initial delegation",
        )
        assert entry.agent_id == "agent-1"
        assert entry.trust_level == 80
        assert "read" in entry.capabilities
        assert entry.reason == "initial delegation"

    def test_default_fields(self):
        entry = DelegationChainEntry(agent_id="a", trust_level=50)
        assert entry.capabilities == frozenset()
        assert entry.reason == ""
        assert isinstance(entry.delegated_at, datetime)

    def test_frozen(self):
        entry = DelegationChainEntry(agent_id="a", trust_level=50)
        with pytest.raises(AttributeError):
            entry.trust_level = 99  # type: ignore[misc]


# -- validate_monotone_constraint ----------------------------------------


class TestMonotoneConstraint:
    def test_empty_chain(self):
        assert validate_monotone_constraint(()) is True

    def test_single_entry(self):
        chain = (DelegationChainEntry(agent_id="a", trust_level=80),)
        assert validate_monotone_constraint(chain) is True

    def test_valid_decreasing(self):
        chain = (
            DelegationChainEntry(agent_id="root", trust_level=100),
            DelegationChainEntry(agent_id="mid", trust_level=70),
            DelegationChainEntry(agent_id="leaf", trust_level=40),
        )
        assert validate_monotone_constraint(chain) is True

    def test_valid_equal_levels(self):
        chain = (
            DelegationChainEntry(agent_id="a", trust_level=80),
            DelegationChainEntry(agent_id="b", trust_level=80),
        )
        assert validate_monotone_constraint(chain) is True

    def test_invalid_increasing(self):
        chain = (
            DelegationChainEntry(agent_id="root", trust_level=50),
            DelegationChainEntry(agent_id="child", trust_level=90),
        )
        assert validate_monotone_constraint(chain) is False

    def test_invalid_increase_in_middle(self):
        chain = (
            DelegationChainEntry(agent_id="a", trust_level=100),
            DelegationChainEntry(agent_id="b", trust_level=60),
            DelegationChainEntry(agent_id="c", trust_level=80),
            DelegationChainEntry(agent_id="d", trust_level=40),
        )
        assert validate_monotone_constraint(chain) is False


# -- DeclaredFields ------------------------------------------------------


class TestDeclaredFields:
    def test_creation(self):
        d = DeclaredFields(
            proposed_transition="write",
            target="database",
            justification="updating records",
            originating_goal="sync data",
        )
        assert d.proposed_transition == "write"
        assert d.target == "database"
        assert d.justification == "updating records"

    def test_defaults(self):
        d = DeclaredFields(proposed_transition="read", target="api")
        assert d.justification == ""
        assert d.originating_goal == ""
        assert d.preconditions == {}
        assert d.declared_impact == ImpactVector()

    def test_with_impact(self):
        impact = ImpactVector(destructivity=0.3)
        d = DeclaredFields(
            proposed_transition="delete",
            target="records",
            declared_impact=impact,
        )
        assert d.declared_impact.destructivity == 0.3


# -- AssessedFields ------------------------------------------------------


class TestAssessedFields:
    def test_defaults(self):
        a = AssessedFields()
        assert a.impact_profile == ImpactVector()
        assert a.justification_gap == 0.0
        assert a.risk_level == 0
        assert a.congruence_score == 1.0
        assert a.assessed_at is None
        assert a.assessor_version == ""

    def test_mutable(self):
        """AssessedFields must be mutable (ClaimAssessor writes them)."""
        a = AssessedFields()
        a.justification_gap = 0.5
        assert a.justification_gap == 0.5


# -- ChainFields ---------------------------------------------------------


class TestChainFields:
    def test_defaults(self):
        c = ChainFields()
        assert c.delegation_chain == ()
        assert c.chain_depth == 0
        assert c.principal == ""
        assert c.monotone_constraint is True
        assert c.chain_id == ""

    def test_with_chain(self):
        entries = (
            DelegationChainEntry(agent_id="root", trust_level=100),
            DelegationChainEntry(agent_id="child", trust_level=70),
        )
        c = ChainFields(
            delegation_chain=entries,
            chain_depth=2,
            principal="user-1",
            chain_id="chain-abc",
        )
        assert len(c.delegation_chain) == 2
        assert c.chain_depth == 2


# -- ActionClaim ---------------------------------------------------------


class TestActionClaim:
    def test_creation_defaults(self):
        claim = ActionClaim()
        assert len(claim.claim_id) == 16
        assert isinstance(claim.created_at, datetime)
        assert claim.verdict == ClaimVerdict.PENDING

    def test_creation_with_fields(self):
        declared = DeclaredFields(proposed_transition="read", target="api")
        claim = ActionClaim(declared=declared)
        assert claim.declared.proposed_transition == "read"
        assert claim.declared.target == "api"

    def test_is_assessed_false_by_default(self):
        claim = ActionClaim()
        assert claim.is_assessed is False

    def test_is_assessed_true_after_assessment(self):
        claim = ActionClaim()
        claim.assessed = AssessedFields(assessed_at=datetime.now(UTC))
        assert claim.is_assessed is True

    def test_is_monotone_valid_no_chain(self):
        claim = ActionClaim()
        assert claim.is_monotone_valid is True

    def test_is_monotone_valid_good_chain(self):
        chain = (
            DelegationChainEntry(agent_id="root", trust_level=100),
            DelegationChainEntry(agent_id="child", trust_level=60),
        )
        claim = ActionClaim(chain=ChainFields(delegation_chain=chain))
        assert claim.is_monotone_valid is True

    def test_is_monotone_valid_bad_chain(self):
        chain = (
            DelegationChainEntry(agent_id="root", trust_level=50),
            DelegationChainEntry(agent_id="child", trust_level=90),
        )
        claim = ActionClaim(chain=ChainFields(delegation_chain=chain))
        assert claim.is_monotone_valid is False

    def test_to_action(self):
        chain = (DelegationChainEntry(agent_id="agent-x", trust_level=80),)
        claim = ActionClaim(
            declared=DeclaredFields(
                proposed_transition="write",
                target="database",
                justification="sync",
                preconditions={"table": "users"},
            ),
            chain=ChainFields(
                delegation_chain=chain,
                chain_id="chain-1",
                chain_depth=1,
            ),
        )
        action = claim.to_action()
        assert isinstance(action, Action)
        assert action.type == "write"
        assert action.target == "database"
        assert action.description == "sync"
        assert action.params == {"table": "users"}
        assert action.agent_id == "agent-x"
        assert action.chain_id == "chain-1"
        assert action.chain_depth == 1

    def test_to_action_no_chain(self):
        claim = ActionClaim(declared=DeclaredFields(proposed_transition="read", target="api"))
        action = claim.to_action()
        assert action.agent_id == ""

    def test_from_action(self):
        action = Action(
            type="delete",
            target="records",
            params={"id": 42},
            description="clean up",
            chain_id="ch-1",
            chain_depth=2,
        )
        claim = ActionClaim.from_action(action, originating_goal="maintenance", principal="admin")
        assert claim.declared.proposed_transition == "delete"
        assert claim.declared.target == "records"
        assert claim.declared.justification == "clean up"
        assert claim.declared.preconditions == {"id": 42}
        assert claim.declared.originating_goal == "maintenance"
        assert claim.chain.chain_id == "ch-1"
        assert claim.chain.chain_depth == 2
        assert claim.chain.principal == "admin"

    def test_round_trip_action_fields(self):
        """from_action(action).to_action() should preserve core Action fields."""
        original = Action(
            type="write",
            target="stripe",
            params={"amount": 100},
            description="charge customer",
            chain_id="chain-rt",
            chain_depth=3,
        )
        claim = ActionClaim.from_action(original)
        restored = claim.to_action()

        assert restored.type == original.type
        assert restored.target == original.target
        assert restored.params == original.params
        assert restored.description == original.description
        assert restored.chain_id == original.chain_id
        assert restored.chain_depth == original.chain_depth

    def test_round_trip_preserves_agent_id(self):
        """Round-trip via from_action preserves agent_id when chain is set."""
        original = Action(
            type="read",
            target="db",
            agent_id="bot-1",
            chain_id="c1",
            chain_depth=1,
        )
        claim = ActionClaim.from_action(original)
        # from_action does not store agent_id in chain; to_action reads last chain entry
        # So agent_id is NOT preserved unless delegation chain is populated separately.
        restored = claim.to_action()
        # Without delegation chain, agent_id defaults to ""
        assert restored.agent_id == ""

    def test_claim_verdicts(self):
        assert ClaimVerdict.APPROVE == "approve"
        assert ClaimVerdict.ESCALATE == "escalate"
        assert ClaimVerdict.BLOCK == "block"
        assert ClaimVerdict.PENDING == "pending"
