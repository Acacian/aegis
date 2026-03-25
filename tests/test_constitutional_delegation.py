"""Tests for constitutional inheritance through delegation."""

from __future__ import annotations

from aegis.core.agent_identity import AgentIdentity, AgentRegistry
from aegis.core.constitution import (
    AgentConstitution,
    AgentOntology,
    Constraint,
    Obligation,
)


class TestDelegationWithConstitution:
    def test_constitution_inherited(self) -> None:
        """Child inherits parent's constitution through delegation."""
        registry = AgentRegistry()

        parent_const = AgentConstitution(
            ontology=AgentOntology(role="orchestrator"),
            obligations=(Obligation(name="audit"),),
            constraints=(
                Constraint(name="no_delete", forbidden_patterns=frozenset({"delete_*"})),
            ),
        )
        parent = AgentIdentity(
            agent_id="parent",
            name="Parent",
            capabilities=frozenset({"read_*", "write_*"}),
            trust_level=90,
            constitution=parent_const,
        )
        registry.register(parent)

        child = AgentIdentity(
            agent_id="child",
            name="Child",
            capabilities=frozenset({"read_crm", "write_crm"}),
            trust_level=80,
        )
        delegated = registry.delegate("parent", child)

        assert delegated.constitution is not None
        # Parent obligations inherited
        assert len(delegated.constitution.obligations) == 1
        assert delegated.constitution.obligations[0].name == "audit"
        # Parent constraints inherited
        assert len(delegated.constitution.constraints) == 1
        assert delegated.constitution.constraints[0].name == "no_delete"
        # Capabilities intersected (existing behavior preserved)
        assert "read_crm" in delegated.capabilities
        assert "write_crm" in delegated.capabilities

    def test_obligations_additive(self) -> None:
        """Both parent and child obligations are kept."""
        registry = AgentRegistry()

        parent = AgentIdentity(
            agent_id="parent",
            name="Parent",
            capabilities=frozenset({"read_*"}),
            trust_level=90,
            constitution=AgentConstitution(
                ontology=AgentOntology(role="orchestrator"),
                obligations=(Obligation(name="audit"),),
            ),
        )
        registry.register(parent)

        child = AgentIdentity(
            agent_id="child",
            name="Child",
            capabilities=frozenset({"read_data"}),
            trust_level=80,
            constitution=AgentConstitution(
                ontology=AgentOntology(role="worker"),
                obligations=(Obligation(name="report_cost"),),
            ),
        )
        delegated = registry.delegate("parent", child)

        assert delegated.constitution is not None
        names = {o.name for o in delegated.constitution.obligations}
        assert "audit" in names
        assert "report_cost" in names

    def test_constraints_additive(self) -> None:
        """Both parent and child constraints are kept."""
        registry = AgentRegistry()

        parent = AgentIdentity(
            agent_id="parent",
            name="Parent",
            capabilities=frozenset({"read_*", "write_*"}),
            trust_level=90,
            constitution=AgentConstitution(
                ontology=AgentOntology(role="orchestrator"),
                constraints=(
                    Constraint(name="no_delete", forbidden_patterns=frozenset({"delete_*"})),
                ),
            ),
        )
        registry.register(parent)

        child = AgentIdentity(
            agent_id="child",
            name="Child",
            capabilities=frozenset({"read_crm", "write_crm"}),
            trust_level=80,
            constitution=AgentConstitution(
                ontology=AgentOntology(role="worker"),
                constraints=(
                    Constraint(name="no_external", forbidden_targets=frozenset({"external_*"})),
                ),
            ),
        )
        delegated = registry.delegate("parent", child)

        assert delegated.constitution is not None
        constraint_names = {c.name for c in delegated.constitution.constraints}
        assert "no_delete" in constraint_names
        assert "no_external" in constraint_names

    def test_child_ontology_wins(self) -> None:
        """Delegated agent keeps child's ontology."""
        registry = AgentRegistry()

        parent = AgentIdentity(
            agent_id="parent",
            name="Parent",
            capabilities=frozenset({"read_*"}),
            trust_level=90,
            constitution=AgentConstitution(
                ontology=AgentOntology(role="orchestrator", domain="global"),
            ),
        )
        registry.register(parent)

        child = AgentIdentity(
            agent_id="child",
            name="Child",
            capabilities=frozenset({"read_data"}),
            trust_level=80,
            constitution=AgentConstitution(
                ontology=AgentOntology(role="analyst", domain="finance"),
            ),
        )
        delegated = registry.delegate("parent", child)

        assert delegated.constitution is not None
        assert delegated.constitution.ontology.role == "analyst"
        assert delegated.constitution.ontology.domain == "finance"


class TestDelegationWithoutConstitution:
    def test_no_constitution_preserves_behavior(self) -> None:
        """Delegation without constitutions works exactly as before."""
        registry = AgentRegistry()

        parent = AgentIdentity(
            agent_id="parent",
            name="Parent",
            capabilities=frozenset({"read_*", "write_*"}),
            trust_level=90,
        )
        registry.register(parent)

        child = AgentIdentity(
            agent_id="child",
            name="Child",
            capabilities=frozenset({"read_crm"}),
            trust_level=80,
        )
        delegated = registry.delegate("parent", child)

        assert delegated.constitution is None
        assert delegated.capabilities == frozenset({"read_crm"})
        assert delegated.trust_level == 80
        assert delegated.parent_id == "parent"


class TestConstitutionChain:
    def test_three_level_delegation(self) -> None:
        """Constitution propagates through 3 levels of delegation."""
        registry = AgentRegistry()

        root = AgentIdentity(
            agent_id="root",
            name="Root",
            capabilities=frozenset({"read_*", "write_*", "admin_*"}),
            trust_level=100,
            constitution=AgentConstitution(
                ontology=AgentOntology(role="root"),
                obligations=(Obligation(name="audit"),),
                constraints=(
                    Constraint(name="no_delete", forbidden_patterns=frozenset({"delete_*"})),
                ),
            ),
        )
        registry.register(root)

        mid = AgentIdentity(
            agent_id="mid",
            name="Mid",
            capabilities=frozenset({"read_*", "write_*"}),
            trust_level=80,
            constitution=AgentConstitution(
                ontology=AgentOntology(role="manager"),
                obligations=(Obligation(name="report"),),
            ),
        )
        registry.delegate("root", mid)

        leaf = AgentIdentity(
            agent_id="leaf",
            name="Leaf",
            capabilities=frozenset({"read_data"}),
            trust_level=60,
        )
        delegated_leaf = registry.delegate("mid", leaf)

        assert delegated_leaf.constitution is not None
        # Should have both root and mid obligations
        names = {o.name for o in delegated_leaf.constitution.obligations}
        assert "audit" in names
        assert "report" in names
        # Should have root constraint
        assert len(delegated_leaf.constitution.constraints) == 1
        assert delegated_leaf.constitution.constraints[0].name == "no_delete"
