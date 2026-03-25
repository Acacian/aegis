"""Tests for AgentConstitution, AgentOntology, Obligation, Constraint."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis.core.action import Action
from aegis.core.constitution import (
    AgentConstitution,
    AgentOntology,
    Constraint,
    Obligation,
)

# ── AgentOntology ────────────────────────────────────────────────────────


class TestAgentOntology:
    def test_creation(self) -> None:
        o = AgentOntology(role="analyst", domain="finance", description="Analyzes data")
        assert o.role == "analyst"
        assert o.domain == "finance"
        assert o.tags == frozenset()

    def test_frozen(self) -> None:
        o = AgentOntology(role="analyst")
        with pytest.raises(AttributeError):
            o.role = "changed"  # type: ignore[misc]

    def test_defaults(self) -> None:
        o = AgentOntology(role="worker")
        assert o.domain == ""
        assert o.description == ""
        assert o.tags == frozenset()

    def test_with_tags(self) -> None:
        o = AgentOntology(role="worker", tags=frozenset({"internal", "read-only"}))
        assert "internal" in o.tags
        assert len(o.tags) == 2


# ── Obligation ───────────────────────────────────────────────────────────


class TestObligation:
    def test_creation(self) -> None:
        ob = Obligation(name="audit_all", trigger="*", action_type="audit")
        assert ob.name == "audit_all"
        assert ob.trigger == "*"

    def test_frozen(self) -> None:
        ob = Obligation(name="test")
        with pytest.raises(AttributeError):
            ob.name = "changed"  # type: ignore[misc]

    def test_defaults(self) -> None:
        ob = Obligation(name="test")
        assert ob.trigger == "*"
        assert ob.action_type == ""
        assert ob.params == {}


# ── Constraint ───────────────────────────────────────────────────────────


class TestConstraint:
    def test_creation(self) -> None:
        c = Constraint(
            name="no_writes",
            forbidden_patterns=frozenset({"write_*", "delete_*"}),
        )
        assert c.name == "no_writes"
        assert "write_*" in c.forbidden_patterns

    def test_frozen(self) -> None:
        c = Constraint(name="test")
        with pytest.raises(AttributeError):
            c.name = "changed"  # type: ignore[misc]

    def test_defaults(self) -> None:
        c = Constraint(name="test")
        assert c.forbidden_patterns == frozenset()
        assert c.forbidden_targets == frozenset()


# ── AgentConstitution ────────────────────────────────────────────────────


class TestAgentConstitution:
    def test_creation(self) -> None:
        const = AgentConstitution(
            ontology=AgentOntology(role="analyst"),
            capabilities=frozenset({"read_*"}),
            obligations=(Obligation(name="audit"),),
            constraints=(Constraint(name="no_writes", forbidden_patterns=frozenset({"write_*"})),),
        )
        assert const.ontology.role == "analyst"
        assert "read_*" in const.capabilities
        assert len(const.obligations) == 1
        assert len(const.constraints) == 1

    def test_frozen(self) -> None:
        const = AgentConstitution(ontology=AgentOntology(role="test"))
        with pytest.raises(AttributeError):
            const.ontology = AgentOntology(role="changed")  # type: ignore[misc]


class TestConstitutionFromDict:
    def test_full_dict(self) -> None:
        data = {
            "ontology": {
                "role": "analyst",
                "domain": "finance",
                "description": "Analyzes data",
                "tags": ["read-only"],
            },
            "capabilities": ["read_*", "report_*"],
            "obligations": [
                {"name": "audit", "trigger": "*", "action_type": "audit"},
            ],
            "constraints": [
                {"name": "no_writes", "forbidden_patterns": ["write_*"]},
            ],
        }
        const = AgentConstitution.from_dict(data)
        assert const.ontology.role == "analyst"
        assert const.ontology.domain == "finance"
        assert "read-only" in const.ontology.tags
        assert "read_*" in const.capabilities
        assert const.obligations[0].name == "audit"
        assert "write_*" in const.constraints[0].forbidden_patterns

    def test_minimal_dict(self) -> None:
        const = AgentConstitution.from_dict({"ontology": {"role": "worker"}})
        assert const.ontology.role == "worker"
        assert const.capabilities == frozenset()
        assert const.obligations == ()
        assert const.constraints == ()

    def test_empty_dict(self) -> None:
        const = AgentConstitution.from_dict({})
        assert const.ontology.role == ""


class TestConstitutionToDict:
    def test_roundtrip(self) -> None:
        original = AgentConstitution(
            ontology=AgentOntology(role="analyst", domain="finance", tags=frozenset({"a", "b"})),
            capabilities=frozenset({"read_*"}),
            obligations=(Obligation(name="audit", trigger="*"),),
            constraints=(Constraint(name="no_writes", forbidden_patterns=frozenset({"write_*"})),),
        )
        d = original.to_dict()
        restored = AgentConstitution.from_dict(d)

        assert restored.ontology.role == original.ontology.role
        assert restored.capabilities == original.capabilities
        assert restored.obligations[0].name == original.obligations[0].name
        assert (
            restored.constraints[0].forbidden_patterns
            == original.constraints[0].forbidden_patterns
        )


class TestConstitutionFromYaml:
    def test_load_yaml(self, tmp_path: Path) -> None:
        yaml_content = """
constitution:
  ontology:
    role: analyst
    domain: finance
  capabilities:
    - read_*
  obligations:
    - name: audit
      trigger: "*"
  constraints:
    - name: no_writes
      forbidden_patterns:
        - write_*
"""
        p = tmp_path / "const.yaml"
        p.write_text(yaml_content)
        const = AgentConstitution.from_yaml(p)
        assert const.ontology.role == "analyst"
        assert "read_*" in const.capabilities


# ── Merge Inherited ──────────────────────────────────────────────────────


class TestConstitutionMerge:
    def test_both_present(self) -> None:
        parent = AgentConstitution(
            ontology=AgentOntology(role="orchestrator"),
            capabilities=frozenset({"read_*", "write_*"}),
            obligations=(Obligation(name="audit"),),
            constraints=(
                Constraint(name="no_delete", forbidden_patterns=frozenset({"delete_*"})),
            ),
        )
        child = AgentConstitution(
            ontology=AgentOntology(role="worker"),
            capabilities=frozenset({"read_crm"}),
            obligations=(Obligation(name="report"),),
            constraints=(
                Constraint(name="no_external", forbidden_targets=frozenset({"external_*"})),
            ),
        )
        merged = AgentConstitution.merge_inherited(
            parent, child, intersect_capabilities=frozenset({"read_crm"})
        )
        assert merged.ontology.role == "worker"  # child wins
        assert merged.capabilities == frozenset({"read_crm"})
        assert len(merged.obligations) == 2  # union
        assert len(merged.constraints) == 2  # union
        obligation_names = {o.name for o in merged.obligations}
        assert "audit" in obligation_names
        assert "report" in obligation_names

    def test_child_overrides_obligation(self) -> None:
        parent = AgentConstitution(
            ontology=AgentOntology(role="parent"),
            obligations=(Obligation(name="audit", action_type="log"),),
        )
        child = AgentConstitution(
            ontology=AgentOntology(role="child"),
            obligations=(Obligation(name="audit", action_type="full_audit"),),
        )
        merged = AgentConstitution.merge_inherited(parent, child, frozenset())
        assert len(merged.obligations) == 1
        assert merged.obligations[0].action_type == "full_audit"  # child wins

    def test_parent_only(self) -> None:
        parent = AgentConstitution(
            ontology=AgentOntology(role="orchestrator"),
            obligations=(Obligation(name="audit"),),
        )
        merged = AgentConstitution.merge_inherited(parent, None, frozenset({"read_*"}))
        assert merged.ontology.role == "orchestrator"
        assert merged.capabilities == frozenset({"read_*"})
        assert len(merged.obligations) == 1

    def test_child_only(self) -> None:
        child = AgentConstitution(
            ontology=AgentOntology(role="worker"),
            constraints=(Constraint(name="no_writes"),),
        )
        merged = AgentConstitution.merge_inherited(None, child, frozenset({"read_*"}))
        assert merged.ontology.role == "worker"
        assert merged.capabilities == frozenset({"read_*"})
        assert len(merged.constraints) == 1

    def test_both_none(self) -> None:
        merged = AgentConstitution.merge_inherited(None, None, frozenset({"x"}))
        assert merged.ontology.role == ""
        assert merged.capabilities == frozenset({"x"})


# ── Check Constraints ────────────────────────────────────────────────────


class TestCheckConstraints:
    def test_no_violations(self) -> None:
        const = AgentConstitution(
            ontology=AgentOntology(role="test"),
            constraints=(Constraint(name="no_writes", forbidden_patterns=frozenset({"write_*"})),),
        )
        action = Action(type="read_data", target="crm")
        assert const.check_constraints(action) == []

    def test_pattern_violation(self) -> None:
        const = AgentConstitution(
            ontology=AgentOntology(role="test"),
            constraints=(Constraint(name="no_writes", forbidden_patterns=frozenset({"write_*"})),),
        )
        action = Action(type="write_record", target="crm")
        violations = const.check_constraints(action)
        assert len(violations) == 1
        assert "no_writes" in violations[0]

    def test_target_violation(self) -> None:
        const = AgentConstitution(
            ontology=AgentOntology(role="test"),
            constraints=(
                Constraint(name="no_external", forbidden_targets=frozenset({"external_*"})),
            ),
        )
        action = Action(type="read", target="external_api")
        violations = const.check_constraints(action)
        assert len(violations) == 1
        assert "no_external" in violations[0]

    def test_multiple_constraints(self) -> None:
        const = AgentConstitution(
            ontology=AgentOntology(role="test"),
            constraints=(
                Constraint(name="c1", forbidden_patterns=frozenset({"write_*"})),
                Constraint(name="c2", forbidden_targets=frozenset({"external_*"})),
            ),
        )
        action = Action(type="write_data", target="external_api")
        violations = const.check_constraints(action)
        assert len(violations) == 2
