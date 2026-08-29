"""Agent Constitution — ontology, capabilities, obligations, and constraints.

Defines the constitutional identity of an AI agent: what it IS (ontology),
what it CAN do (capabilities), what it MUST do (obligations), and what it
MUST NOT do (constraints).

Constitutions are immutable, YAML-definable, and propagate through
delegation chains via :meth:`AgentConstitution.merge_inherited`.

Example::

    from aegis.core.constitution import AgentConstitution, AgentOntology

    constitution = AgentConstitution(
        ontology=AgentOntology(role="data-analyst", domain="finance"),
        capabilities=frozenset({"read_*", "report_*"}),
        obligations=(
            Obligation(name="audit_all", trigger="*", action_type="audit"),
        ),
        constraints=(
            Constraint(name="no_writes", forbidden_patterns=frozenset({"write_*", "delete_*"})),
        ),
    )
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aegis.core.action import Action


# ── Ontology ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AgentOntology:
    """What the agent IS — its role, domain, and classification.

    Attributes:
        role: Primary role identifier (e.g. ``"data-analyst"``, ``"orchestrator"``).
        domain: Operational domain (e.g. ``"finance"``, ``"healthcare"``).
        description: Human-readable description of the agent's purpose.
        tags: Arbitrary classification tags for filtering and grouping.
    """

    role: str
    domain: str = ""
    description: str = ""
    tags: frozenset[str] = frozenset()


# ── Obligation ───────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Obligation:
    """Something the agent MUST do when a trigger condition matches.

    Obligations are additive during delegation: a child inherits all
    parent obligations plus its own.

    Attributes:
        name: Unique identifier (e.g. ``"audit_all_actions"``).
        description: Human-readable description.
        trigger: Glob pattern for action types that activate this obligation.
        action_type: The required action (e.g. ``"audit"``, ``"report_cost"``).
        params: Additional parameters for the obligation action.
    """

    name: str
    description: str = ""
    trigger: str = "*"
    action_type: str = ""
    params: dict[str, Any] = field(default_factory=dict)


# ── Constraint ───────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Constraint:
    """Something the agent MUST NOT do — forbidden action patterns.

    Constraints are additive during delegation: a child inherits all
    parent constraints plus its own.

    Attributes:
        name: Unique identifier (e.g. ``"no_data_exfiltration"``).
        description: Human-readable description.
        forbidden_patterns: Glob patterns for forbidden action types.
        forbidden_targets: Glob patterns for forbidden targets.
    """

    name: str
    description: str = ""
    forbidden_patterns: frozenset[str] = frozenset()
    forbidden_targets: frozenset[str] = frozenset()


# ── AgentConstitution ────────────────────────────────────────────────────


@dataclass(frozen=True)
class AgentConstitution:
    """Constitutional definition for an AI agent.

    Combines ontology (what the agent IS), capabilities (what it CAN do),
    obligations (what it MUST do), and constraints (what it MUST NOT do).

    Constitutions are frozen (immutable) and propagate through delegation
    chains via :meth:`merge_inherited`.

    Example::

        constitution = AgentConstitution.from_dict({
            "ontology": {"role": "analyst", "domain": "finance"},
            "capabilities": ["read_*"],
            "obligations": [{"name": "audit_all", "trigger": "*"}],
            "constraints": [{"name": "no_writes", "forbidden_patterns": ["write_*"]}],
        })
    """

    ontology: AgentOntology
    capabilities: frozenset[str] = frozenset()
    obligations: tuple[Obligation, ...] = ()
    constraints: tuple[Constraint, ...] = ()

    # ── Serialization ────────────────────────────────────────────────

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentConstitution:
        """Create a constitution from a dictionary (e.g. parsed YAML).

        Missing keys are tolerated and filled with defaults.
        """
        ont_data = data.get("ontology", {})
        ontology = AgentOntology(
            role=ont_data.get("role", ""),
            domain=ont_data.get("domain", ""),
            description=ont_data.get("description", ""),
            tags=frozenset(ont_data.get("tags", [])),
        )

        capabilities = frozenset(data.get("capabilities", []))

        obligations: list[Obligation] = []
        for o in data.get("obligations", []):
            obligations.append(
                Obligation(
                    name=o.get("name", ""),
                    description=o.get("description", ""),
                    trigger=o.get("trigger", "*"),
                    action_type=o.get("action_type", ""),
                    params=dict(o.get("params", {})),
                )
            )

        constraints: list[Constraint] = []
        for c in data.get("constraints", []):
            constraints.append(
                Constraint(
                    name=c.get("name", ""),
                    description=c.get("description", ""),
                    forbidden_patterns=frozenset(c.get("forbidden_patterns", [])),
                    forbidden_targets=frozenset(c.get("forbidden_targets", [])),
                )
            )

        return cls(
            ontology=ontology,
            capabilities=capabilities,
            obligations=tuple(obligations),
            constraints=tuple(constraints),
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> AgentConstitution:
        """Load a constitution from a YAML file."""
        import yaml

        with open(path, encoding="utf-8") as f:
            loaded = yaml.safe_load(f)

        # safe_load returns Any — a YAML file can hold a scalar or a list just
        # as easily as a mapping. Narrow both the document and the section so
        # from_dict always receives a dict, whatever the file turns out to be.
        data: dict[str, Any] = loaded if isinstance(loaded, dict) else {}
        section = data.get("constitution", data)
        return cls.from_dict(section if isinstance(section, dict) else {})

    def to_dict(self) -> dict[str, Any]:
        """Serialize the constitution to a plain dictionary."""
        return {
            "ontology": {
                "role": self.ontology.role,
                "domain": self.ontology.domain,
                "description": self.ontology.description,
                "tags": sorted(self.ontology.tags),
            },
            "capabilities": sorted(self.capabilities),
            "obligations": [
                {
                    "name": o.name,
                    "description": o.description,
                    "trigger": o.trigger,
                    "action_type": o.action_type,
                    **({"params": dict(o.params)} if o.params else {}),
                }
                for o in self.obligations
            ],
            "constraints": [
                {
                    "name": c.name,
                    "description": c.description,
                    "forbidden_patterns": sorted(c.forbidden_patterns),
                    "forbidden_targets": sorted(c.forbidden_targets),
                }
                for c in self.constraints
            ],
        }

    # ── Inheritance ──────────────────────────────────────────────────

    @staticmethod
    def merge_inherited(
        parent: AgentConstitution | None,
        child: AgentConstitution | None,
        intersect_capabilities: frozenset[str],
    ) -> AgentConstitution:
        """Merge parent and child constitutions for delegation.

        Rules:
        - **Ontology**: child's ontology takes precedence.
        - **Capabilities**: uses the already-intersected set from delegation.
        - **Obligations**: union (parent + child). On name collision, child wins.
        - **Constraints**: union (parent + child). On name collision, child wins.

        If one side is ``None``, the other is used with intersected capabilities.
        """
        if parent is None and child is None:
            return AgentConstitution(
                ontology=AgentOntology(role=""),
                capabilities=intersect_capabilities,
            )

        if parent is None:
            assert child is not None
            return AgentConstitution(
                ontology=child.ontology,
                capabilities=intersect_capabilities,
                obligations=child.obligations,
                constraints=child.constraints,
            )

        if child is None:
            return AgentConstitution(
                ontology=parent.ontology,
                capabilities=intersect_capabilities,
                obligations=parent.obligations,
                constraints=parent.constraints,
            )

        # Both present: merge obligations and constraints
        # Child wins on name collision
        merged_obligations: dict[str, Obligation] = {}
        for o in parent.obligations:
            merged_obligations[o.name] = o
        for o in child.obligations:
            merged_obligations[o.name] = o  # child overrides

        merged_constraints: dict[str, Constraint] = {}
        for c in parent.constraints:
            merged_constraints[c.name] = c
        for c in child.constraints:
            merged_constraints[c.name] = c  # child overrides

        return AgentConstitution(
            ontology=child.ontology,
            capabilities=intersect_capabilities,
            obligations=tuple(merged_obligations.values()),
            constraints=tuple(merged_constraints.values()),
        )

    # ── Constraint checking ──────────────────────────────────────────

    def check_constraints(self, action: Action) -> list[str]:
        """Check whether an action violates any constraints.

        Returns a list of violation descriptions (empty if no violations).
        """
        violations: list[str] = []
        for c in self.constraints:
            for pattern in c.forbidden_patterns:
                if fnmatch.fnmatch(action.type, pattern):
                    violations.append(
                        f"Constraint '{c.name}' violated: "
                        f"action type '{action.type}' matches forbidden pattern '{pattern}'"
                    )
                    break
            for pattern in c.forbidden_targets:
                if fnmatch.fnmatch(action.target, pattern):
                    violations.append(
                        f"Constraint '{c.name}' violated: "
                        f"target '{action.target}' matches forbidden pattern '{pattern}'"
                    )
                    break
        return violations
