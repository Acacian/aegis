"""YAML-based policy engine.

Evaluates agent actions against configurable rules to determine
risk levels and approval requirements.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml

from aegis.core.action import Action
from aegis.core.conditions import evaluate_conditions
from aegis.core.risk import RiskLevel


class Approval(StrEnum):
    """Approval requirement for an action."""

    AUTO = "auto"  # Execute without human approval
    APPROVE = "approve"  # Require human approval before execution
    BLOCK = "block"  # Never execute


@dataclass(frozen=True)
class PolicyDecision:
    """Result of evaluating an action against the policy.

    Produced by :meth:`Policy.evaluate` and consumed by the runtime engine
    to decide whether to execute, prompt for approval, or block.
    """

    action: Action
    risk_level: RiskLevel
    approval: Approval
    matched_rule: str = ""

    @property
    def is_allowed(self) -> bool:
        """Whether the action is allowed (not blocked) by the policy."""
        return self.approval != Approval.BLOCK


@dataclass
class PolicyRule:
    """A single rule in the policy.

    Matches actions by type and target using glob patterns,
    with optional conditions for time-based and param-based logic.
    """

    match_type: str = "*"
    match_target: str = "*"
    risk_level: RiskLevel = RiskLevel.MEDIUM
    approval: Approval = Approval.APPROVE
    name: str = ""
    conditions: dict[str, Any] = field(default_factory=dict)
    match_agent: str = "*"

    def matches(self, action: Action) -> bool:
        """Check if this rule matches the given action.

        Both glob patterns and conditions (if any) must match.
        When ``match_agent`` is set to a non-wildcard value, the
        action's ``agent_id`` must also match.
        """
        glob_match = fnmatch.fnmatch(action.type, self.match_type) and fnmatch.fnmatch(
            action.target, self.match_target
        )
        if not glob_match:
            return False
        if self.match_agent != "*" and not fnmatch.fnmatch(
            action.agent_id or "*", self.match_agent
        ):
            return False
        if self.conditions:
            return evaluate_conditions(self.conditions, action.params)
        return True


@dataclass
class Policy:
    """YAML-based policy engine that maps actions to risk levels and approval requirements.

    Rules are evaluated in order; the first matching rule wins.
    If no rule matches, the default risk level and approval are used.

    Example YAML::

        version: "1"
        defaults:
          risk_level: medium
          approval: approve
        rules:
          - name: read_ops
            match:
              type: read
            risk_level: low
            approval: auto
    """

    rules: list[PolicyRule] = field(default_factory=list)
    default_risk_level: RiskLevel = RiskLevel.MEDIUM
    default_approval: Approval = Approval.APPROVE
    scope: str = "global"
    scope_id: str = ""
    version: int = 1

    def evaluate(self, action: Action) -> PolicyDecision:
        """Evaluate an action against the policy rules.

        Rules are checked in order; the first match wins.
        Falls back to defaults if no rule matches.
        """
        for rule in self.rules:
            if rule.matches(action):
                return PolicyDecision(
                    action=action,
                    risk_level=rule.risk_level,
                    approval=rule.approval,
                    matched_rule=rule.name or f"{rule.match_type}@{rule.match_target}",
                )

        return PolicyDecision(
            action=action,
            risk_level=self.default_risk_level,
            approval=self.default_approval,
            matched_rule="<default>",
        )

    def merge(self, other: Policy) -> Policy:
        """Merge another policy into this one.

        Rules from ``other`` are appended after this policy's rules.
        Defaults come from this policy (the base).

        Useful for environment-specific overrides::

            base = Policy.from_yaml("base.yaml")
            prod = Policy.from_yaml("prod.yaml")
            combined = base.merge(prod)
        """
        return Policy(
            rules=self.rules + other.rules,
            default_risk_level=self.default_risk_level,
            default_approval=self.default_approval,
            scope=self.scope,
            scope_id=self.scope_id,
            version=self.version,
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> Policy:
        """Load a policy from a YAML file.

        Raises:
            FileNotFoundError: If the file does not exist.
            TypeError: If the YAML content is not a mapping.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")
        with path.open() as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data)

    @classmethod
    def from_yaml_files(cls, *paths: str | Path) -> Policy:
        """Load and merge multiple policy files.

        The first file's defaults are used as the base. Rules from
        subsequent files are appended in order (first-match-wins still
        applies, so put higher-priority rules in earlier files).

        Example::

            policy = Policy.from_yaml_files("base.yaml", "overrides.yaml")
        """
        if not paths:
            return cls()
        base = cls.from_yaml(paths[0])
        for p in paths[1:]:
            base = base.merge(cls.from_yaml(p))
        return base

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Policy:
        """Load a policy from a dictionary.

        Returns a default policy when *data* is ``None`` (e.g. an empty
        YAML file).  Raises :class:`TypeError` for any other non-dict input.
        """
        if data is None:
            return cls()
        if not isinstance(data, dict):
            raise TypeError(
                f"Expected a dict for policy data, got {type(data).__name__}. "
                "Check that your YAML file contains a mapping (key: value), not a scalar."
            )
        defaults = data.get("defaults") or {}
        default_risk = RiskLevel[defaults.get("risk_level", "medium").upper()]
        default_approval = Approval(defaults.get("approval", "approve"))

        rules: list[PolicyRule] = []
        for i, rule_data in enumerate(data.get("rules") or []):
            match = rule_data.get("match", {})
            rules.append(
                PolicyRule(
                    match_type=match.get("type", "*"),
                    match_target=match.get("target", "*"),
                    risk_level=RiskLevel[rule_data.get("risk_level", "medium").upper()],
                    approval=Approval(rule_data.get("approval", "approve")),
                    name=rule_data.get("name", f"rule_{i}"),
                    conditions=rule_data.get("conditions", {}),
                    match_agent=match.get("agent", "*"),
                )
            )

        return cls(
            rules=rules,
            default_risk_level=default_risk,
            default_approval=default_approval,
            scope=data.get("scope", "global"),
            scope_id=data.get("scope_id", ""),
            version=int(data.get("version", 1)),
        )
