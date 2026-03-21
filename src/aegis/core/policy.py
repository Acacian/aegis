"""YAML-based policy engine.

Evaluates agent actions against configurable rules to determine
risk levels and approval requirements.
"""

from __future__ import annotations

import fnmatch
import re as _re
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

    Glob patterns are compiled to regex at construction time for
    faster repeated matching.
    """

    match_type: str = "*"
    match_target: str = "*"
    risk_level: RiskLevel = RiskLevel.MEDIUM
    approval: Approval = Approval.APPROVE
    name: str = ""
    conditions: dict[str, Any] = field(default_factory=dict)
    match_agent: str = "*"

    def __post_init__(self) -> None:
        """Pre-compile glob patterns to regex for fast matching."""
        self._re_type: _re.Pattern[str] = _re.compile(fnmatch.translate(self.match_type))
        self._re_target: _re.Pattern[str] = _re.compile(fnmatch.translate(self.match_target))
        self._re_agent: _re.Pattern[str] | None = (
            _re.compile(fnmatch.translate(self.match_agent)) if self.match_agent != "*" else None
        )

    def matches(self, action: Action) -> bool:
        """Check if this rule matches the given action.

        Both glob patterns and conditions (if any) must match.
        When ``match_agent`` is set to a non-wildcard value, the
        action's ``agent_id`` must also match.
        """
        if not self._re_type.match(action.type) or not self._re_target.match(action.target):
            return False
        if self._re_agent is not None and not self._re_agent.match(action.agent_id or "*"):
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

    def __post_init__(self) -> None:
        """Initialize evaluation cache (disabled by default)."""
        self._cache: dict[tuple[str, ...], PolicyDecision] = {}
        self._cache_maxsize: int = 0

    def with_cache(self, maxsize: int = 256) -> Policy:
        """Enable evaluation caching. Returns self for chaining.

        When enabled, ``evaluate()`` results are cached by action key
        ``(type, target, agent_id)``. Only results from rules without
        conditions are cached, since conditions (time-based, param-based)
        can produce different results for the same key.

        Args:
            maxsize: Maximum number of cached entries. Default 256.
        """
        self._cache_maxsize = maxsize
        self._cache = {}
        return self

    def clear_cache(self) -> None:
        """Clear the evaluation cache."""
        self._cache.clear()

    def evaluate(self, action: Action) -> PolicyDecision:
        """Evaluate an action against the policy rules.

        Rules are checked in order; the first match wins.
        Falls back to defaults if no rule matches.
        """
        if self._cache_maxsize > 0:
            key = (action.type, action.target, action.agent_id)
            cached = self._cache.get(key)
            if cached is not None:
                return PolicyDecision(
                    action=action,
                    risk_level=cached.risk_level,
                    approval=cached.approval,
                    matched_rule=cached.matched_rule,
                )
            decision = self._evaluate_uncached(action)
            if self._should_cache(decision):
                if len(self._cache) >= self._cache_maxsize:
                    # Evict oldest entry (FIFO)
                    oldest = next(iter(self._cache))
                    del self._cache[oldest]
                self._cache[key] = decision
            return decision

        return self._evaluate_uncached(action)

    def _evaluate_uncached(self, action: Action) -> PolicyDecision:
        """Evaluate without cache lookup."""
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

    def _should_cache(self, decision: PolicyDecision) -> bool:
        """Determine whether a decision is safe to cache.

        Only caches results from rules without conditions, since
        time-based or param-based conditions make results
        non-deterministic for the same cache key.
        """
        for rule in self.rules:
            rule_name = rule.name or f"{rule.match_type}@{rule.match_target}"
            if rule_name == decision.matched_rule:
                return not rule.conditions
        # Default rule has no conditions
        return decision.matched_rule == "<default>"

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
