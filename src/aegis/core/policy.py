"""YAML-based policy engine.

Evaluates agent actions against configurable rules to determine
risk levels and approval requirements.
"""

from __future__ import annotations

import fnmatch
import re as _re
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml

from aegis.core.action import Action
from aegis.core.conditions import evaluate_conditions
from aegis.core.risk import RiskLevel
from aegis.core.semantic import SemanticEvaluator, evaluate_semantic_condition


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

    def matches(
        self,
        action: Action,
        semantic_evaluator: SemanticEvaluator | None = None,
    ) -> bool:
        """Check if this rule matches the given action.

        Both glob patterns and conditions (if any) must match.
        When ``match_agent`` is set to a non-wildcard value, the
        action's ``agent_id`` must also match.

        The ``semantic`` condition key is evaluated separately via
        :func:`evaluate_semantic_condition` because it needs the full
        :class:`Action`, not just ``params``.
        """
        if not self._re_type.match(action.type) or not self._re_target.match(action.target):
            return False
        if self._re_agent is not None and not self._re_agent.match(action.agent_id or "*"):
            return False
        if self.conditions:
            # Handle "semantic" condition separately (needs full Action).
            semantic_cond = self.conditions.get("semantic")
            other_conditions = (
                {k: v for k, v in self.conditions.items() if k != "semantic"}
                if semantic_cond is not None
                else self.conditions
            )
            if other_conditions and not evaluate_conditions(other_conditions, action.params):
                return False
            if semantic_cond is not None and not evaluate_semantic_condition(
                semantic_cond, action, evaluator=semantic_evaluator
            ):
                return False
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
    default_approval: Approval = Approval.BLOCK
    scope: str = "global"
    scope_id: str = ""
    version: int = 1
    semantic_evaluator: SemanticEvaluator | None = field(default=None, repr=False)
    plan_rules: Any = field(default=None, repr=False)  # PlanRules | None

    def __post_init__(self) -> None:
        """Initialize evaluation cache (disabled by default)."""
        self._cache: OrderedDict[tuple[str, ...], PolicyDecision] = OrderedDict()
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
        self._cache = OrderedDict()
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
                self._cache.move_to_end(key)  # LRU: mark as recently used
                return PolicyDecision(
                    action=action,
                    risk_level=cached.risk_level,
                    approval=cached.approval,
                    matched_rule=cached.matched_rule,
                )
            decision = self._evaluate_uncached(action)
            if self._is_cacheable(action):
                if len(self._cache) >= self._cache_maxsize:
                    self._cache.popitem(last=False)  # LRU: evict least-recently-used
                self._cache[key] = decision
            return decision

        return self._evaluate_uncached(action)

    def _evaluate_uncached(self, action: Action) -> PolicyDecision:
        """Evaluate without cache lookup."""
        for rule in self.rules:
            if rule.matches(action, semantic_evaluator=self.semantic_evaluator):
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

    def _is_cacheable(self, action: Action) -> bool:
        """Determine whether evaluation results for *action* are safe to cache.

        Returns ``False`` if **any** rule with conditions has glob patterns
        that match this action.  This prevents the scenario where a cached
        unconditional match shadows a conditional rule that would match
        with different params or at a different time.
        """
        for rule in self.rules:
            if (
                rule.conditions
                and rule._re_type.match(action.type)
                and rule._re_target.match(action.target)
                and (rule._re_agent is None or rule._re_agent.match(action.agent_id or "*"))
            ):
                return False
        return True

    def merge(self, other: Policy) -> Policy:
        """Merge another policy into this one.

        Rules from ``other`` are appended after this policy's rules.
        Defaults come from this policy (the base).

        Useful for environment-specific overrides::

            base = Policy.from_yaml("base.yaml")
            prod = Policy.from_yaml("prod.yaml")
            combined = base.merge(prod)
        """
        merged_plan_rules = _merge_plan_rules(self.plan_rules, other.plan_rules)
        return Policy(
            rules=self.rules + other.rules,
            default_risk_level=self.default_risk_level,
            default_approval=self.default_approval,
            scope=self.scope,
            scope_id=self.scope_id,
            version=self.version,
            semantic_evaluator=self.semantic_evaluator or other.semantic_evaluator,
            plan_rules=merged_plan_rules,
        )

    @classmethod
    def from_yaml(
        cls,
        path: str | Path,
        semantic_evaluator: SemanticEvaluator | None = None,
    ) -> Policy:
        """Load a policy from a YAML file.

        Args:
            path: Path to the YAML policy file.
            semantic_evaluator: Optional custom semantic evaluator.
                When provided, it replaces the built-in keyword matcher
                for ``semantic`` conditions.

        Raises:
            FileNotFoundError: If the file does not exist.
            TypeError: If the YAML content is not a mapping.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data, semantic_evaluator=semantic_evaluator)

    @classmethod
    def from_yaml_files(
        cls,
        *paths: str | Path,
        semantic_evaluator: SemanticEvaluator | None = None,
    ) -> Policy:
        """Load and merge multiple policy files.

        The first file's defaults are used as the base. Rules from
        subsequent files are appended in order (first-match-wins still
        applies, so put higher-priority rules in earlier files).

        Example::

            policy = Policy.from_yaml_files("base.yaml", "overrides.yaml")
        """
        if not paths:
            return cls()
        base = cls.from_yaml(paths[0], semantic_evaluator=semantic_evaluator)
        for p in paths[1:]:
            base = base.merge(cls.from_yaml(p))
        return base

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any] | None,
        semantic_evaluator: SemanticEvaluator | None = None,
    ) -> Policy:
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
        default_approval = Approval(defaults.get("approval", "block"))

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

        # Plan-level rules (optional)
        plan_rules = None
        plan_rules_data = data.get("plan_rules")
        if plan_rules_data:
            from aegis.core.plan_rules import PlanRules

            plan_rules = PlanRules.from_dict(plan_rules_data)

        return cls(
            rules=rules,
            default_risk_level=default_risk,
            default_approval=default_approval,
            scope=data.get("scope", "global"),
            scope_id=data.get("scope_id", ""),
            version=int(data.get("version", 1)),
            semantic_evaluator=semantic_evaluator,
            plan_rules=plan_rules,
        )


def _merge_plan_rules(a: Any, b: Any) -> Any:
    """Merge two PlanRules (or None) for Policy.merge().

    Combines sequence patterns and picks the more restrictive cumulative risk.
    """
    if a is None:
        return b
    if b is None:
        return a

    from aegis.core.plan_rules import PlanRules

    merged_patterns = list(a.sequence_patterns) + list(b.sequence_patterns)

    merged_cumulative = None
    if a.cumulative_risk and b.cumulative_risk:
        # More restrictive = lower threshold
        if a.cumulative_risk.max_total_risk <= b.cumulative_risk.max_total_risk:
            merged_cumulative = a.cumulative_risk
        else:
            merged_cumulative = b.cumulative_risk
    else:
        merged_cumulative = a.cumulative_risk or b.cumulative_risk

    return PlanRules(
        sequence_patterns=merged_patterns,
        cumulative_risk=merged_cumulative,
    )
