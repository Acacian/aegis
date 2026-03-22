"""Policy-as-Code SDK — fluent builder API for defining policies programmatically.

Enables defining policies in Python code (notebooks, tests, dynamic scenarios)
instead of YAML files, while producing the same :class:`Policy` objects.

Example::

    from aegis.core.builder import PolicyBuilder

    policy = (
        PolicyBuilder()
        .defaults(risk_level="medium", approval="approve")
        .rule("read_auto")
            .match(type="read*")
            .risk("low")
            .approve_auto()
        .rule("write_approve")
            .match(type="write*", target="crm")
            .risk("medium")
            .approve_human()
        .rule("delete_block")
            .match(type="delete*")
            .risk("critical")
            .block()
            .when(semantic="destructive")
        .build()
    )
"""

from __future__ import annotations

from typing import Any

import yaml

from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.risk import RiskLevel

_VALID_RISK_LEVELS = frozenset({"low", "medium", "high", "critical"})
_VALID_APPROVALS = frozenset({"auto", "approve", "block"})


class RuleBuilder:
    """Fluent builder for a single policy rule.

    Created via :meth:`PolicyBuilder.rule` — not intended for direct
    instantiation.  Every setter returns ``self`` so calls can be chained.
    Calling :meth:`PolicyBuilder.rule` or :meth:`PolicyBuilder.build` from
    the returned ``RuleBuilder`` automatically delegates back to the parent
    ``PolicyBuilder``.
    """

    def __init__(self, name: str, parent: PolicyBuilder) -> None:
        self._name = name
        self._parent = parent
        self._match_type: str = "*"
        self._match_target: str = "*"
        self._match_agent: str = "*"
        self._risk_level: str | None = None
        self._approval: str | None = None
        self._conditions: dict[str, Any] = {}
        self._description_text: str = ""
        self._match_set: bool = False

    # -- match / filter ----------------------------------------------------

    def match(
        self,
        type: str = "*",  # noqa: A002
        target: str = "*",
        agent: str = "*",
    ) -> RuleBuilder:
        """Set the glob match pattern for action type, target, and agent.

        Args:
            type: Glob pattern for action type (e.g. ``"read*"``).
            target: Glob pattern for action target (e.g. ``"crm"``).
            agent: Glob pattern for agent id.
        """
        self._match_type = type
        self._match_target = target
        self._match_agent = agent
        self._match_set = True
        return self

    # -- risk --------------------------------------------------------------

    def risk(self, level: str) -> RuleBuilder:
        """Set the risk level (low / medium / high / critical)."""
        normalized = level.strip().lower()
        if normalized not in _VALID_RISK_LEVELS:
            raise ValueError(
                f"Invalid risk level '{level}'. "
                f"Must be one of: {', '.join(sorted(_VALID_RISK_LEVELS))}"
            )
        self._risk_level = normalized
        return self

    # -- approval shortcuts ------------------------------------------------

    def approve_auto(self) -> RuleBuilder:
        """Set approval to ``auto`` (execute without human approval)."""
        self._approval = "auto"
        return self

    def approve_human(self) -> RuleBuilder:
        """Set approval to ``approve`` (require human approval)."""
        self._approval = "approve"
        return self

    def block(self) -> RuleBuilder:
        """Set approval to ``block`` (never execute)."""
        self._approval = "block"
        return self

    # -- conditions --------------------------------------------------------

    def when(self, **conditions: Any) -> RuleBuilder:
        """Add conditions to the rule (semantic, time_range, param_*, etc.).

        Multiple calls merge conditions together::

            .when(semantic="destructive")
            .when(param_gt={"count": 100})
        """
        self._conditions.update(conditions)
        return self

    # -- description -------------------------------------------------------

    def description(self, text: str) -> RuleBuilder:
        """Add a human-readable description to the rule."""
        self._description_text = text
        return self

    # -- delegation back to parent -----------------------------------------

    def rule(self, name: str) -> RuleBuilder:
        """Finish this rule and start a new one on the parent builder."""
        return self._parent.rule(name)

    def build(self) -> Policy:
        """Finish this rule and build the final :class:`Policy`."""
        return self._parent.build()

    def to_yaml(self) -> str:
        """Finish this rule and return YAML via the parent builder."""
        return self._parent.to_yaml()

    def to_dict(self) -> dict[str, Any]:
        """Finish this rule and return dict via the parent builder."""
        return self._parent.to_dict()

    def defaults(self, **kwargs: Any) -> PolicyBuilder:
        """Delegate back to parent's :meth:`PolicyBuilder.defaults`."""
        return self._parent.defaults(**kwargs)

    def merge(self, other: PolicyBuilder | RuleBuilder) -> PolicyBuilder:
        """Delegate back to parent's :meth:`PolicyBuilder.merge`.

        Accepts either a :class:`PolicyBuilder` or a :class:`RuleBuilder`
        (extracts the parent builder in the latter case).
        """
        target = other._parent if isinstance(other, RuleBuilder) else other
        return self._parent.merge(target)

    def from_existing(self, policy: Policy) -> PolicyBuilder:
        """Delegate back to parent's :meth:`PolicyBuilder.from_existing`."""
        return self._parent.from_existing(policy)

    # -- internal ----------------------------------------------------------

    def _finalize(self) -> _RuleSpec:
        """Return the accumulated rule specification."""
        return _RuleSpec(
            name=self._name,
            match_type=self._match_type,
            match_target=self._match_target,
            match_agent=self._match_agent,
            risk_level=self._risk_level,
            approval=self._approval,
            conditions=dict(self._conditions),
            description=self._description_text,
            match_set=self._match_set,
        )


class _RuleSpec:
    """Internal value object that stores the raw data from a RuleBuilder."""

    __slots__ = (
        "name",
        "match_type",
        "match_target",
        "match_agent",
        "risk_level",
        "approval",
        "conditions",
        "description",
        "match_set",
    )

    def __init__(
        self,
        *,
        name: str,
        match_type: str,
        match_target: str,
        match_agent: str,
        risk_level: str | None,
        approval: str | None,
        conditions: dict[str, Any],
        description: str,
        match_set: bool,
    ) -> None:
        self.name = name
        self.match_type = match_type
        self.match_target = match_target
        self.match_agent = match_agent
        self.risk_level = risk_level
        self.approval = approval
        self.conditions = conditions
        self.description = description
        self.match_set = match_set


class PolicyBuilder:
    """Fluent builder for constructing :class:`Policy` objects programmatically.

    Usage::

        policy = (
            PolicyBuilder()
            .defaults(risk_level="medium", approval="approve")
            .rule("read_auto")
                .match(type="read*")
                .risk("low")
                .approve_auto()
            .build()
        )
    """

    def __init__(self) -> None:
        self._default_risk: str = "medium"
        self._default_approval: str = "approve"
        self._rule_builders: list[RuleBuilder] = []
        self._current_rule: RuleBuilder | None = None
        self._scope: str = "global"
        self._scope_id: str = ""
        self._version: int = 1

    # -- defaults ----------------------------------------------------------

    def defaults(
        self,
        risk_level: str | None = None,
        approval: str | None = None,
    ) -> PolicyBuilder:
        """Set default risk level and/or approval for unmatched actions.

        Args:
            risk_level: Default risk level (low/medium/high/critical).
            approval: Default approval (auto/approve/block).
        """
        if risk_level is not None:
            normalized = risk_level.strip().lower()
            if normalized not in _VALID_RISK_LEVELS:
                raise ValueError(
                    f"Invalid default risk level '{risk_level}'. "
                    f"Must be one of: {', '.join(sorted(_VALID_RISK_LEVELS))}"
                )
            self._default_risk = normalized
        if approval is not None:
            normalized_a = approval.strip().lower()
            if normalized_a not in _VALID_APPROVALS:
                raise ValueError(
                    f"Invalid default approval '{approval}'. "
                    f"Must be one of: {', '.join(sorted(_VALID_APPROVALS))}"
                )
            self._default_approval = normalized_a
        return self

    # -- scope / version ---------------------------------------------------

    def scope(self, scope: str, scope_id: str = "") -> PolicyBuilder:
        """Set policy scope and optional scope ID."""
        self._scope = scope
        self._scope_id = scope_id
        return self

    def version(self, version: int) -> PolicyBuilder:
        """Set policy version number."""
        self._version = version
        return self

    # -- rule management ---------------------------------------------------

    def rule(self, name: str) -> RuleBuilder:
        """Start defining a new rule with the given name.

        Returns a :class:`RuleBuilder` that chains back to this builder.
        """
        self._flush_current()
        rb = RuleBuilder(name, parent=self)
        self._current_rule = rb
        self._rule_builders.append(rb)
        return rb

    # -- from_existing / merge ---------------------------------------------

    def from_existing(self, policy: Policy) -> PolicyBuilder:
        """Seed this builder from an existing :class:`Policy` object.

        Copies defaults, scope, version, and all rules from *policy*.
        Any rules already added to this builder are cleared.
        """
        self._default_risk = policy.default_risk_level.name.lower()
        self._default_approval = policy.default_approval.value
        self._scope = policy.scope
        self._scope_id = policy.scope_id
        self._version = policy.version
        self._rule_builders = []
        self._current_rule = None

        for pr in policy.rules:
            rb = RuleBuilder(pr.name, parent=self)
            rb._match_type = pr.match_type
            rb._match_target = pr.match_target
            rb._match_agent = pr.match_agent
            rb._risk_level = pr.risk_level.name.lower()
            rb._approval = pr.approval.value
            rb._conditions = dict(pr.conditions)
            rb._match_set = True
            self._rule_builders.append(rb)

        return self

    def merge(self, other: PolicyBuilder | RuleBuilder) -> PolicyBuilder:
        """Merge another builder's rules into this one.

        Accepts either a :class:`PolicyBuilder` or a :class:`RuleBuilder`
        (extracts the parent builder in the latter case).

        Rules from *other* are appended after this builder's rules.
        Defaults are kept from this builder (the base).
        """
        target = other._parent if isinstance(other, RuleBuilder) else other
        self._flush_current()
        target._flush_current()

        for rb in target._rule_builders:
            spec = rb._finalize()
            new_rb = RuleBuilder(spec.name, parent=self)
            new_rb._match_type = spec.match_type
            new_rb._match_target = spec.match_target
            new_rb._match_agent = spec.match_agent
            new_rb._risk_level = spec.risk_level
            new_rb._approval = spec.approval
            new_rb._conditions = dict(spec.conditions)
            new_rb._description_text = spec.description
            new_rb._match_set = spec.match_set
            self._rule_builders.append(new_rb)

        return self

    # -- build / export ----------------------------------------------------

    def build(self) -> Policy:
        """Build and return a validated :class:`Policy` object.

        Raises:
            ValueError: On duplicate rule names, invalid risk levels,
                or rules with no match pattern set.
        """
        self._flush_current()
        specs = [rb._finalize() for rb in self._rule_builders]
        self._validate(specs)

        default_risk = RiskLevel[self._default_risk.upper()]
        default_approval = Approval(self._default_approval)

        rules: list[PolicyRule] = []
        for spec in specs:
            risk = RiskLevel[spec.risk_level.upper()] if spec.risk_level else default_risk
            approval = Approval(spec.approval) if spec.approval else default_approval
            rules.append(
                PolicyRule(
                    match_type=spec.match_type,
                    match_target=spec.match_target,
                    risk_level=risk,
                    approval=approval,
                    name=spec.name,
                    conditions=spec.conditions,
                    match_agent=spec.match_agent,
                )
            )

        return Policy(
            rules=rules,
            default_risk_level=default_risk,
            default_approval=default_approval,
            scope=self._scope,
            scope_id=self._scope_id,
            version=self._version,
        )

    def to_dict(self) -> dict[str, Any]:
        """Export the builder state as a policy dictionary.

        This produces the same structure as a parsed YAML policy file,
        suitable for serialization or :meth:`Policy.from_dict`.
        """
        self._flush_current()
        specs = [rb._finalize() for rb in self._rule_builders]
        self._validate(specs)

        result: dict[str, Any] = {
            "version": str(self._version),
            "defaults": {
                "risk_level": self._default_risk,
                "approval": self._default_approval,
            },
        }

        if self._scope != "global":
            result["scope"] = self._scope
        if self._scope_id:
            result["scope_id"] = self._scope_id

        rules_list: list[dict[str, Any]] = []
        for spec in specs:
            rule_dict: dict[str, Any] = {"name": spec.name}
            match_dict: dict[str, str] = {}
            if spec.match_type != "*":
                match_dict["type"] = spec.match_type
            if spec.match_target != "*":
                match_dict["target"] = spec.match_target
            if spec.match_agent != "*":
                match_dict["agent"] = spec.match_agent
            if match_dict:
                rule_dict["match"] = match_dict
            if spec.risk_level:
                rule_dict["risk_level"] = spec.risk_level
            if spec.approval:
                rule_dict["approval"] = spec.approval
            if spec.conditions:
                rule_dict["conditions"] = spec.conditions
            if spec.description:
                rule_dict["description"] = spec.description
            rules_list.append(rule_dict)

        if rules_list:
            result["rules"] = rules_list

        return result

    def to_yaml(self) -> str:
        """Export the builder state as a YAML string.

        The output is compatible with :meth:`Policy.from_yaml` /
        :meth:`Policy.from_dict`.
        """
        return yaml.dump(self.to_dict(), default_flow_style=False, sort_keys=False)

    # -- internal helpers --------------------------------------------------

    def _flush_current(self) -> None:
        """Flush the current in-progress rule builder (no-op if none)."""
        self._current_rule = None

    @staticmethod
    def _validate(specs: list[_RuleSpec]) -> None:
        """Validate rule specifications before building.

        Raises:
            ValueError: On duplicate names, invalid risk levels,
                or rules missing a match pattern.
        """
        # Check duplicate names
        seen_names: set[str] = set()
        for spec in specs:
            if spec.name in seen_names:
                raise ValueError(f"Duplicate rule name: '{spec.name}'")
            seen_names.add(spec.name)

        for spec in specs:
            # Check invalid risk levels
            if spec.risk_level is not None:
                normalized = spec.risk_level.strip().lower()
                if normalized not in _VALID_RISK_LEVELS:
                    raise ValueError(
                        f"Invalid risk level '{spec.risk_level}' in rule '{spec.name}'. "
                        f"Must be one of: {', '.join(sorted(_VALID_RISK_LEVELS))}"
                    )

            # Check for rules with no match pattern
            if not spec.match_set:
                raise ValueError(
                    f"Rule '{spec.name}' has no match pattern. "
                    "Call .match() to set at least a type or target pattern."
                )
