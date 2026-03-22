"""Policy diff and impact analysis engine.

Compares two policies to detect added, removed, and modified rules,
then optionally replays recorded actions to show concrete impact of
the changes (like ``terraform plan`` for governance policies).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aegis.core.action import Action
from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.risk import RiskLevel

# Severity ordering for determining restriction direction.
_APPROVAL_SEVERITY: dict[str, int] = {
    "auto": 0,
    "approve": 1,
    "block": 2,
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleDiff:
    """Difference record for a single policy rule."""

    rule_name: str
    change_type: str  # "added", "removed", "modified"
    old_value: dict[str, Any] | None
    new_value: dict[str, Any] | None
    fields_changed: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PolicyDiffResult:
    """Aggregate diff between two policies."""

    rules_added: list[RuleDiff]
    rules_removed: list[RuleDiff]
    rules_modified: list[RuleDiff]
    defaults_changed: dict[str, tuple[Any, Any]]  # field -> (old, new)
    impact_summary: str


@dataclass(frozen=True)
class ImpactEntry:
    """Impact of a policy change on a single recorded action."""

    action_type: str
    target: str
    old_decision: str  # "auto", "approve", "block"
    new_decision: str
    change: str  # "promoted", "restricted", "unchanged"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rule_to_dict(rule: PolicyRule) -> dict[str, Any]:
    """Serialize a PolicyRule to a comparable dictionary."""
    return {
        "match_type": rule.match_type,
        "match_target": rule.match_target,
        "match_agent": rule.match_agent,
        "risk_level": rule.risk_level.name.lower(),
        "approval": rule.approval.value,
        "conditions": rule.conditions,
    }


def _diff_fields(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """Return keys whose values differ between *old* and *new*."""
    all_keys = set(old) | set(new)
    return sorted(k for k in all_keys if old.get(k) != new.get(k))


def _classify_change(old_approval: str, new_approval: str) -> str:
    """Classify the restriction direction of a decision change."""
    old_sev = _APPROVAL_SEVERITY.get(old_approval, 0)
    new_sev = _APPROVAL_SEVERITY.get(new_approval, 0)
    if new_sev > old_sev:
        return "restricted"
    if new_sev < old_sev:
        return "promoted"
    return "unchanged"


def _build_impact_summary(result: PolicyDiffResult) -> str:
    """Build a human-readable one-line impact summary."""
    parts: list[str] = []
    n_added = len(result.rules_added)
    n_removed = len(result.rules_removed)
    n_modified = len(result.rules_modified)
    n_defaults = len(result.defaults_changed)

    if n_added:
        parts.append(f"{n_added} rule(s) added")
    if n_removed:
        parts.append(f"{n_removed} rule(s) removed")
    if n_modified:
        parts.append(f"{n_modified} rule(s) modified")
    if n_defaults:
        parts.append(f"{n_defaults} default(s) changed")

    return ", ".join(parts) if parts else "no changes"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def diff_policies(old: Policy, new: Policy) -> PolicyDiffResult:
    """Compare two policies and return a structured diff.

    Rules are compared by name. Rules with the same name in both policies
    are checked for modifications; rules present in only one side are
    classified as added or removed.
    """
    old_rules = {r.name: r for r in old.rules}
    new_rules = {r.name: r for r in new.rules}

    old_names = set(old_rules)
    new_names = set(new_rules)

    added: list[RuleDiff] = []
    for name in sorted(new_names - old_names):
        added.append(
            RuleDiff(
                rule_name=name,
                change_type="added",
                old_value=None,
                new_value=_rule_to_dict(new_rules[name]),
                fields_changed=[],
            )
        )

    removed: list[RuleDiff] = []
    for name in sorted(old_names - new_names):
        removed.append(
            RuleDiff(
                rule_name=name,
                change_type="removed",
                old_value=_rule_to_dict(old_rules[name]),
                new_value=None,
                fields_changed=[],
            )
        )

    modified: list[RuleDiff] = []
    for name in sorted(old_names & new_names):
        old_dict = _rule_to_dict(old_rules[name])
        new_dict = _rule_to_dict(new_rules[name])
        changed = _diff_fields(old_dict, new_dict)
        if changed:
            modified.append(
                RuleDiff(
                    rule_name=name,
                    change_type="modified",
                    old_value=old_dict,
                    new_value=new_dict,
                    fields_changed=changed,
                )
            )

    # Defaults comparison
    defaults_changed: dict[str, tuple[Any, Any]] = {}
    if old.default_risk_level != new.default_risk_level:
        defaults_changed["risk_level"] = (
            old.default_risk_level.name.lower(),
            new.default_risk_level.name.lower(),
        )
    if old.default_approval != new.default_approval:
        defaults_changed["approval"] = (
            old.default_approval.value,
            new.default_approval.value,
        )

    # Build partial result to compute summary
    partial = PolicyDiffResult(
        rules_added=added,
        rules_removed=removed,
        rules_modified=modified,
        defaults_changed=defaults_changed,
        impact_summary="",
    )
    summary = _build_impact_summary(partial)

    return PolicyDiffResult(
        rules_added=added,
        rules_removed=removed,
        rules_modified=modified,
        defaults_changed=defaults_changed,
        impact_summary=summary,
    )


def analyze_impact(
    old: Policy,
    new: Policy,
    actions: list[Action],
) -> list[ImpactEntry]:
    """Replay actions against both policies and classify decision changes.

    Each action is evaluated under both the old and new policy. The
    resulting approval decisions are compared to determine whether each
    action is *restricted* (stricter), *promoted* (less strict), or
    *unchanged*.
    """
    entries: list[ImpactEntry] = []
    for action in actions:
        old_decision = old.evaluate(action)
        new_decision = new.evaluate(action)
        old_approval = old_decision.approval.value
        new_approval = new_decision.approval.value
        change = _classify_change(old_approval, new_approval)
        entries.append(
            ImpactEntry(
                action_type=action.type,
                target=action.target,
                old_decision=old_approval,
                new_decision=new_approval,
                change=change,
            )
        )
    return entries
