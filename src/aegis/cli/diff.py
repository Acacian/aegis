"""CLI command for ``aegis diff`` — policy diff and impact analysis."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from aegis.cli import colors
from aegis.core.action import Action
from aegis.core.diff import (
    ImpactEntry,
    PolicyDiffResult,
    RuleDiff,
    analyze_impact,
    diff_policies,
)
from aegis.core.policy import Policy


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """Register the ``diff`` subcommand."""
    diff_parser = subparsers.add_parser(
        "diff",
        help="Compare two policy files and show impact analysis",
    )
    diff_parser.add_argument("old_policy", help="Path to the old (baseline) policy YAML")
    diff_parser.add_argument("new_policy", help="Path to the new policy YAML")
    diff_parser.add_argument(
        "--replay",
        metavar="ACTIONS_FILE",
        help="JSONL file of recorded actions to replay for impact analysis",
    )
    diff_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        dest="fmt",
        help="Output format (default: table)",
    )


def run(args: argparse.Namespace) -> None:
    """Execute the ``diff`` command."""
    old_path = Path(args.old_policy)
    new_path = Path(args.new_policy)

    for p in (old_path, new_path):
        if not p.exists():
            print(colors.red(f"File not found: {p}"), file=sys.stderr)
            sys.exit(1)

    try:
        old_policy = Policy.from_yaml(old_path)
    except Exception as e:
        print(colors.red(f"Failed to load old policy: {e}"), file=sys.stderr)
        sys.exit(1)

    try:
        new_policy = Policy.from_yaml(new_path)
    except Exception as e:
        print(colors.red(f"Failed to load new policy: {e}"), file=sys.stderr)
        sys.exit(1)

    diff_result = diff_policies(old_policy, new_policy)

    # Optional replay
    impact_entries: list[ImpactEntry] = []
    if args.replay:
        replay_path = Path(args.replay)
        if not replay_path.exists():
            print(colors.red(f"Replay file not found: {replay_path}"), file=sys.stderr)
            sys.exit(1)
        actions = _load_actions(replay_path)
        impact_entries = analyze_impact(old_policy, new_policy, actions)

    if args.fmt == "json":
        _print_json(diff_result, impact_entries)
    else:
        _print_table(diff_result, impact_entries, old_path.name, new_path.name)


# ---------------------------------------------------------------------------
# Action loading
# ---------------------------------------------------------------------------


def _load_actions(path: Path) -> list[Action]:
    """Load actions from a JSONL file.

    Each line must be a JSON object with at least ``type`` and ``target``
    keys.  Optional keys: ``params``, ``description``, ``agent_id``.
    """
    actions: list[Action] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            actions.append(
                Action(
                    type=data.get("type", "unknown"),
                    target=data.get("target", "unknown"),
                    params=data.get("params", {}),
                    description=data.get("description", ""),
                    agent_id=data.get("agent_id", ""),
                )
            )
    return actions


# ---------------------------------------------------------------------------
# Table output
# ---------------------------------------------------------------------------


def _print_table(
    diff: PolicyDiffResult,
    impact: list[ImpactEntry],
    old_name: str,
    new_name: str,
) -> None:
    """Print a human-readable diff report."""
    header = f"Policy Diff: {old_name} -> {new_name}"
    print(colors.bold(header))
    print("=" * len(header))
    print()

    # Defaults
    if diff.defaults_changed:
        print(colors.bold("Defaults changed:"))
        for field_name, (old_val, new_val) in sorted(diff.defaults_changed.items()):
            print(f"  {field_name}: {old_val} -> {new_val}")
        print()

    # Added rules
    if diff.rules_added:
        print(colors.bold(f"Rules added (+{len(diff.rules_added)}):"))
        for rd in diff.rules_added:
            nv = rd.new_value or {}
            approval = nv.get("approval", "?").upper()
            risk = nv.get("risk_level", "?")
            match_type = nv.get("match_type", "*")
            match_target = nv.get("match_target", "*")
            pattern = f"{match_type}@{match_target}" if match_target != "*" else match_type
            print(f"  {colors.green('+')} {rd.rule_name}: {pattern} -> {approval} ({risk})")
        print()

    # Removed rules
    if diff.rules_removed:
        print(colors.bold(f"Rules removed (-{len(diff.rules_removed)}):"))
        for rd in diff.rules_removed:
            ov = rd.old_value or {}
            approval = ov.get("approval", "?").upper()
            risk = ov.get("risk_level", "?")
            match_type = ov.get("match_type", "*")
            match_target = ov.get("match_target", "*")
            pattern = f"{match_type}@{match_target}" if match_target != "*" else match_type
            print(f"  {colors.red('-')} {rd.rule_name}: {pattern} -> {approval} ({risk})")
        print()

    # Modified rules
    if diff.rules_modified:
        print(colors.bold(f"Rules modified ({len(diff.rules_modified)}):"))
        for rd in diff.rules_modified:
            changes = ", ".join(
                f"{f}: {(rd.old_value or {}).get(f)} -> {(rd.new_value or {}).get(f)}"
                for f in rd.fields_changed
            )
            print(f"  {colors.yellow('~')} {rd.rule_name}: {changes}")
        print()

    # Summary
    if diff.impact_summary:
        print(f"Summary: {diff.impact_summary}")

    has_changes = (
        diff.rules_added or diff.rules_removed or diff.rules_modified or diff.defaults_changed
    )
    if not has_changes:
        print("No changes detected.")

    # Impact replay
    if impact:
        _print_impact_table(impact)


def _print_impact_table(entries: list[ImpactEntry]) -> None:
    """Print the impact analysis section."""
    total = len(entries)
    print()
    print(colors.bold(f"Impact on {total} recorded actions:"))

    # Group by transition
    transitions: Counter[tuple[str, str]] = Counter()
    for e in entries:
        transitions[(e.old_decision, e.new_decision)] += 1

    unchanged = transitions.pop(("auto", "auto"), 0)
    unchanged += transitions.pop(("approve", "approve"), 0)
    unchanged += transitions.pop(("block", "block"), 0)

    restricted_count = 0
    promoted_count = 0

    for (old_d, new_d), count in sorted(transitions.items()):
        arrow = f"{old_d} -> {new_d}"
        label = _transition_label(old_d, new_d)
        if _is_restriction(old_d, new_d):
            restricted_count += count
            print(f"  {colors.red(str(count)):>6} actions: {arrow} ({label})")
        else:
            promoted_count += count
            print(f"  {colors.green(str(count)):>6} actions: {arrow} ({label})")

    if unchanged:
        print(f"  {str(unchanged):>6} actions: unchanged")

    # Warning for blocked actions
    newly_blocked = sum(
        1 for e in entries if e.new_decision == "block" and e.old_decision != "block"
    )
    if newly_blocked:
        print()
        print(
            colors.bright_red(
                f"WARNING: {newly_blocked} previously-allowed action(s) will be BLOCKED"
            )
        )


def _transition_label(old: str, new: str) -> str:
    """Human-readable label for a decision transition."""
    if new == "block":
        return "will be BLOCKED"
    if new == "approve" and old == "auto":
        return "will now need human approval"
    if new == "auto" and old in ("approve", "block"):
        return "simplified"
    if new == "approve" and old == "block":
        return "unblocked, needs approval"
    return "changed"


def _is_restriction(old: str, new: str) -> bool:
    """Return True if the transition makes things stricter."""
    severity = {"auto": 0, "approve": 1, "block": 2}
    return severity.get(new, 0) > severity.get(old, 0)


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


def _print_json(diff: PolicyDiffResult, impact: list[ImpactEntry]) -> None:
    """Print diff and impact as JSON."""

    def _rule_diff_dict(rd: RuleDiff) -> dict[str, object]:
        return {
            "rule_name": rd.rule_name,
            "change_type": rd.change_type,
            "old_value": rd.old_value,
            "new_value": rd.new_value,
            "fields_changed": rd.fields_changed,
        }

    data: dict[str, object] = {
        "rules_added": [_rule_diff_dict(r) for r in diff.rules_added],
        "rules_removed": [_rule_diff_dict(r) for r in diff.rules_removed],
        "rules_modified": [_rule_diff_dict(r) for r in diff.rules_modified],
        "defaults_changed": {
            k: {"old": v[0], "new": v[1]} for k, v in diff.defaults_changed.items()
        },
        "impact_summary": diff.impact_summary,
    }

    if impact:
        data["impact"] = [
            {
                "action_type": e.action_type,
                "target": e.target,
                "old_decision": e.old_decision,
                "new_decision": e.new_decision,
                "change": e.change,
            }
            for e in impact
        ]

    print(json.dumps(data, indent=2))
