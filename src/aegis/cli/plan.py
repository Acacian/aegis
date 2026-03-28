"""CLI command for ``aegis plan`` — preview impact of policy changes.

Like ``terraform plan`` for AI agent governance: shows what would change
if you swap one policy for another, replayed against real audit history.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aegis.cli import colors
from aegis.core.diff import (
    ImpactEntry,
    PolicyDiffResult,
    analyze_impact,
    diff_policies,
)
from aegis.core.policy import Policy
from aegis.core.replay import (
    ReplayReport,
    load_events_from_audit_db,
    load_events_from_jsonl,
)


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """Register the ``plan`` subcommand."""
    plan_parser = subparsers.add_parser(
        "plan",
        help="Preview impact of policy changes (like terraform plan)",
    )
    plan_parser.add_argument("old_policy", help="Path to the current policy YAML")
    plan_parser.add_argument("new_policy", help="Path to the proposed policy YAML")
    plan_parser.add_argument(
        "--audit-db",
        metavar="DB",
        help="SQLite audit database to replay actions from",
    )
    plan_parser.add_argument(
        "--replay",
        metavar="JSONL",
        help="JSONL file of recorded actions to replay",
    )
    plan_parser.add_argument(
        "--session",
        metavar="ID",
        help="Filter audit DB replay to a specific session",
    )
    plan_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        dest="fmt",
        help="Output format (default: table)",
    )
    plan_parser.add_argument(
        "--ci",
        action="store_true",
        default=False,
        help="CI mode: exit 1 if any actions would be newly blocked",
    )


def run(args: argparse.Namespace) -> None:
    """Execute the ``plan`` command."""
    old_path = Path(args.old_policy)
    new_path = Path(args.new_policy)

    for p in (old_path, new_path):
        if not p.exists():
            print(colors.red(f"File not found: {p}"), file=sys.stderr)
            sys.exit(1)

    try:
        old_policy = Policy.from_yaml(old_path)
    except Exception as e:
        print(colors.red(f"Failed to load current policy: {e}"), file=sys.stderr)
        sys.exit(1)

    try:
        new_policy = Policy.from_yaml(new_path)
    except Exception as e:
        print(colors.red(f"Failed to load proposed policy: {e}"), file=sys.stderr)
        sys.exit(1)

    # Phase 1: Diff rules
    diff_result = diff_policies(old_policy, new_policy)

    # Phase 2: Replay against audit history (if provided)
    replay_report: ReplayReport | None = None
    impact_entries: list[ImpactEntry] = []

    if args.audit_db:
        db_path = Path(args.audit_db)
        if not db_path.exists():
            print(colors.red(f"Audit database not found: {db_path}"), file=sys.stderr)
            sys.exit(1)
        events = load_events_from_audit_db(db_path, session_id=args.session)
        if events:
            from aegis.core.replay import ReplayEngine

            engine = ReplayEngine(old_policy)
            replay_report = engine.what_if(events, new_policy)
            # Also build impact entries for action-level detail
            actions = [e.action for e in events]
            impact_entries = analyze_impact(old_policy, new_policy, actions)
    elif args.replay:
        replay_path = Path(args.replay)
        if not replay_path.exists():
            print(colors.red(f"Replay file not found: {replay_path}"), file=sys.stderr)
            sys.exit(1)
        events = load_events_from_jsonl(replay_path)
        if events:
            from aegis.core.replay import ReplayEngine

            engine = ReplayEngine(old_policy)
            replay_report = engine.what_if(events, new_policy)
            actions = [e.action for e in events]
            impact_entries = analyze_impact(old_policy, new_policy, actions)

    if args.fmt == "json":
        _print_json(diff_result, replay_report, impact_entries)
    else:
        _print_plan(diff_result, replay_report, impact_entries, old_path.name, new_path.name)

    # CI exit code
    if args.ci:
        newly_blocked = sum(
            1 for e in impact_entries if e.new_decision == "block" and e.old_decision != "block"
        )
        if newly_blocked:
            sys.exit(1)


# ---------------------------------------------------------------------------
# Table output (terraform plan style)
# ---------------------------------------------------------------------------


def _print_plan(
    diff: PolicyDiffResult,
    replay: ReplayReport | None,
    impact: list[ImpactEntry],
    old_name: str,
    new_name: str,
) -> None:
    """Print a terraform-plan-style output."""
    print()
    print(colors.bold("Aegis Policy Plan"))
    print(colors.bold(f"  Current:  {old_name}"))
    print(colors.bold(f"  Proposed: {new_name}"))
    print()

    has_changes = (
        diff.rules_added or diff.rules_removed or diff.rules_modified or diff.defaults_changed
    )

    if not has_changes:
        print(colors.green("No changes. Your policy is up-to-date."))
        print()
        return

    # Rule changes
    print(colors.bold("Rule changes:"))
    print()

    for rd in diff.rules_added:
        nv = rd.new_value or {}
        approval = nv.get("approval", "?")
        risk = nv.get("risk_level", "?")
        match_type = nv.get("match_type", "*")
        match_target = nv.get("match_target", "*")
        pattern = f"{match_type}@{match_target}" if match_target != "*" else match_type
        print(f"  {colors.green('+  add')}    {rd.rule_name}: {pattern} → {approval} ({risk})")

    for rd in diff.rules_removed:
        ov = rd.old_value or {}
        approval = ov.get("approval", "?")
        risk = ov.get("risk_level", "?")
        match_type = ov.get("match_type", "*")
        match_target = ov.get("match_target", "*")
        pattern = f"{match_type}@{match_target}" if match_target != "*" else match_type
        print(f"  {colors.red('-  del')}    {rd.rule_name}: {pattern} → {approval} ({risk})")

    for rd in diff.rules_modified:
        changes = ", ".join(
            f"{f}: {(rd.old_value or {}).get(f)} → {(rd.new_value or {}).get(f)}"
            for f in rd.fields_changed
        )
        print(f"  {colors.yellow('~  mod')}    {rd.rule_name}: {changes}")

    if diff.defaults_changed:
        for field_name, (old_val, new_val) in sorted(diff.defaults_changed.items()):
            print(f"  {colors.yellow('~  mod')}    default {field_name}: {old_val} → {new_val}")

    print()

    # Replay impact
    if replay and replay.total_events > 0:
        print(colors.bold(f"Impact on {replay.total_events} historical action(s):"))
        print()

        if replay.changed_count == 0:
            print(f"  All {replay.total_events} actions unchanged.")
        else:
            if replay.promoted_count:
                n = replay.promoted_count
                print(f"  {colors.green(str(n))} action(s) promoted (less restrictive)")
            if replay.restricted_count:
                n = replay.restricted_count
                print(f"  {colors.yellow(str(n))} action(s) restricted (more restrictive)")
            if replay.newly_blocked:
                print(
                    f"  {colors.bright_red(str(replay.newly_blocked))} action(s) "
                    f"{colors.bright_red('NEWLY BLOCKED')}"
                )
            unchanged = replay.total_events - replay.changed_count
            if unchanged:
                print(f"  {unchanged} action(s) unchanged")

            # Show details for changed actions
            changed_results = [r for r in replay.results if r.changed]
            if changed_results:
                print()
                print(colors.bold("  Changed actions:"))
                for r in changed_results[:20]:  # Cap at 20
                    action = r.event.action
                    old_d = r.event.original_decision
                    new_d = r.new_decision
                    if r.change_type == "newly_blocked":
                        color_fn = colors.bright_red
                    elif r.change_type == "restricted":
                        color_fn = colors.yellow
                    else:
                        color_fn = colors.green
                    print(
                        f"    {color_fn('•')} {action.type}@{action.target}: "
                        f"{old_d} → {color_fn(new_d)}"
                    )
                if len(changed_results) > 20:
                    print(f"    ... and {len(changed_results) - 20} more")
        print()

    # Summary line (terraform plan style)
    added = len(diff.rules_added)
    removed = len(diff.rules_removed)
    modified = len(diff.rules_modified)
    parts: list[str] = []
    if added:
        parts.append(colors.green(f"{added} to add"))
    if modified:
        parts.append(colors.yellow(f"{modified} to change"))
    if removed:
        parts.append(colors.red(f"{removed} to remove"))

    print(colors.bold(f"Plan: {', '.join(parts)}."))

    if replay and replay.newly_blocked:
        print(
            colors.bright_red(
                f"\nWARNING: {replay.newly_blocked} previously-allowed action(s) "
                f"will be BLOCKED by this change."
            )
        )
    print()


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


def _print_json(
    diff: PolicyDiffResult,
    replay: ReplayReport | None,
    impact: list[ImpactEntry],
) -> None:
    """Print plan as JSON."""
    data: dict[str, object] = {
        "rules_added": [
            {
                "rule_name": r.rule_name,
                "new_value": r.new_value,
            }
            for r in diff.rules_added
        ],
        "rules_removed": [
            {
                "rule_name": r.rule_name,
                "old_value": r.old_value,
            }
            for r in diff.rules_removed
        ],
        "rules_modified": [
            {
                "rule_name": r.rule_name,
                "fields_changed": r.fields_changed,
                "old_value": r.old_value,
                "new_value": r.new_value,
            }
            for r in diff.rules_modified
        ],
        "defaults_changed": {
            k: {"old": v[0], "new": v[1]} for k, v in diff.defaults_changed.items()
        },
        "summary": diff.impact_summary,
    }

    if replay:
        data["replay"] = {
            "total_events": replay.total_events,
            "changed": replay.changed_count,
            "unchanged": replay.unchanged_count,
            "promoted": replay.promoted_count,
            "restricted": replay.restricted_count,
            "newly_blocked": replay.newly_blocked,
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
