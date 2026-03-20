"""Aegis CLI entry point."""

from __future__ import annotations

import argparse
import json
import sys

from aegis.runtime.audit import AuditLogger


def main(argv: list[str] | None = None) -> None:
    """CLI entry point for ``aegis`` command."""
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis: Policy & approval runtime for AI agents",
    )
    parser.add_argument("--version", action="store_true", help="Show version")
    subparsers = parser.add_subparsers(dest="command")

    # aegis audit
    audit_parser = subparsers.add_parser("audit", help="View the audit log")
    audit_parser.add_argument("--db", default="aegis_audit.db", help="Database path")
    audit_parser.add_argument("--session", help="Filter by session ID")
    audit_parser.add_argument(
        "--format", choices=["table", "json"], default="table", dest="fmt"
    )

    # aegis validate
    validate_parser = subparsers.add_parser("validate", help="Validate a policy file")
    validate_parser.add_argument("policy_file", help="Path to policy YAML file")

    args = parser.parse_args(argv)

    if args.version:
        from aegis import __version__

        print(f"aegis {__version__}")
        return

    if args.command == "audit":
        _cmd_audit(args)
    elif args.command == "validate":
        _cmd_validate(args)
    else:
        parser.print_help()


def _cmd_audit(args: argparse.Namespace) -> None:
    """Display audit log entries."""
    logger = AuditLogger(db_path=args.db)
    entries = logger.get_log(session_id=args.session)
    logger.close()

    if not entries:
        print("No audit entries found.")
        return

    if args.fmt == "json":
        print(json.dumps(entries, indent=2))
        return

    # Table format
    header = f"{'ID':>4} {'Session':>12} {'Action':>15} {'Target':>15} {'Risk':>8} {'Decision':>10} {'Result':>10}"
    print(header)
    print("-" * len(header))
    for e in entries:
        print(
            f"{e['id']:>4} {e['session_id']:>12} {e['action_type']:>15} "
            f"{e['action_target']:>15} {e['risk_level']:>8} "
            f"{(e.get('human_decision') or e['approval']):>10} "
            f"{(e.get('result_status') or '-'):>10}"
        )


def _cmd_validate(args: argparse.Namespace) -> None:
    """Validate a policy YAML file."""
    from aegis.core.policy import Policy

    try:
        policy = Policy.from_yaml(args.policy_file)
        print(f"Policy valid: {len(policy.rules)} rule(s) loaded.")
        for rule in policy.rules:
            print(
                f"  - {rule.name}: {rule.match_type}@{rule.match_target} "
                f"-> {rule.risk_level.name}/{rule.approval.value}"
            )
    except Exception as e:
        print(f"Policy validation failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
