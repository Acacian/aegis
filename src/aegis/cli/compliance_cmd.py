"""CLI command for ``aegis compliance`` — compliance evidence auto-generation.

Generates regulatory compliance reports from audit data for EU AI Act,
SOC2, NIST AI RMF, and ISO 42001.

Usage::

    aegis compliance report --framework eu-ai-act --period 2026-Q1
    aegis compliance report --framework soc2 --from 2026-01-01 --to 2026-03-31
    aegis compliance status
"""

from __future__ import annotations

import argparse
import contextlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

from aegis.cli import colors


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """Register the ``compliance-report`` subcommand group."""
    comp_parser = subparsers.add_parser(
        "compliance-report",
        help="Generate compliance evidence reports (EU AI Act, SOC2, NIST, ISO 42001)",
    )
    comp_sub = comp_parser.add_subparsers(dest="compliance_action")

    # --- aegis compliance-report report ---
    report_parser = comp_sub.add_parser(
        "report",
        help="Generate a compliance evidence report for a specific framework",
    )
    report_parser.add_argument(
        "--framework",
        required=True,
        choices=["eu-ai-act", "soc2", "nist", "iso42001"],
        help="Regulatory framework to generate the report for",
    )
    report_parser.add_argument(
        "--period",
        default=None,
        help="Shorthand period (e.g. 2026-Q1, 2026-Q2)",
    )
    report_parser.add_argument(
        "--from",
        dest="from_date",
        default=None,
        help="Start date (YYYY-MM-DD)",
    )
    report_parser.add_argument(
        "--to",
        dest="to_date",
        default=None,
        help="End date (YYYY-MM-DD)",
    )
    report_parser.add_argument(
        "--db",
        default="aegis_audit.db",
        help="Audit database path (default: aegis_audit.db)",
    )
    report_parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Output file path (default: stdout)",
    )
    report_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="json",
        dest="fmt",
        help="Output format (default: json)",
    )
    report_parser.add_argument(
        "--granularity",
        choices=["daily", "weekly"],
        default="daily",
        help="Time-series granularity (default: daily)",
    )

    # --- aegis compliance-report status ---
    status_parser = comp_sub.add_parser(
        "status",
        help="Quick check: which frameworks have sufficient evidence",
    )
    status_parser.add_argument(
        "--db",
        default="aegis_audit.db",
        help="Audit database path (default: aegis_audit.db)",
    )
    status_parser.add_argument(
        "--format",
        choices=["json", "table"],
        default="table",
        dest="fmt",
        help="Output format (default: table)",
    )


def _parse_quarter(quarter_str: str) -> tuple[datetime, datetime]:
    """Parse a quarter string like ``2026-Q1`` into start/end datetimes."""
    match = re.match(r"^(\d{4})-Q([1-4])$", quarter_str, re.IGNORECASE)
    if not match:
        print(
            f"Invalid period format: {quarter_str!r}. Use YYYY-Q[1-4] (e.g. 2026-Q1).",
            file=sys.stderr,
        )
        sys.exit(1)

    year = int(match.group(1))
    quarter = int(match.group(2))

    quarter_starts = {1: 1, 2: 4, 3: 7, 4: 10}
    quarter_ends = {1: (3, 31), 2: (6, 30), 3: (9, 30), 4: (12, 31)}

    start_month = quarter_starts[quarter]
    end_month, end_day = quarter_ends[quarter]

    return (
        datetime(year, start_month, 1, tzinfo=UTC),
        datetime(year, end_month, end_day, 23, 59, 59, tzinfo=UTC),
    )


def _parse_date(date_str: str) -> datetime:
    """Parse a YYYY-MM-DD date string."""
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError:
        print(
            f"Invalid date format: {date_str!r}. Use YYYY-MM-DD.",
            file=sys.stderr,
        )
        sys.exit(1)


def run(args: argparse.Namespace) -> None:
    """Execute the compliance-report command."""
    action = getattr(args, "compliance_action", None)
    if action == "report":
        _cmd_report(args)
    elif action == "status":
        _cmd_status(args)
    else:
        print("Usage: aegis compliance-report {report,status}", file=sys.stderr)
        print("  report  — Generate a compliance evidence report", file=sys.stderr)
        print("  status  — Quick framework evidence status check", file=sys.stderr)
        sys.exit(1)


def _cmd_report(args: argparse.Namespace) -> None:
    """Generate a compliance evidence report."""
    from aegis.core.compliance_report import ComplianceReportGenerator

    # Resolve period
    if args.period:
        period_start, period_end = _parse_quarter(args.period)
    elif args.from_date and args.to_date:
        period_start = _parse_date(args.from_date)
        period_end = _parse_date(args.to_date).replace(hour=23, minute=59, second=59)
    else:
        print(
            "Specify --period (e.g. 2026-Q1) or both --from and --to dates.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Load audit data
    db_path = Path(args.db)
    if db_path.exists():
        from aegis.runtime.audit import AuditLogger

        logger = AuditLogger(db_path=db_path)
        gen = ComplianceReportGenerator(audit_logger=logger)
    else:
        print(
            f"Warning: Database {db_path} not found. Generating report with empty data.",
            file=sys.stderr,
        )
        gen = ComplianceReportGenerator(audit_entries=[])

    # Generate the report
    framework_map = {
        "eu-ai-act": gen.generate_eu_ai_act_report,
        "soc2": gen.generate_soc2_report,
        "nist": gen.generate_nist_report,
        "iso42001": gen.generate_iso42001_report,
    }
    generator_fn = framework_map[args.framework]
    report = generator_fn(period_start, period_end, granularity=args.granularity)

    # Format output
    if args.fmt == "json":
        output_text = json.dumps(report.to_dict(), indent=2, default=str)
    else:
        from aegis.core.compliance_report import ComplianceReportGenerator as CRG

        output_text = CRG.to_text(report)

    # Write or print
    output_path = getattr(args, "output", None)
    if output_path:
        Path(output_path).write_text(output_text, encoding="utf-8")
        print(f"Report written to {output_path}")
    else:
        print(output_text)

    # Close logger if opened
    if db_path.exists():
        with contextlib.suppress(Exception):
            logger.close()  # noqa: F821


def _cmd_status(args: argparse.Namespace) -> None:
    """Show quick framework evidence status."""
    from aegis.core.compliance_report import ComplianceReportGenerator

    db_path = Path(args.db)
    if db_path.exists():
        from aegis.runtime.audit import AuditLogger

        logger = AuditLogger(db_path=db_path)
        gen = ComplianceReportGenerator(audit_logger=logger)
    else:
        gen = ComplianceReportGenerator(audit_entries=[])

    status = gen.check_status()

    if args.fmt == "json":
        print(json.dumps(status, indent=2))
    else:
        print(colors.bold("=== Compliance Framework Status ==="))
        print()
        for fw_name, info in status.items():
            score = info["coverage_score"]
            if score >= 80:
                score_str = colors.green(f"{score:.1f}%")
            elif score >= 50:
                score_str = colors.yellow(f"{score:.1f}%")
            else:
                score_str = colors.red(f"{score:.1f}%")

            gap_warning = ""
            if info["has_mandatory_gaps"]:
                gap_warning = colors.red(" [MANDATORY GAPS]")

            print(f"  {fw_name}")
            print(f"    Coverage: {score_str}{gap_warning}")
            print(
                f"    Requirements: {info['total_requirements']} total, "
                f"{colors.green(str(info['fully_covered']))} full, "
                f"{colors.yellow(str(info['partially_covered']))} partial, "
                f"{colors.red(str(info['gaps']))} gaps"
            )
            print()

    if db_path.exists():
        with contextlib.suppress(Exception):
            logger.close()  # noqa: F821
