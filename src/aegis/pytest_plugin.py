"""pytest-aegis: detect ungoverned AI calls during testing.

Automatically scans your project for ungoverned AI agent calls
as part of the pytest session. Fails if the governance score
falls below the configured threshold.

Usage::

    pip install agent-aegis
    pytest --aegis-scan          # enable scan
    pytest --aegis-scan --aegis-threshold C  # fail below C grade

Or always-on in pytest.ini / pyproject.toml::

    [tool.pytest.ini_options]
    addopts = "--aegis-scan"
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    pass


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register aegis command-line options."""
    group = parser.getgroup("aegis", "Aegis AI agent security scanning")
    group.addoption(
        "--aegis-scan",
        action="store_true",
        default=False,
        help="Run aegis scan to detect ungoverned AI calls",
    )
    group.addoption(
        "--aegis-threshold",
        default="F",
        help="Minimum governance grade to pass (A/B/C/D/F, default: F)",
    )
    group.addoption(
        "--aegis-scan-dir",
        default=".",
        help="Directory to scan (default: current directory)",
    )


def pytest_collection_finish(session: pytest.Session) -> None:
    """Run aegis scan after test collection, before execution."""
    config = session.config
    if not config.getoption("aegis_scan", default=False):
        return

    threshold = config.getoption("aegis_threshold", default="F")
    scan_dir = config.getoption("aegis_scan_dir", default=".")

    from aegis.cli.scan import scan_directory

    scan_path = Path(scan_dir).resolve()
    if not scan_path.exists():
        return

    _file_count, findings = scan_directory(str(scan_path))

    if not findings:
        session.config.stash.setdefault(_aegis_key, {})["passed"] = True
        return

    # Compute grade
    count = len(findings)
    if count == 0:
        grade = "A"
    elif count <= 2:
        grade = "B"
    elif count <= 5:
        grade = "C"
    elif count <= 10:
        grade = "D"
    else:
        grade = "F"

    grade_order = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}
    threshold_rank = grade_order.get(threshold.upper(), 4)
    actual_rank = grade_order.get(grade, 4)

    if actual_rank > threshold_rank:
        lines = [f"Aegis scan: grade {grade} (found {count} ungoverned call(s))"]
        for f in findings[:10]:
            lines.append(f"  {f.file}:{f.line}  {f.category}  {f.detail}")
        if count > 10:
            lines.append(f"  ... and {count - 10} more")
        lines.append(f"Threshold: {threshold.upper()}, actual: {grade}")
        pytest.fail("\n".join(lines), pytrace=False)


_aegis_key = pytest.StashKey[dict[str, object]]()


def pytest_report_header(config: pytest.Config) -> list[str]:
    """Show aegis status in pytest header."""
    if config.getoption("aegis_scan", default=False):
        threshold = config.getoption("aegis_threshold", default="F")
        return [f"aegis: scan enabled (threshold={threshold})"]
    return []
