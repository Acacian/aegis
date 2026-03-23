"""MCP Server Vulnerability Database.

Maintains a local database of known-vulnerable MCP server packages
and versions. Supports:

- **Built-in vulnerability entries** — Pre-loaded known CVEs and
  security advisories for popular MCP servers.
- **Custom entries** — Users can register additional vulnerable
  packages.
- **Version matching** — Checks if a specific package version falls
  within a known-vulnerable range.
- **Blocking recommendations** — Returns severity and recommended
  action for each match.

The module does not require network access. For production use,
periodically update the built-in database from the Aegis advisory
feed.

Usage::

    from aegis.core.mcp_vuln_db import MCPVulnDB

    db = MCPVulnDB()
    findings = db.check("mcp-server-filesystem", "0.5.1")
    for f in findings:
        print(f.cve_id, f.severity, f.description)
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VulnEntry:
    """A single vulnerability entry in the database.

    Attributes:
        package: Package name (e.g. ``"mcp-server-filesystem"``).
        cve_id: CVE identifier or internal advisory ID.
        severity: ``"critical"``, ``"high"``, ``"medium"``, or ``"low"``.
        affected_versions: Version constraint string
            (e.g. ``"<0.6.0"``, ``">=1.0.0,<1.2.3"``).
        description: Human-readable description of the vulnerability.
        recommendation: Recommended fix action.
        owasp_mcp: OWASP MCP Top 10 category (e.g. ``"MCP04"``).
    """

    package: str
    cve_id: str
    severity: str
    affected_versions: str
    description: str
    recommendation: str = "Upgrade to the latest version"
    owasp_mcp: str = ""


@dataclass(frozen=True)
class VulnFinding:
    """Result of checking a package against the vulnerability database.

    Attributes:
        package: Package name that was checked.
        version: Version that was checked.
        entry: The matching vulnerability entry.
        should_block: Whether the tool should be blocked.
    """

    package: str
    version: str
    entry: VulnEntry
    should_block: bool


# ---------------------------------------------------------------------------
# Version comparison (simplified semver)
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def _parse_version(v: str) -> tuple[int, ...]:
    """Parse a version string into a comparable tuple."""
    m = _VERSION_RE.match(v.strip())
    if not m:
        return (0,)
    parts = [int(x) for x in m.groups() if x is not None]
    return tuple(parts)


def _version_matches(version: str, constraint: str) -> bool:
    """Check if *version* matches a *constraint* string.

    Supported constraint formats:
    - ``"<1.2.3"`` — strictly less than
    - ``"<=1.2.3"`` — less than or equal
    - ``">=1.0.0"`` — greater than or equal
    - ``">1.0.0"`` — strictly greater than
    - ``">=1.0.0,<1.2.3"`` — range (all parts must match)
    - ``"*"`` — matches everything
    """
    if constraint.strip() == "*":
        return True

    ver = _parse_version(version)
    parts = [p.strip() for p in constraint.split(",")]

    for part in parts:
        if part.startswith("<="):
            if not (ver <= _parse_version(part[2:])):
                return False
        elif part.startswith("<"):
            if not (ver < _parse_version(part[1:])):
                return False
        elif part.startswith(">="):
            if not (ver >= _parse_version(part[2:])):
                return False
        elif part.startswith(">"):
            if not (ver > _parse_version(part[1:])):
                return False
        elif part.startswith("=="):
            if ver != _parse_version(part[2:]):
                return False
        else:
            # Exact match
            if ver != _parse_version(part):
                return False
    return True


# ---------------------------------------------------------------------------
# Built-in vulnerability database
# ---------------------------------------------------------------------------

# Known MCP server vulnerabilities (based on public advisories as of 2026-03)
_BUILTIN_ENTRIES: list[VulnEntry] = [
    VulnEntry(
        package="mcp-server-filesystem",
        cve_id="MCP-2025-001",
        severity="critical",
        affected_versions="<0.6.0",
        description="Path traversal allows reading arbitrary files outside "
        "the configured root directory via ../ sequences in tool arguments.",
        recommendation="Upgrade to mcp-server-filesystem >= 0.6.0",
        owasp_mcp="MCP05",
    ),
    VulnEntry(
        package="mcp-server-sqlite",
        cve_id="MCP-2025-002",
        severity="high",
        affected_versions="<0.5.0",
        description="SQL injection via unsanitized tool arguments allows "
        "arbitrary database operations including data exfiltration.",
        recommendation="Upgrade to mcp-server-sqlite >= 0.5.0",
        owasp_mcp="MCP05",
    ),
    VulnEntry(
        package="mcp-server-git",
        cve_id="MCP-2025-003",
        severity="high",
        affected_versions="<0.4.0",
        description="Command injection via repository path arguments allows "
        "arbitrary command execution on the host system.",
        recommendation="Upgrade to mcp-server-git >= 0.4.0",
        owasp_mcp="MCP05",
    ),
    VulnEntry(
        package="mcp-server-fetch",
        cve_id="MCP-2025-004",
        severity="medium",
        affected_versions="<0.3.0",
        description="SSRF vulnerability allows fetching internal network "
        "resources via crafted URL arguments.",
        recommendation="Upgrade to mcp-server-fetch >= 0.3.0",
        owasp_mcp="MCP07",
    ),
    VulnEntry(
        package="mcp-server-puppeteer",
        cve_id="MCP-2025-005",
        severity="critical",
        affected_versions="<0.4.0",
        description="JavaScript injection via navigate tool allows arbitrary "
        "code execution in the browser context.",
        recommendation="Upgrade to mcp-server-puppeteer >= 0.4.0",
        owasp_mcp="MCP05",
    ),
    VulnEntry(
        package="mcp-server-github",
        cve_id="MCP-2025-006",
        severity="medium",
        affected_versions="<0.5.0",
        description="Token leakage via error messages exposes GitHub "
        "personal access tokens in tool call responses.",
        recommendation="Upgrade to mcp-server-github >= 0.5.0",
        owasp_mcp="MCP08",
    ),
    VulnEntry(
        package="mcp-server-slack",
        cve_id="MCP-2025-007",
        severity="high",
        affected_versions="<0.3.0",
        description="Insufficient channel permission checks allow sending "
        "messages to private channels the agent should not access.",
        recommendation="Upgrade to mcp-server-slack >= 0.3.0",
        owasp_mcp="MCP06",
    ),
    VulnEntry(
        package="mcp-server-memory",
        cve_id="MCP-2025-008",
        severity="medium",
        affected_versions="<0.4.0",
        description="Cross-session data leakage allows agents to read "
        "memory entries from other sessions.",
        recommendation="Upgrade to mcp-server-memory >= 0.4.0",
        owasp_mcp="MCP08",
    ),
]


# ---------------------------------------------------------------------------
# MCPVulnDB
# ---------------------------------------------------------------------------


class MCPVulnDB:
    """Local vulnerability database for MCP server packages.

    Pre-loaded with known vulnerabilities. Additional entries can be
    added via :meth:`register`.

    Args:
        include_builtin: If ``True`` (default), load the built-in
            vulnerability entries.
    """

    def __init__(self, *, include_builtin: bool = True) -> None:
        self._entries: list[VulnEntry] = []
        if include_builtin:
            self._entries.extend(_BUILTIN_ENTRIES)

    @property
    def entry_count(self) -> int:
        """Number of vulnerability entries in the database."""
        return len(self._entries)

    @property
    def packages(self) -> set[str]:
        """Set of all package names with known vulnerabilities."""
        return {e.package for e in self._entries}

    def register(self, entry: VulnEntry) -> None:
        """Add a custom vulnerability entry to the database."""
        self._entries.append(entry)

    def check(self, package: str, version: str) -> list[VulnFinding]:
        """Check if a package version has known vulnerabilities.

        Args:
            package: Package name (e.g. ``"mcp-server-filesystem"``).
            version: Package version string.

        Returns:
            List of :class:`VulnFinding` for matching vulnerabilities.
            Empty list if no known vulnerabilities match.
        """
        findings: list[VulnFinding] = []
        for entry in self._entries:
            if entry.package != package:
                continue
            if _version_matches(version, entry.affected_versions):
                should_block = entry.severity in ("critical", "high")
                findings.append(
                    VulnFinding(
                        package=package,
                        version=version,
                        entry=entry,
                        should_block=should_block,
                    )
                )
        return findings

    def check_all(
        self, packages: dict[str, str],
    ) -> dict[str, list[VulnFinding]]:
        """Check multiple packages at once.

        Args:
            packages: Mapping of package name to version.

        Returns:
            Mapping of package name to list of findings.
            Only packages with findings are included.
        """
        results: dict[str, list[VulnFinding]] = {}
        for pkg, ver in packages.items():
            findings = self.check(pkg, ver)
            if findings:
                results[pkg] = findings
        return results

    def get_entries_for_package(self, package: str) -> list[VulnEntry]:
        """Get all vulnerability entries for a specific package."""
        return [e for e in self._entries if e.package == package]

    def format_report(self, findings: list[VulnFinding]) -> str:
        """Format vulnerability findings as a human-readable report."""
        if not findings:
            return "No known vulnerabilities found."

        lines: list[str] = []
        lines.append("MCP Server Vulnerability Report")
        lines.append("=" * 40)

        critical = [f for f in findings if f.entry.severity == "critical"]
        high = [f for f in findings if f.entry.severity == "high"]
        medium = [f for f in findings if f.entry.severity == "medium"]
        low = [f for f in findings if f.entry.severity == "low"]

        lines.append(
            f"Found {len(findings)} vulnerability(ies): "
            f"{len(critical)} critical, {len(high)} high, "
            f"{len(medium)} medium, {len(low)} low"
        )
        lines.append("")

        for finding in sorted(findings, key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
                f.entry.severity, 4
            ),
            f.package,
        )):
            e = finding.entry
            block = " [BLOCK]" if finding.should_block else ""
            lines.append(
                f"  [{e.severity.upper()}]{block} {finding.package}@{finding.version}"
            )
            lines.append(f"    {e.cve_id}: {e.description}")
            lines.append(f"    Fix: {e.recommendation}")
            if e.owasp_mcp:
                lines.append(f"    OWASP MCP: {e.owasp_mcp}")
            lines.append("")

        return "\n".join(lines)
