"""MCP Security Report Generator.

Generates comprehensive security reports for MCP server deployments by
aggregating findings from multiple security components:

- **ToolDescriptionScanner** — Detects tool poisoning patterns.
- **RugPullDetector** — Hash-based change detection.
- **ArgumentSanitizer** — Path traversal and injection checks.
- **MCPVulnDB** — Known vulnerability matching.
- **SBOMGenerator** — Software bill of materials.

The report includes per-server security profiles, a grading system
(A through F), and prioritized recommendations.

Output formats: dict, JSON, plain text, and standalone HTML.

Usage::

    from aegis.core.mcp_security_report import MCPSecurityReportGenerator

    gen = MCPSecurityReportGenerator()
    report = gen.generate({
        "filesystem": [
            {"name": "read_file", "description": "Read a file", "inputSchema": {}},
        ],
    })
    print(report.to_text())
"""

from __future__ import annotations

import html
import json
import time
from dataclasses import dataclass, field
from typing import Any

from aegis.core.mcp_sbom import SBOM, MCPServerInfo, MCPToolInfo, SBOMGenerator
from aegis.core.mcp_security import (
    MCPFinding,
    MCPSecurityGate,
    Severity,
    TrustLevel,
    TrustScore,
)
from aegis.core.mcp_vuln_db import MCPVulnDB, VulnFinding

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ServerSecurityProfile:
    """Security profile for a single MCP server.

    Attributes:
        server_name: Name of the MCP server.
        tool_count: Number of tools exposed by the server.
        trust_scores: Mapping of tool name to its trust score.
        findings: Tool description scan findings.
        vuln_findings: Vulnerability database findings.
        shadow_findings: Shadow tool conflict findings (reserved).
        escalation_rules_applicable: Names of applicable escalation rules.
        overall_risk: Aggregate risk level for this server.
    """

    server_name: str
    tool_count: int
    trust_scores: dict[str, TrustScore] = field(default_factory=dict)
    findings: list[MCPFinding] = field(default_factory=list)
    vuln_findings: list[VulnFinding] = field(default_factory=list)
    shadow_findings: list[dict[str, Any]] = field(default_factory=list)
    escalation_rules_applicable: list[str] = field(default_factory=list)
    overall_risk: str = "low"


@dataclass
class MCPSecurityReport:
    """Comprehensive security report for an MCP deployment.

    Attributes:
        generated_at: ISO 8601 timestamp.
        servers: Per-server security profiles.
        total_tools: Total tools across all servers.
        total_findings: Total security findings.
        critical_count: Number of critical findings.
        high_count: Number of high findings.
        medium_count: Number of medium findings.
        low_count: Number of low findings.
        shadow_conflicts: Shadow tool conflict findings (reserved).
        escalation_risks: Applicable escalation rules (reserved).
        sbom: Software Bill of Materials, if generated.
        overall_grade: Letter grade A through F.
        recommendations: Prioritized recommendation strings.
    """

    generated_at: str = ""
    servers: list[ServerSecurityProfile] = field(default_factory=list)
    total_tools: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    shadow_conflicts: list[dict[str, Any]] = field(default_factory=list)
    escalation_risks: list[str] = field(default_factory=list)
    sbom: SBOM | None = None
    overall_grade: str = "A"
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "generatedAt": self.generated_at,
            "overallGrade": self.overall_grade,
            "summary": {
                "totalServers": len(self.servers),
                "totalTools": self.total_tools,
                "totalFindings": self.total_findings,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "servers": [
                {
                    "name": s.server_name,
                    "toolCount": s.tool_count,
                    "overallRisk": s.overall_risk,
                    "trustScores": {
                        name: {
                            "level": ts.level.name,
                            "score": ts.score,
                            "pinned": ts.pinned,
                        }
                        for name, ts in s.trust_scores.items()
                    },
                    "findings": [
                        {
                            "category": f.category,
                            "severity": f.severity,
                            "patternName": f.pattern_name,
                            "detail": f.detail,
                            "toolName": f.tool_name,
                        }
                        for f in s.findings
                    ],
                    "vulnFindings": [
                        {
                            "package": vf.package,
                            "version": vf.version,
                            "cveId": vf.entry.cve_id,
                            "severity": vf.entry.severity,
                            "shouldBlock": vf.should_block,
                        }
                        for vf in s.vuln_findings
                    ],
                }
                for s in self.servers
            ],
            "recommendations": self.recommendations,
            "sbom": self.sbom.to_dict() if self.sbom else None,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_text(self) -> str:
        """Generate a human-readable plain text report."""
        lines: list[str] = []
        lines.append("\u2550\u2550\u2550 MCP Security Report \u2550\u2550\u2550")
        lines.append(f"Generated: {self.generated_at}")
        lines.append(f"Grade: {self.overall_grade}")
        lines.append("")
        lines.append(
            f"Summary: {len(self.servers)} servers, "
            f"{self.total_tools} tools, "
            f"{self.total_findings} findings "
            f"({self.critical_count} critical, {self.high_count} high, "
            f"{self.medium_count} medium, {self.low_count} low)"
        )

        for server in self.servers:
            lines.append("")
            lines.append(f"\u2500\u2500\u2500 Server: {server.server_name} \u2500\u2500\u2500")
            # Determine representative trust level
            trust_label = _server_trust_label(server)
            lines.append(
                f"Tools: {server.tool_count} | Risk: {server.overall_risk} | Trust: {trust_label}"
            )
            for finding in server.findings:
                lines.append(
                    f"  [{finding.severity.upper()}] "
                    f"{finding.pattern_name} in {finding.tool_name}: "
                    f"{finding.detail}"
                )
            for vf in server.vuln_findings:
                lines.append(
                    f"  [VULN-{vf.entry.severity.upper()}] "
                    f"{vf.entry.cve_id}: {vf.entry.description[:80]}"
                )

        if self.recommendations:
            lines.append("")
            lines.append("\u2500\u2500\u2500 Recommendations \u2500\u2500\u2500")
            for rec in self.recommendations:
                lines.append(f"  - {rec}")

        lines.append("")
        return "\n".join(lines)

    def to_html(self) -> str:
        """Generate a standalone HTML report page."""
        return _render_html(self)


# ---------------------------------------------------------------------------
# Grading
# ---------------------------------------------------------------------------


def _compute_grade(critical: int, high: int, medium: int) -> str:
    """Compute letter grade from severity counts.

    Grading rules:
        A: 0 critical, 0 high, <=2 medium
        B: 0 critical, <=2 high, <=5 medium
        C: 0 critical, <=5 high
        D: <=2 critical
        F: >2 critical
    """
    if critical == 0 and high == 0 and medium <= 2:
        return "A"
    if critical == 0 and high <= 2 and medium <= 5:
        return "B"
    if critical == 0 and high <= 5:
        return "C"
    if critical <= 2:
        return "D"
    return "F"


# ---------------------------------------------------------------------------
# Risk assessment
# ---------------------------------------------------------------------------


def _compute_server_risk(findings: list[MCPFinding], vuln_findings: list[VulnFinding]) -> str:
    """Determine overall risk for a server based on findings."""
    severities: list[str] = [f.severity for f in findings]
    severities.extend(vf.entry.severity for vf in vuln_findings)

    if not severities:
        return "low"

    if Severity.CRITICAL in severities:
        return "critical"
    if Severity.HIGH in severities:
        return "high"
    if Severity.MEDIUM in severities:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Recommendations engine
# ---------------------------------------------------------------------------


def _generate_recommendations(
    servers: list[ServerSecurityProfile],
) -> list[str]:
    """Generate prioritized recommendations from server profiles."""
    recs: list[str] = []
    seen: set[str] = set()

    # Critical findings first
    for server in servers:
        for f in server.findings:
            if f.severity == Severity.CRITICAL:
                key = f"critical:{f.pattern_name}:{server.server_name}"
                if key not in seen:
                    seen.add(key)
                    if f.category == "rug_pull":
                        recs.append(
                            f"IMMEDIATE: Pin tool definitions for "
                            f"'{server.server_name}' to prevent rug-pull attacks"
                        )
                    elif f.pattern_name == "parameter_override":
                        recs.append(
                            f"IMMEDIATE: Block parameter override attempts "
                            f"in '{f.tool_name}' on '{server.server_name}'"
                        )
                    elif f.pattern_name == "stealth_suppression":
                        recs.append(
                            f"IMMEDIATE: Investigate stealth suppression "
                            f"in '{f.tool_name}' on '{server.server_name}'"
                        )
                    else:
                        recs.append(
                            f"IMMEDIATE: Address {f.pattern_name} "
                            f"in '{f.tool_name}' on '{server.server_name}'"
                        )

        for vf in server.vuln_findings:
            if vf.entry.severity == Severity.CRITICAL:
                key = f"vuln-critical:{vf.entry.cve_id}"
                if key not in seen:
                    seen.add(key)
                    recs.append(f"IMMEDIATE: {vf.entry.recommendation} ({vf.entry.cve_id})")

    # High findings
    for server in servers:
        for f in server.findings:
            if f.severity == Severity.HIGH:
                key = f"high:{f.pattern_name}:{server.server_name}"
                if key not in seen:
                    seen.add(key)
                    recs.append(
                        f"HIGH PRIORITY: Remediate {f.pattern_name} "
                        f"in '{f.tool_name}' on '{server.server_name}'"
                    )

        for vf in server.vuln_findings:
            if vf.entry.severity == Severity.HIGH:
                key = f"vuln-high:{vf.entry.cve_id}"
                if key not in seen:
                    seen.add(key)
                    recs.append(f"HIGH PRIORITY: {vf.entry.recommendation} ({vf.entry.cve_id})")

    # Shadow conflict recommendations
    for server in servers:
        if server.shadow_findings:
            key = f"shadow:{server.server_name}"
            if key not in seen:
                seen.add(key)
                recs.append(
                    f"RESOLVE: Remove duplicate tool registrations on '{server.server_name}'"
                )

    # Low trust score recommendations
    for server in servers:
        low_trust_tools = [
            name for name, ts in server.trust_scores.items() if ts.level <= TrustLevel.L0_UNTRUSTED
        ]
        if low_trust_tools:
            key = f"trust:{server.server_name}"
            if key not in seen:
                seen.add(key)
                recs.append(f"IMPROVE: Review and audit tools from '{server.server_name}'")

    # Unpinned tool recommendations
    for server in servers:
        unpinned = [name for name, ts in server.trust_scores.items() if not ts.pinned]
        if unpinned and server.tool_count > 0:
            key = f"pin:{server.server_name}"
            if key not in seen:
                seen.add(key)
                recs.append(
                    f"RECOMMENDED: Pin tool definitions for "
                    f"'{server.server_name}' to detect rug-pull attacks"
                )

    return recs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iso_now() -> str:
    """Return current UTC time in ISO 8601 format."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _server_trust_label(server: ServerSecurityProfile) -> str:
    """Determine a representative trust label for a server."""
    if not server.trust_scores:
        return "unknown"
    min_level = min(ts.level for ts in server.trust_scores.values())
    return TrustLevel(min_level).name


def _severity_counts(
    findings: list[MCPFinding],
    vuln_findings: list[VulnFinding],
) -> tuple[int, int, int, int]:
    """Count findings by severity. Returns (critical, high, medium, low)."""
    critical = high = medium = low = 0
    for f in findings:
        if f.severity == Severity.CRITICAL:
            critical += 1
        elif f.severity == Severity.HIGH:
            high += 1
        elif f.severity == Severity.MEDIUM:
            medium += 1
        else:
            low += 1
    for vf in vuln_findings:
        sev = vf.entry.severity
        if sev == "critical":
            critical += 1
        elif sev == "high":
            high += 1
        elif sev == "medium":
            medium += 1
        else:
            low += 1
    return critical, high, medium, low


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

_SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#16a34a",
}

_GRADE_COLORS = {
    "A": "#16a34a",
    "B": "#65a30d",
    "C": "#ca8a04",
    "D": "#ea580c",
    "F": "#dc2626",
}


def _render_html(report: MCPSecurityReport) -> str:
    """Render a standalone HTML report page."""
    grade_color = _GRADE_COLORS.get(report.overall_grade, "#6b7280")
    e = html.escape

    server_sections: list[str] = []
    for server in report.servers:
        finding_rows: list[str] = []
        for f in server.findings:
            sev_color = _SEVERITY_COLORS.get(f.severity, "#6b7280")
            finding_rows.append(
                f"<tr>"
                f'<td><span style="color:{sev_color};font-weight:bold">'
                f"{e(f.severity.upper())}</span></td>"
                f"<td>{e(f.tool_name)}</td>"
                f"<td>{e(f.pattern_name)}</td>"
                f"<td>{e(f.detail)}</td>"
                f"</tr>"
            )
        for vf in server.vuln_findings:
            sev_color = _SEVERITY_COLORS.get(vf.entry.severity, "#6b7280")
            finding_rows.append(
                f"<tr>"
                f'<td><span style="color:{sev_color};font-weight:bold">'
                f"{e(vf.entry.severity.upper())}</span></td>"
                f"<td>{e(vf.package)}</td>"
                f"<td>{e(vf.entry.cve_id)}</td>"
                f"<td>{e(vf.entry.description[:120])}</td>"
                f"</tr>"
            )

        findings_table = ""
        if finding_rows:
            findings_table = (
                '<table class="findings">'
                "<tr><th>Severity</th><th>Tool</th>"
                "<th>Pattern/CVE</th><th>Detail</th></tr>" + "\n".join(finding_rows) + "</table>"
            )
        else:
            findings_table = '<p class="clean">No findings. Clean.</p>'

        risk_color = _SEVERITY_COLORS.get(server.overall_risk, "#16a34a")
        server_sections.append(
            f'<div class="server">'
            f"<h2>{e(server.server_name)}</h2>"
            f"<p>Tools: {server.tool_count} | Risk: "
            f'<span style="color:{risk_color};font-weight:bold">'
            f"{e(server.overall_risk)}</span></p>"
            f"{findings_table}"
            f"</div>"
        )

    recs_html = ""
    if report.recommendations:
        items = "\n".join(f"<li>{e(r)}</li>" for r in report.recommendations)
        recs_html = f'<div class="recs"><h2>Recommendations</h2><ol>{items}</ol></div>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MCP Security Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  background:#f8fafc;color:#1e293b;padding:2rem;max-width:960px;margin:0 auto}}
h1{{font-size:1.5rem;margin-bottom:0.5rem}}
.meta{{color:#64748b;margin-bottom:1.5rem}}
.dashboard{{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}}
.card{{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:1rem 1.5rem;
  min-width:120px;text-align:center}}
.card .value{{font-size:2rem;font-weight:700}}
.card .label{{color:#64748b;font-size:0.85rem}}
.server{{background:#fff;border:1px solid #e2e8f0;border-radius:8px;
  padding:1.5rem;margin-bottom:1rem}}
.server h2{{font-size:1.1rem;margin-bottom:0.5rem}}
table.findings{{width:100%;border-collapse:collapse;margin-top:0.5rem}}
table.findings th,table.findings td{{text-align:left;padding:0.4rem 0.6rem;
  border-bottom:1px solid #e2e8f0;font-size:0.9rem}}
table.findings th{{background:#f1f5f9;font-weight:600}}
.clean{{color:#16a34a;font-style:italic}}
.recs{{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:1.5rem;
  margin-top:1rem}}
.recs h2{{font-size:1.1rem;margin-bottom:0.5rem}}
.recs ol{{padding-left:1.5rem}}
.recs li{{margin-bottom:0.3rem;font-size:0.9rem}}
</style>
</head>
<body>
<h1>MCP Security Report</h1>
<p class="meta">Generated: {e(report.generated_at)}</p>
<div class="dashboard">
  <div class="card">
    <div class="value" style="color:{grade_color}">{e(report.overall_grade)}</div>
    <div class="label">Grade</div>
  </div>
  <div class="card">
    <div class="value">{len(report.servers)}</div>
    <div class="label">Servers</div>
  </div>
  <div class="card">
    <div class="value">{report.total_tools}</div>
    <div class="label">Tools</div>
  </div>
  <div class="card">
    <div class="value">{report.total_findings}</div>
    <div class="label">Findings</div>
  </div>
  <div class="card">
    <div class="value" style="color:{_SEVERITY_COLORS["critical"]}">{report.critical_count}</div>
    <div class="label">Critical</div>
  </div>
  <div class="card">
    <div class="value" style="color:{_SEVERITY_COLORS["high"]}">{report.high_count}</div>
    <div class="label">High</div>
  </div>
  <div class="card">
    <div class="value" style="color:{_SEVERITY_COLORS["medium"]}">{report.medium_count}</div>
    <div class="label">Medium</div>
  </div>
  <div class="card">
    <div class="value" style="color:{_SEVERITY_COLORS["low"]}">{report.low_count}</div>
    <div class="label">Low</div>
  </div>
</div>
{"".join(server_sections)}
{recs_html}
</body>
</html>"""


# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------


def _trust_level_name(ts: object | None) -> str:
    """Extract trust level name from a TrustScore, defaulting to 'unknown'."""
    if ts is not None and hasattr(ts, "level"):
        return str(ts.level.name)
    return "unknown"


class MCPSecurityReportGenerator:
    """Generates comprehensive security reports for MCP deployments.

    Combines MCPSecurityGate (description scan, rug-pull detection,
    argument sanitization, trust scoring) with MCPVulnDB (known CVEs)
    and SBOMGenerator into a single unified report.

    Args:
        gate: Security gate instance. Created automatically if not provided.
        vuln_db: Vulnerability database. Created automatically if not provided.
        sbom_generator: SBOM generator. Created automatically if not provided.
    """

    def __init__(
        self,
        *,
        gate: MCPSecurityGate | None = None,
        vuln_db: MCPVulnDB | None = None,
        sbom_generator: SBOMGenerator | None = None,
    ) -> None:
        self._gate = gate or MCPSecurityGate()
        self._vuln_db = vuln_db or MCPVulnDB()
        self._sbom_gen = sbom_generator or SBOMGenerator(vuln_db=self._vuln_db)

    def analyze_server(
        self,
        server_name: str,
        tools: list[dict[str, Any]],
        *,
        version: str = "unknown",
    ) -> ServerSecurityProfile:
        """Analyze a single server's security posture.

        Args:
            server_name: Name of the MCP server.
            tools: List of tool definitions, each with ``name``,
                ``description``, and optionally ``inputSchema``.
            version: Server version string for vulnerability checks.

        Returns:
            A :class:`ServerSecurityProfile` with findings and scores.
        """
        all_findings: list[MCPFinding] = []
        trust_scores: dict[str, TrustScore] = {}

        for tool in tools:
            tool_name = tool.get("name", "")
            description = tool.get("description", "")
            schema = tool.get("inputSchema")

            score = self._gate.evaluate(
                server=server_name,
                tool=tool_name,
                description=description,
                schema=schema,
            )
            trust_scores[tool_name] = score
            all_findings.extend(score.findings)

        # Vulnerability check
        vuln_findings: list[VulnFinding] = []
        if version and version != "unknown":
            vuln_findings = self._vuln_db.check(server_name, version)

        overall_risk = _compute_server_risk(all_findings, vuln_findings)

        return ServerSecurityProfile(
            server_name=server_name,
            tool_count=len(tools),
            trust_scores=trust_scores,
            findings=all_findings,
            vuln_findings=vuln_findings,
            overall_risk=overall_risk,
        )

    def generate(
        self,
        servers: dict[str, list[dict[str, Any]]],
        *,
        versions: dict[str, str] | None = None,
    ) -> MCPSecurityReport:
        """Generate a full security report across all servers.

        Args:
            servers: Mapping of server name to list of tool definitions.
            versions: Optional mapping of server name to version string.

        Returns:
            A complete :class:`MCPSecurityReport`.
        """
        versions = versions or {}
        profiles: list[ServerSecurityProfile] = []

        for server_name, tools in servers.items():
            version = versions.get(server_name, "unknown")
            profile = self.analyze_server(
                server_name,
                tools,
                version=version,
            )
            profiles.append(profile)

        # Aggregate counts
        total_tools = sum(p.tool_count for p in profiles)
        all_findings: list[MCPFinding] = []
        all_vuln_findings: list[VulnFinding] = []
        for p in profiles:
            all_findings.extend(p.findings)
            all_vuln_findings.extend(p.vuln_findings)

        critical, high, medium, low = _severity_counts(
            all_findings,
            all_vuln_findings,
        )
        total_findings = critical + high + medium + low

        # SBOM generation
        sbom: SBOM | None = None
        sbom_servers: list[MCPServerInfo] = []
        for server_name, tools in servers.items():
            version = versions.get(server_name, "")
            sbom_tools = [
                MCPToolInfo(
                    name=t.get("name", ""),
                    description=t.get("description", ""),
                    schema=t.get("inputSchema"),
                    trust_level=_trust_level_name(profiles[i].trust_scores.get(t.get("name", ""))),
                )
                for i, (sn, _) in enumerate(servers.items())
                if sn == server_name
                for t in tools
            ]
            sbom_servers.append(
                MCPServerInfo(
                    name=server_name,
                    version=version,
                    tools=sbom_tools,
                )
            )
        if sbom_servers:
            sbom = self._sbom_gen.generate(sbom_servers)

        grade = _compute_grade(critical, high, medium)
        recommendations = _generate_recommendations(profiles)

        return MCPSecurityReport(
            generated_at=_iso_now(),
            servers=profiles,
            total_tools=total_tools,
            total_findings=total_findings,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            sbom=sbom,
            overall_grade=grade,
            recommendations=recommendations,
        )
