"""MCP Server Software Bill of Materials (SBOM) generation.

Generates structured inventories of MCP server components for supply
chain security auditing.  Produces CycloneDX-inspired output (JSON)
without requiring external dependencies.

Key capabilities:

- **Server inventory** — Catalogs MCP servers with name, version,
  transport, and tool lists.
- **Tool cataloging** — Records each tool's description, schema hash,
  and trust level.
- **Vulnerability overlay** — Integrates with :class:`MCPVulnDB` to
  annotate SBOM components with known vulnerabilities.
- **Hash pinning** — Records SHA-256 hashes of tool definitions for
  integrity tracking.
- **JSON export** — Serializable SBOM in a CycloneDX-inspired schema
  for interop with security toolchains.

Usage::

    from aegis.core.mcp_sbom import MCPServerInfo, MCPToolInfo, SBOMGenerator

    server = MCPServerInfo(
        name="mcp-server-filesystem",
        version="0.5.0",
        transport="stdio",
        tools=[
            MCPToolInfo(name="read_file", description="Read a file"),
            MCPToolInfo(name="write_file", description="Write a file"),
        ],
    )
    gen = SBOMGenerator()
    sbom = gen.generate([server])
    print(sbom.to_json())
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

from aegis.core.mcp_vuln_db import MCPVulnDB, VulnFinding

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class MCPToolInfo:
    """Metadata for a single MCP tool.

    Attributes:
        name: Tool name (e.g. ``"read_file"``).
        description: Tool description text.
        schema: JSON Schema for the tool's arguments.
        trust_level: Trust level string (e.g. ``"L2_PINNED"``).
    """

    name: str
    description: str = ""
    schema: dict[str, Any] | None = None
    trust_level: str = ""


@dataclass
class MCPServerInfo:
    """Metadata for an MCP server.

    Attributes:
        name: Server package name (e.g. ``"mcp-server-filesystem"``).
        version: Server version string.
        transport: Transport type (``"stdio"``, ``"sse"``, ``"http"``).
        tools: List of tools exposed by the server.
        metadata: Additional server metadata.
    """

    name: str
    version: str = ""
    transport: str = "stdio"
    tools: list[MCPToolInfo] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SBOMVulnerability:
    """A vulnerability annotation on an SBOM component.

    Attributes:
        cve_id: CVE or advisory identifier.
        severity: ``"critical"``, ``"high"``, ``"medium"``, ``"low"``.
        description: Human-readable description.
        recommendation: Fix recommendation.
        should_block: Whether the component should be blocked.
    """

    cve_id: str
    severity: str
    description: str
    recommendation: str
    should_block: bool


@dataclass(frozen=True)
class SBOMToolComponent:
    """A tool component in the SBOM.

    Attributes:
        name: Tool name.
        description_hash: SHA-256 of the tool description + schema.
        trust_level: Assessed trust level.
        description_preview: First 200 chars of description.
    """

    name: str
    description_hash: str
    trust_level: str
    description_preview: str


@dataclass
class SBOMComponent:
    """A server component in the SBOM.

    Attributes:
        name: Server package name.
        version: Server version.
        transport: Transport type.
        tool_count: Number of tools.
        tools: Tool components.
        vulnerabilities: Known vulnerabilities.
        metadata: Additional metadata.
    """

    name: str
    version: str
    transport: str
    tool_count: int
    tools: list[SBOMToolComponent] = field(default_factory=list)
    vulnerabilities: list[SBOMVulnerability] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SBOM:
    """Software Bill of Materials for MCP servers.

    Attributes:
        bom_format: Format identifier.
        spec_version: Spec version.
        version: SBOM document version.
        serial_number: Unique SBOM identifier.
        generated_at: Generation timestamp (ISO 8601).
        components: Server components.
        total_tools: Total tool count across all servers.
        total_vulnerabilities: Total vulnerability count.
    """

    bom_format: str = "AegisMCPSBOM"
    spec_version: str = "1.0"
    version: int = 1
    serial_number: str = ""
    generated_at: str = ""
    components: list[SBOMComponent] = field(default_factory=list)
    total_tools: int = 0
    total_vulnerabilities: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dictionary."""
        return {
            "bomFormat": self.bom_format,
            "specVersion": self.spec_version,
            "version": self.version,
            "serialNumber": self.serial_number,
            "metadata": {
                "generatedAt": self.generated_at,
                "tool": "aegis",
            },
            "summary": {
                "totalServers": len(self.components),
                "totalTools": self.total_tools,
                "totalVulnerabilities": self.total_vulnerabilities,
            },
            "components": [
                {
                    "type": "mcp-server",
                    "name": c.name,
                    "version": c.version,
                    "transport": c.transport,
                    "toolCount": c.tool_count,
                    "tools": [
                        {
                            "name": t.name,
                            "descriptionHash": t.description_hash,
                            "trustLevel": t.trust_level,
                            "descriptionPreview": t.description_preview,
                        }
                        for t in c.tools
                    ],
                    "vulnerabilities": [
                        {
                            "id": v.cve_id,
                            "severity": v.severity,
                            "description": v.description,
                            "recommendation": v.recommendation,
                            "shouldBlock": v.should_block,
                        }
                        for v in c.vulnerabilities
                    ],
                    "metadata": c.metadata,
                }
                for c in self.components
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


# ---------------------------------------------------------------------------
# SBOM Generator
# ---------------------------------------------------------------------------


def _tool_definition_hash(tool: MCPToolInfo) -> str:
    """Compute SHA-256 hash of a tool definition."""
    canonical = (
        tool.name
        + "\0"
        + tool.description
        + "\0"
        + json.dumps(tool.schema or {}, sort_keys=True, separators=(",", ":"))
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _vuln_finding_to_sbom(finding: VulnFinding) -> SBOMVulnerability:
    """Convert a VulnFinding to an SBOMVulnerability."""
    return SBOMVulnerability(
        cve_id=finding.entry.cve_id,
        severity=finding.entry.severity,
        description=finding.entry.description,
        recommendation=finding.entry.recommendation,
        should_block=finding.should_block,
    )


class SBOMGenerator:
    """Generates SBOM documents for MCP server inventories.

    Args:
        vuln_db: Optional vulnerability database for annotations.
            If not provided, vulnerability checks are skipped.
    """

    def __init__(self, vuln_db: MCPVulnDB | None = None) -> None:
        self._vuln_db = vuln_db

    def generate(
        self,
        servers: list[MCPServerInfo],
        *,
        serial_number: str = "",
    ) -> SBOM:
        """Generate an SBOM from a list of MCP server inventories.

        Args:
            servers: MCP server metadata to include.
            serial_number: Optional unique identifier for this SBOM.

        Returns:
            A complete :class:`SBOM` document.
        """
        sbom = SBOM(
            serial_number=serial_number or _generate_serial(servers),
            generated_at=_iso_now(),
        )

        total_tools = 0
        total_vulns = 0

        for server in servers:
            component = self._build_component(server)
            total_tools += component.tool_count
            total_vulns += len(component.vulnerabilities)
            sbom.components.append(component)

        sbom.total_tools = total_tools
        sbom.total_vulnerabilities = total_vulns
        return sbom

    def _build_component(self, server: MCPServerInfo) -> SBOMComponent:
        """Build an SBOM component for a single server."""
        tool_components: list[SBOMToolComponent] = []
        for tool in server.tools:
            tool_components.append(
                SBOMToolComponent(
                    name=tool.name,
                    description_hash=_tool_definition_hash(tool),
                    trust_level=tool.trust_level or "unknown",
                    description_preview=tool.description[:200],
                )
            )

        vulns: list[SBOMVulnerability] = []
        if self._vuln_db and server.version:
            findings = self._vuln_db.check(server.name, server.version)
            vulns = [_vuln_finding_to_sbom(f) for f in findings]

        return SBOMComponent(
            name=server.name,
            version=server.version,
            transport=server.transport,
            tool_count=len(server.tools),
            tools=tool_components,
            vulnerabilities=vulns,
            metadata=dict(server.metadata),
        )

    def format_report(self, sbom: SBOM) -> str:
        """Format an SBOM as a human-readable text report."""
        lines: list[str] = []
        lines.append("MCP Server SBOM Report")
        lines.append("=" * 40)
        lines.append(f"Generated: {sbom.generated_at}")
        lines.append(f"Serial: {sbom.serial_number}")
        lines.append(
            f"Servers: {len(sbom.components)} | "
            f"Tools: {sbom.total_tools} | "
            f"Vulnerabilities: {sbom.total_vulnerabilities}"
        )
        lines.append("")

        for comp in sbom.components:
            version = f"@{comp.version}" if comp.version else ""
            lines.append(f"  [{comp.transport.upper()}] {comp.name}{version}")
            lines.append(f"    Tools: {comp.tool_count}")

            for tool in comp.tools:
                trust = f" [{tool.trust_level}]" if tool.trust_level != "unknown" else ""
                lines.append(f"      - {tool.name}{trust}")
                lines.append(f"        hash: {tool.description_hash[:16]}...")

            if comp.vulnerabilities:
                lines.append(f"    Vulnerabilities: {len(comp.vulnerabilities)}")
                for vuln in comp.vulnerabilities:
                    block = " [BLOCK]" if vuln.should_block else ""
                    lines.append(
                        f"      [{vuln.severity.upper()}]{block} {vuln.cve_id}"
                    )
                    lines.append(f"        {vuln.description[:100]}")
                    lines.append(f"        Fix: {vuln.recommendation}")

            lines.append("")

        if sbom.total_vulnerabilities == 0:
            lines.append("No known vulnerabilities found.")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iso_now() -> str:
    """Return current time as ISO 8601 string."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _generate_serial(servers: list[MCPServerInfo]) -> str:
    """Generate a deterministic serial number from server list."""
    content = "|".join(
        f"{s.name}:{s.version}:{len(s.tools)}" for s in servers
    )
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
