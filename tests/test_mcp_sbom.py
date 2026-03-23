"""Tests for MCP server SBOM generation."""

from __future__ import annotations

import json

from aegis.core.mcp_sbom import (
    SBOM,
    MCPServerInfo,
    MCPToolInfo,
    SBOMComponent,
    SBOMGenerator,
    SBOMToolComponent,
    SBOMVulnerability,
    _generate_serial,
    _tool_definition_hash,
)
from aegis.core.mcp_vuln_db import MCPVulnDB

# ---------------------------------------------------------------------------
# Tool hashing
# ---------------------------------------------------------------------------


class TestToolDefinitionHash:
    def test_deterministic(self) -> None:
        tool = MCPToolInfo(name="read", description="Read a file")
        h1 = _tool_definition_hash(tool)
        h2 = _tool_definition_hash(tool)
        assert h1 == h2

    def test_different_tools_different_hash(self) -> None:
        t1 = MCPToolInfo(name="read", description="Read a file")
        t2 = MCPToolInfo(name="write", description="Write a file")
        assert _tool_definition_hash(t1) != _tool_definition_hash(t2)

    def test_schema_affects_hash(self) -> None:
        t1 = MCPToolInfo(name="read", description="Read", schema={"type": "object"})
        t2 = MCPToolInfo(name="read", description="Read", schema={"type": "string"})
        assert _tool_definition_hash(t1) != _tool_definition_hash(t2)

    def test_none_schema_same_as_empty(self) -> None:
        t1 = MCPToolInfo(name="read", description="Read", schema=None)
        t2 = MCPToolInfo(name="read", description="Read", schema={})
        assert _tool_definition_hash(t1) == _tool_definition_hash(t2)


# ---------------------------------------------------------------------------
# Serial number generation
# ---------------------------------------------------------------------------


class TestSerialGeneration:
    def test_deterministic(self) -> None:
        servers = [MCPServerInfo(name="s1", version="1.0")]
        s1 = _generate_serial(servers)
        s2 = _generate_serial(servers)
        assert s1 == s2

    def test_different_servers_different_serial(self) -> None:
        s1 = _generate_serial([MCPServerInfo(name="s1", version="1.0")])
        s2 = _generate_serial([MCPServerInfo(name="s2", version="1.0")])
        assert s1 != s2

    def test_length(self) -> None:
        serial = _generate_serial([MCPServerInfo(name="s1")])
        assert len(serial) == 16


# ---------------------------------------------------------------------------
# SBOM data model
# ---------------------------------------------------------------------------


class TestSBOMModel:
    def test_to_dict(self) -> None:
        sbom = SBOM(
            serial_number="abc123",
            generated_at="2026-03-24T00:00:00Z",
            total_tools=2,
            total_vulnerabilities=0,
            components=[
                SBOMComponent(
                    name="test-server",
                    version="1.0.0",
                    transport="stdio",
                    tool_count=2,
                    tools=[
                        SBOMToolComponent(
                            name="read",
                            description_hash="deadbeef",
                            trust_level="L2_PINNED",
                            description_preview="Read a file",
                        ),
                    ],
                ),
            ],
        )
        d = sbom.to_dict()
        assert d["bomFormat"] == "AegisMCPSBOM"
        assert d["specVersion"] == "1.0"
        assert d["serialNumber"] == "abc123"
        assert d["summary"]["totalServers"] == 1
        assert d["summary"]["totalTools"] == 2
        assert len(d["components"]) == 1
        assert d["components"][0]["name"] == "test-server"
        assert len(d["components"][0]["tools"]) == 1

    def test_to_json(self) -> None:
        sbom = SBOM(serial_number="test", generated_at="now")
        j = sbom.to_json()
        parsed = json.loads(j)
        assert parsed["serialNumber"] == "test"

    def test_to_json_valid(self) -> None:
        sbom = SBOM(
            serial_number="test",
            generated_at="now",
            components=[
                SBOMComponent(
                    name="srv",
                    version="1.0",
                    transport="sse",
                    tool_count=0,
                    vulnerabilities=[
                        SBOMVulnerability(
                            cve_id="CVE-2025-001",
                            severity="critical",
                            description="Test vuln",
                            recommendation="Upgrade",
                            should_block=True,
                        ),
                    ],
                ),
            ],
        )
        parsed = json.loads(sbom.to_json())
        vuln = parsed["components"][0]["vulnerabilities"][0]
        assert vuln["id"] == "CVE-2025-001"
        assert vuln["shouldBlock"] is True


# ---------------------------------------------------------------------------
# SBOMGenerator — basic generation
# ---------------------------------------------------------------------------


class TestSBOMGenerator:
    def test_empty_servers(self) -> None:
        gen = SBOMGenerator()
        sbom = gen.generate([])
        assert len(sbom.components) == 0
        assert sbom.total_tools == 0
        assert sbom.total_vulnerabilities == 0
        assert sbom.generated_at != ""

    def test_single_server(self) -> None:
        server = MCPServerInfo(
            name="mcp-server-test",
            version="1.0.0",
            transport="stdio",
            tools=[
                MCPToolInfo(name="read_file", description="Read a file"),
                MCPToolInfo(name="write_file", description="Write a file"),
            ],
        )
        gen = SBOMGenerator()
        sbom = gen.generate([server])
        assert len(sbom.components) == 1
        assert sbom.total_tools == 2
        comp = sbom.components[0]
        assert comp.name == "mcp-server-test"
        assert comp.version == "1.0.0"
        assert comp.transport == "stdio"
        assert comp.tool_count == 2
        assert len(comp.tools) == 2

    def test_multiple_servers(self) -> None:
        servers = [
            MCPServerInfo(
                name="server-a",
                version="1.0",
                tools=[MCPToolInfo(name="tool_1")],
            ),
            MCPServerInfo(
                name="server-b",
                version="2.0",
                tools=[
                    MCPToolInfo(name="tool_2"),
                    MCPToolInfo(name="tool_3"),
                ],
            ),
        ]
        gen = SBOMGenerator()
        sbom = gen.generate(servers)
        assert len(sbom.components) == 2
        assert sbom.total_tools == 3

    def test_tool_hashes_populated(self) -> None:
        server = MCPServerInfo(
            name="srv",
            tools=[MCPToolInfo(name="read", description="Read a file")],
        )
        gen = SBOMGenerator()
        sbom = gen.generate([server])
        tool = sbom.components[0].tools[0]
        assert len(tool.description_hash) == 64  # SHA-256 hex
        assert tool.description_preview == "Read a file"

    def test_trust_level_propagated(self) -> None:
        server = MCPServerInfo(
            name="srv",
            tools=[
                MCPToolInfo(
                    name="read",
                    description="Read",
                    trust_level="L3_VERIFIED",
                ),
            ],
        )
        gen = SBOMGenerator()
        sbom = gen.generate([server])
        assert sbom.components[0].tools[0].trust_level == "L3_VERIFIED"

    def test_unknown_trust_level_default(self) -> None:
        server = MCPServerInfo(
            name="srv",
            tools=[MCPToolInfo(name="read")],
        )
        gen = SBOMGenerator()
        sbom = gen.generate([server])
        assert sbom.components[0].tools[0].trust_level == "unknown"

    def test_custom_serial_number(self) -> None:
        gen = SBOMGenerator()
        sbom = gen.generate([], serial_number="custom-serial-123")
        assert sbom.serial_number == "custom-serial-123"

    def test_auto_serial_number(self) -> None:
        servers = [MCPServerInfo(name="srv", version="1.0")]
        gen = SBOMGenerator()
        sbom = gen.generate(servers)
        assert len(sbom.serial_number) == 16

    def test_metadata_preserved(self) -> None:
        server = MCPServerInfo(
            name="srv",
            metadata={"author": "test", "license": "MIT"},
        )
        gen = SBOMGenerator()
        sbom = gen.generate([server])
        assert sbom.components[0].metadata["author"] == "test"
        assert sbom.components[0].metadata["license"] == "MIT"


# ---------------------------------------------------------------------------
# Vulnerability integration
# ---------------------------------------------------------------------------


class TestVulnerabilityIntegration:
    def test_vulnerable_server(self) -> None:
        db = MCPVulnDB()
        server = MCPServerInfo(
            name="mcp-server-filesystem",
            version="0.5.0",
            tools=[MCPToolInfo(name="read_file", description="Read")],
        )
        gen = SBOMGenerator(vuln_db=db)
        sbom = gen.generate([server])
        comp = sbom.components[0]
        assert len(comp.vulnerabilities) == 1
        vuln = comp.vulnerabilities[0]
        assert vuln.cve_id == "MCP-2025-001"
        assert vuln.severity == "critical"
        assert vuln.should_block is True
        assert sbom.total_vulnerabilities == 1

    def test_safe_server(self) -> None:
        db = MCPVulnDB()
        server = MCPServerInfo(
            name="mcp-server-filesystem",
            version="0.6.0",
            tools=[MCPToolInfo(name="read_file")],
        )
        gen = SBOMGenerator(vuln_db=db)
        sbom = gen.generate([server])
        assert len(sbom.components[0].vulnerabilities) == 0
        assert sbom.total_vulnerabilities == 0

    def test_unknown_server_no_vulns(self) -> None:
        db = MCPVulnDB()
        server = MCPServerInfo(name="custom-server", version="1.0.0")
        gen = SBOMGenerator(vuln_db=db)
        sbom = gen.generate([server])
        assert len(sbom.components[0].vulnerabilities) == 0

    def test_no_version_skips_vuln_check(self) -> None:
        db = MCPVulnDB()
        server = MCPServerInfo(name="mcp-server-filesystem")
        gen = SBOMGenerator(vuln_db=db)
        sbom = gen.generate([server])
        assert len(sbom.components[0].vulnerabilities) == 0

    def test_multiple_servers_mixed_vulns(self) -> None:
        db = MCPVulnDB()
        servers = [
            MCPServerInfo(name="mcp-server-filesystem", version="0.5.0"),
            MCPServerInfo(name="mcp-server-sqlite", version="0.4.0"),
            MCPServerInfo(name="custom-server", version="1.0.0"),
        ]
        gen = SBOMGenerator(vuln_db=db)
        sbom = gen.generate(servers)
        assert sbom.total_vulnerabilities == 2  # filesystem + sqlite


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------


class TestReportFormatting:
    def test_empty_report(self) -> None:
        gen = SBOMGenerator()
        sbom = gen.generate([])
        report = gen.format_report(sbom)
        assert "SBOM Report" in report
        assert "Servers: 0" in report
        assert "No known vulnerabilities" in report

    def test_report_with_servers(self) -> None:
        server = MCPServerInfo(
            name="mcp-server-test",
            version="1.0.0",
            transport="sse",
            tools=[
                MCPToolInfo(
                    name="read_file",
                    description="Read a file from disk",
                    trust_level="L2_PINNED",
                ),
            ],
        )
        gen = SBOMGenerator()
        sbom = gen.generate([server])
        report = gen.format_report(sbom)
        assert "mcp-server-test@1.0.0" in report
        assert "[SSE]" in report
        assert "read_file" in report
        assert "L2_PINNED" in report

    def test_report_with_vulns(self) -> None:
        db = MCPVulnDB()
        server = MCPServerInfo(
            name="mcp-server-filesystem",
            version="0.5.0",
        )
        gen = SBOMGenerator(vuln_db=db)
        sbom = gen.generate([server])
        report = gen.format_report(sbom)
        assert "CRITICAL" in report
        assert "BLOCK" in report
        assert "MCP-2025-001" in report

    def test_report_no_version(self) -> None:
        server = MCPServerInfo(name="srv", transport="stdio")
        gen = SBOMGenerator()
        sbom = gen.generate([server])
        report = gen.format_report(sbom)
        # No @version when version is empty
        assert "srv" in report
        assert "@" not in report.split("srv")[1].split("\n")[0]
