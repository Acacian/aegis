"""Tests for MCP server vulnerability database."""

from __future__ import annotations

from aegis.core.mcp_vuln_db import (
    MCPVulnDB,
    VulnEntry,
    _parse_version,
    _version_matches,
)

# ---------------------------------------------------------------------------
# Version parsing
# ---------------------------------------------------------------------------


class TestVersionParsing:
    def test_full_semver(self) -> None:
        assert _parse_version("1.2.3") == (1, 2, 3)

    def test_major_minor(self) -> None:
        assert _parse_version("1.2") == (1, 2)

    def test_major_only(self) -> None:
        assert _parse_version("1") == (1,)

    def test_invalid(self) -> None:
        assert _parse_version("abc") == (0,)


# ---------------------------------------------------------------------------
# Version matching
# ---------------------------------------------------------------------------


class TestVersionMatching:
    def test_less_than(self) -> None:
        assert _version_matches("0.5.0", "<0.6.0")
        assert not _version_matches("0.6.0", "<0.6.0")
        assert not _version_matches("0.7.0", "<0.6.0")

    def test_less_than_equal(self) -> None:
        assert _version_matches("0.5.0", "<=0.6.0")
        assert _version_matches("0.6.0", "<=0.6.0")
        assert not _version_matches("0.7.0", "<=0.6.0")

    def test_greater_than(self) -> None:
        assert _version_matches("1.0.0", ">0.9.0")
        assert not _version_matches("0.9.0", ">0.9.0")

    def test_greater_than_equal(self) -> None:
        assert _version_matches("1.0.0", ">=1.0.0")
        assert not _version_matches("0.9.0", ">=1.0.0")

    def test_range(self) -> None:
        assert _version_matches("1.1.0", ">=1.0.0,<1.2.0")
        assert not _version_matches("0.9.0", ">=1.0.0,<1.2.0")
        assert not _version_matches("1.2.0", ">=1.0.0,<1.2.0")

    def test_wildcard(self) -> None:
        assert _version_matches("0.0.1", "*")
        assert _version_matches("999.0.0", "*")

    def test_exact_match(self) -> None:
        assert _version_matches("1.2.3", "==1.2.3")
        assert not _version_matches("1.2.4", "==1.2.3")


# ---------------------------------------------------------------------------
# MCPVulnDB — basic operations
# ---------------------------------------------------------------------------


class TestMCPVulnDB:
    def test_builtin_entries_loaded(self) -> None:
        db = MCPVulnDB()
        assert db.entry_count > 0

    def test_no_builtin(self) -> None:
        db = MCPVulnDB(include_builtin=False)
        assert db.entry_count == 0

    def test_register_custom(self) -> None:
        db = MCPVulnDB(include_builtin=False)
        entry = VulnEntry(
            package="my-mcp-server",
            cve_id="MY-001",
            severity="high",
            affected_versions="<1.0.0",
            description="Test vulnerability",
        )
        db.register(entry)
        assert db.entry_count == 1
        assert "my-mcp-server" in db.packages

    def test_packages_property(self) -> None:
        db = MCPVulnDB()
        pkgs = db.packages
        assert "mcp-server-filesystem" in pkgs
        assert "mcp-server-sqlite" in pkgs


# ---------------------------------------------------------------------------
# Vulnerability checking
# ---------------------------------------------------------------------------


class TestVulnChecking:
    def test_vulnerable_version(self) -> None:
        db = MCPVulnDB()
        findings = db.check("mcp-server-filesystem", "0.5.0")
        assert len(findings) == 1
        assert findings[0].entry.severity == "critical"
        assert findings[0].should_block is True

    def test_safe_version(self) -> None:
        db = MCPVulnDB()
        findings = db.check("mcp-server-filesystem", "0.6.0")
        assert len(findings) == 0

    def test_unknown_package(self) -> None:
        db = MCPVulnDB()
        findings = db.check("unknown-package", "1.0.0")
        assert len(findings) == 0

    def test_medium_severity_no_block(self) -> None:
        db = MCPVulnDB()
        findings = db.check("mcp-server-fetch", "0.2.0")
        assert len(findings) == 1
        assert findings[0].entry.severity == "medium"
        assert findings[0].should_block is False

    def test_high_severity_blocks(self) -> None:
        db = MCPVulnDB()
        findings = db.check("mcp-server-sqlite", "0.4.0")
        assert len(findings) == 1
        assert findings[0].should_block is True

    def test_check_all(self) -> None:
        db = MCPVulnDB()
        results = db.check_all(
            {
                "mcp-server-filesystem": "0.5.0",
                "mcp-server-sqlite": "0.4.0",
                "safe-package": "1.0.0",
            }
        )
        assert "mcp-server-filesystem" in results
        assert "mcp-server-sqlite" in results
        assert "safe-package" not in results

    def test_get_entries_for_package(self) -> None:
        db = MCPVulnDB()
        entries = db.get_entries_for_package("mcp-server-filesystem")
        assert len(entries) >= 1
        assert all(e.package == "mcp-server-filesystem" for e in entries)

    def test_get_entries_unknown_package(self) -> None:
        db = MCPVulnDB()
        entries = db.get_entries_for_package("nonexistent")
        assert entries == []


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------


class TestReportFormatting:
    def test_no_findings(self) -> None:
        db = MCPVulnDB()
        report = db.format_report([])
        assert "No known vulnerabilities" in report

    def test_with_findings(self) -> None:
        db = MCPVulnDB()
        findings = db.check("mcp-server-filesystem", "0.5.0")
        report = db.format_report(findings)
        assert "Vulnerability Report" in report
        assert "CRITICAL" in report
        assert "BLOCK" in report
        assert "MCP-2025-001" in report

    def test_mixed_severities(self) -> None:
        db = MCPVulnDB()
        findings = db.check("mcp-server-filesystem", "0.5.0") + db.check(
            "mcp-server-fetch", "0.2.0"
        )
        report = db.format_report(findings)
        assert "CRITICAL" in report
        assert "MEDIUM" in report
        # Critical should come first
        crit_pos = report.index("CRITICAL")
        med_pos = report.index("MEDIUM")
        assert crit_pos < med_pos

    def test_owasp_mcp_shown(self) -> None:
        db = MCPVulnDB()
        findings = db.check("mcp-server-filesystem", "0.5.0")
        report = db.format_report(findings)
        assert "MCP05" in report
