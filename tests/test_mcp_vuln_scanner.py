"""Tests for aegis.core.mcp_vuln_scanner -- MCP vulnerability scanner.

Reference: arXiv:2510.23673
"""

from __future__ import annotations

import re
import threading

import pytest

from aegis.core.mcp_vuln_scanner import (
    MCPVulnScanner,
    ScanReport,
    VulnCategory,
    VulnFinding,
)

# ---------------------------------------------------------------------------
# VulnFinding frozen dataclass
# ---------------------------------------------------------------------------


class TestVulnFinding:
    def test_creation(self) -> None:
        f = VulnFinding("tool", "injection", "high", "desc", "CWE-89")
        assert f.tool_name == "tool"
        assert f.vuln_type == "injection"
        assert f.cwe_id == "CWE-89"

    def test_frozen(self) -> None:
        f = VulnFinding("tool", "injection", "high", "desc", "CWE-89")
        with pytest.raises(AttributeError):
            f.tool_name = "x"  # type: ignore[misc]

    def test_default_matched_text(self) -> None:
        f = VulnFinding("tool", "t", "h", "d", "CWE-1")
        assert f.matched_text == ""


# ---------------------------------------------------------------------------
# ScanReport frozen dataclass
# ---------------------------------------------------------------------------


class TestScanReport:
    def test_creation(self) -> None:
        r = ScanReport(5, (), 0.0)
        assert r.total_tools == 5
        assert r.clean is True
        assert r.risk_score == 0.0

    def test_frozen(self) -> None:
        r = ScanReport(1, (), 0.0)
        with pytest.raises(AttributeError):
            r.total_tools = 10  # type: ignore[misc]

    def test_not_clean(self) -> None:
        f = VulnFinding("t", "injection", "high", "d", "CWE-89")
        r = ScanReport(1, (f,), 2.0)
        assert r.clean is False


# ---------------------------------------------------------------------------
# VulnCategory enum
# ---------------------------------------------------------------------------


class TestVulnCategory:
    def test_all_categories_exist(self) -> None:
        expected = {
            "injection",
            "ssrf",
            "path_traversal",
            "command_injection",
            "privilege_escalation",
            "data_exfil",
            "supply_chain",
        }
        actual = {c.value for c in VulnCategory}
        assert expected == actual


# ---------------------------------------------------------------------------
# INJECTION detection
# ---------------------------------------------------------------------------


class TestInjectionDetection:
    def test_sql_injection(self) -> None:
        scanner = MCPVulnScanner()
        findings = scanner.scan_tool("db_query", "Execute raw SQL query")
        types = {f.vuln_type for f in findings}
        assert VulnCategory.INJECTION in types

    def test_template_injection(self) -> None:
        scanner = MCPVulnScanner()
        findings = scanner.scan_tool("render", "Render template expression")
        types = {f.vuln_type for f in findings}
        assert VulnCategory.INJECTION in types

    def test_nosql_injection(self) -> None:
        scanner = MCPVulnScanner()
        findings = scanner.scan_tool("mongo", "Mongo query with user input")
        types = {f.vuln_type for f in findings}
        assert VulnCategory.INJECTION in types


# ---------------------------------------------------------------------------
# SSRF detection
# ---------------------------------------------------------------------------


class TestSSRFDetection:
    def test_url_fetch(self) -> None:
        scanner = MCPVulnScanner()
        findings = scanner.scan_tool("fetcher", "Fetch from any URL provided")
        types = {f.vuln_type for f in findings}
        assert VulnCategory.SSRF in types

    def test_internal_network(self) -> None:
        scanner = MCPVulnScanner()
        findings = scanner.scan_tool("proxy", "Access localhost:8080 admin panel")
        types = {f.vuln_type for f in findings}
        assert VulnCategory.SSRF in types


# ---------------------------------------------------------------------------
# PATH_TRAVERSAL detection
# ---------------------------------------------------------------------------


class TestPathTraversalDetection:
    def test_dotdot(self) -> None:
        scanner = MCPVulnScanner()
        findings = scanner.scan_tool("reader", "Read file at ../../etc/passwd")
        types = {f.vuln_type for f in findings}
        assert VulnCategory.PATH_TRAVERSAL in types

    def test_arbitrary_path(self) -> None:
        scanner = MCPVulnScanner()
        findings = scanner.scan_tool("reader", "Read any user-provided path")
        types = {f.vuln_type for f in findings}
        assert VulnCategory.PATH_TRAVERSAL in types

    def test_sensitive_file(self) -> None:
        scanner = MCPVulnScanner()
        findings = scanner.scan_tool("reader", "Access /etc/passwd for info")
        types = {f.vuln_type for f in findings}
        assert VulnCategory.PATH_TRAVERSAL in types


# ---------------------------------------------------------------------------
# COMMAND_INJECTION detection
# ---------------------------------------------------------------------------


class TestCommandInjection:
    def test_shell_command(self) -> None:
        scanner = MCPVulnScanner()
        findings = scanner.scan_tool("exec", "Execute any shell command")
        types = {f.vuln_type for f in findings}
        assert VulnCategory.COMMAND_INJECTION in types

    def test_eval(self) -> None:
        scanner = MCPVulnScanner()
        findings = scanner.scan_tool("evaluator", "Execute arbitrary code on server")
        types = {f.vuln_type for f in findings}
        assert VulnCategory.COMMAND_INJECTION in types


# ---------------------------------------------------------------------------
# PRIVILEGE_ESCALATION detection
# ---------------------------------------------------------------------------


class TestPrivilegeEscalation:
    def test_sudo_access(self) -> None:
        scanner = MCPVulnScanner()
        findings = scanner.scan_tool("admin", "Requires root access to run")
        types = {f.vuln_type for f in findings}
        assert VulnCategory.PRIVILEGE_ESCALATION in types

    def test_bypass_auth(self) -> None:
        scanner = MCPVulnScanner()
        findings = scanner.scan_tool("bypass", "Bypass authentication checks")
        types = {f.vuln_type for f in findings}
        assert VulnCategory.PRIVILEGE_ESCALATION in types


# ---------------------------------------------------------------------------
# DATA_EXFIL detection
# ---------------------------------------------------------------------------


class TestDataExfil:
    def test_send_data(self) -> None:
        scanner = MCPVulnScanner()
        findings = scanner.scan_tool("exfil", "Send all data to remote server")
        types = {f.vuln_type for f in findings}
        assert VulnCategory.DATA_EXFIL in types

    def test_credential_access(self) -> None:
        scanner = MCPVulnScanner()
        findings = scanner.scan_tool("creds", "Read all credentials from vault")
        types = {f.vuln_type for f in findings}
        assert VulnCategory.DATA_EXFIL in types


# ---------------------------------------------------------------------------
# SUPPLY_CHAIN detection
# ---------------------------------------------------------------------------


class TestSupplyChain:
    def test_install_package(self) -> None:
        scanner = MCPVulnScanner()
        findings = scanner.scan_tool("installer", "Install any package from npm")
        types = {f.vuln_type for f in findings}
        assert VulnCategory.SUPPLY_CHAIN in types

    def test_remote_code(self) -> None:
        scanner = MCPVulnScanner()
        findings = scanner.scan_tool("loader", "Download and execute script")
        types = {f.vuln_type for f in findings}
        assert VulnCategory.SUPPLY_CHAIN in types

    def test_untrusted_source(self) -> None:
        scanner = MCPVulnScanner()
        findings = scanner.scan_tool("fetch", "Fetch from untrusted source")
        types = {f.vuln_type for f in findings}
        assert VulnCategory.SUPPLY_CHAIN in types


# ---------------------------------------------------------------------------
# Schema scanning
# ---------------------------------------------------------------------------


class TestSchemaScanning:
    def test_vuln_in_schema_description(self) -> None:
        scanner = MCPVulnScanner()
        schema = {"properties": {"cmd": {"description": "Execute any shell command"}}}
        findings = scanner.scan_tool("tool", "A tool", schema)
        assert len(findings) >= 1

    def test_vuln_in_schema_title(self) -> None:
        scanner = MCPVulnScanner()
        schema = {"title": "Execute raw SQL query interface"}
        findings = scanner.scan_tool("tool", "A tool", schema)
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# Aggregate scanning (scan_all)
# ---------------------------------------------------------------------------


class TestScanAll:
    def test_clean_tools(self) -> None:
        scanner = MCPVulnScanner()
        tools = [
            {"name": "read", "description": "Read a document"},
            {"name": "write", "description": "Write a document"},
        ]
        report = scanner.scan_all(tools)
        assert report.total_tools == 2
        assert report.clean is True
        assert report.risk_score == 0.0

    def test_mixed_tools(self) -> None:
        scanner = MCPVulnScanner()
        tools = [
            {"name": "safe", "description": "Read a document"},
            {"name": "danger", "description": "Execute any shell command on server"},
        ]
        report = scanner.scan_all(tools)
        assert report.total_tools == 2
        assert report.clean is False
        assert report.risk_score > 0.0

    def test_empty_list(self) -> None:
        scanner = MCPVulnScanner()
        report = scanner.scan_all([])
        assert report.total_tools == 0
        assert report.clean is True

    def test_risk_score_capped(self) -> None:
        scanner = MCPVulnScanner()
        # Craft a tool that triggers many critical findings
        tools = [
            {
                "name": "mega_bad",
                "description": (
                    "Execute raw SQL query. Fetch from any URL. "
                    "Read ../../etc/passwd. Execute any shell command. "
                    "Requires root access. Send all data to attacker.com. "
                    "Download and execute malware."
                ),
            }
        ]
        report = scanner.scan_all(tools)
        assert report.risk_score <= 10.0


# ---------------------------------------------------------------------------
# Extra patterns
# ---------------------------------------------------------------------------


class TestExtraPatterns:
    def test_custom_pattern(self) -> None:
        custom = [
            (
                "custom_vuln",
                VulnCategory.INJECTION,
                "low",
                "CWE-0",
                re.compile(r"CUSTOM_VULN_MARKER"),
            )
        ]
        scanner = MCPVulnScanner(extra_patterns=custom)
        findings = scanner.scan_tool("tool", "Has CUSTOM_VULN_MARKER here")
        names = {f.description for f in findings}
        assert any("custom_vuln" in n for n in names)


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_scanning(self) -> None:
        scanner = MCPVulnScanner()
        results: list[list[VulnFinding]] = []
        lock = threading.Lock()

        def scan_worker(i: int) -> None:
            findings = scanner.scan_tool(f"tool_{i}", "Execute any shell command")
            with lock:
                results.append(findings)

        threads = [threading.Thread(target=scan_worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 20
        for findings in results:
            assert len(findings) >= 1


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_description(self) -> None:
        scanner = MCPVulnScanner()
        findings = scanner.scan_tool("tool", "")
        assert isinstance(findings, list)

    def test_none_schema(self) -> None:
        scanner = MCPVulnScanner()
        findings = scanner.scan_tool("tool", "Safe tool", None)
        assert isinstance(findings, list)

    def test_deeply_nested_schema(self) -> None:
        schema: dict = {"description": "Safe"}
        current = schema
        for _ in range(25):
            current["properties"] = {"nested": {"description": "Safe"}}
            current = current["properties"]["nested"]

        scanner = MCPVulnScanner()
        findings = scanner.scan_tool("tool", "Safe", schema)
        assert isinstance(findings, list)
