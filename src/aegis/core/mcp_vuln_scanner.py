"""MCP vulnerability scanner -- pattern-based detection of tool definition flaws.

Scans MCP tool definitions (names, descriptions, parameter schemas) for
known vulnerability patterns covering injection, SSRF, path traversal,
command injection, privilege escalation, data exfiltration, and supply
chain risks.

Key components:

* **MCPVulnScanner** -- Main scanner that applies 20+ regex patterns.
* **VulnFinding** -- Immutable finding with CWE reference.
* **ScanReport** -- Aggregated scan results with risk scoring.

Thread-safe: the scanner itself is stateless (all state lives in method
locals), so it is inherently safe for concurrent use.

Reference:
    MCPGuard: Automated MCP Vulnerability Detection.
    arXiv:2510.23673 (2025).

Example::

    scanner = MCPVulnScanner()
    finding_list = scanner.scan_tool(
        "exec_cmd", "Execute any shell command", {"type": "object"}
    )
    report = scanner.scan_all([
        {"name": "exec_cmd", "description": "Execute any shell command"},
        {"name": "read_file", "description": "Read a local file"},
    ])
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

# ---------------------------------------------------------------------------
# Vulnerability categories
# ---------------------------------------------------------------------------


class VulnCategory(StrEnum):
    """Vulnerability categories for MCP tool definitions."""

    INJECTION = "injection"
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFIL = "data_exfil"
    SUPPLY_CHAIN = "supply_chain"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VulnFinding:
    """A single vulnerability finding for an MCP tool.

    Attributes:
        tool_name: The tool where the vulnerability was detected.
        vuln_type: Vulnerability category.
        severity: ``"critical"`` / ``"high"`` / ``"medium"`` / ``"low"``.
        description: Human-readable explanation.
        cwe_id: CWE identifier (e.g. ``"CWE-78"``).
        matched_text: The text that triggered the pattern.
    """

    tool_name: str
    vuln_type: str
    severity: str
    description: str
    cwe_id: str
    matched_text: str = ""


@dataclass(frozen=True)
class ScanReport:
    """Aggregated vulnerability scan report.

    Attributes:
        total_tools: Number of tools scanned.
        findings: All findings across all tools.
        risk_score: Aggregate risk score (0.0 = clean, 10.0 = maximum risk).
    """

    total_tools: int
    findings: tuple[VulnFinding, ...]
    risk_score: float

    @property
    def clean(self) -> bool:
        """Whether no vulnerabilities were found."""
        return len(self.findings) == 0


# ---------------------------------------------------------------------------
# Detection patterns: (name, category, severity, cwe_id, regex)
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[str, VulnCategory, str, str, re.Pattern[str]]] = [
    # -- INJECTION (4 patterns) --
    (
        "sql_injection_keywords",
        VulnCategory.INJECTION,
        "critical",
        "CWE-89",
        re.compile(
            r"(?:execute|run)\s+(?:raw\s+)?(?:sql|query|statement)",
            re.IGNORECASE,
        ),
    ),
    (
        "template_injection",
        VulnCategory.INJECTION,
        "high",
        "CWE-1336",
        re.compile(
            r"(?:render|eval(?:uate)?|execute)\s+(?:template|expression|string)",
            re.IGNORECASE,
        ),
    ),
    (
        "ldap_injection",
        VulnCategory.INJECTION,
        "high",
        "CWE-90",
        re.compile(
            r"(?:ldap|directory)\s+(?:search|query|filter|bind)",
            re.IGNORECASE,
        ),
    ),
    (
        "nosql_injection",
        VulnCategory.INJECTION,
        "high",
        "CWE-943",
        re.compile(
            r"(?:mongo|nosql|couchdb|dynamodb)\s+(?:query|find|aggregate|eval)",
            re.IGNORECASE,
        ),
    ),
    # -- SSRF (3 patterns) --
    (
        "ssrf_url_fetch",
        VulnCategory.SSRF,
        "high",
        "CWE-918",
        re.compile(
            r"(?:fetch|request|get|post|load|download)\s+(?:from\s+)?(?:any\s+)?(?:url|uri|endpoint|address)",
            re.IGNORECASE,
        ),
    ),
    (
        "ssrf_internal_network",
        VulnCategory.SSRF,
        "critical",
        "CWE-918",
        re.compile(
            r"(?:internal|localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.|10\.\d|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)",
            re.IGNORECASE,
        ),
    ),
    (
        "ssrf_redirect_follow",
        VulnCategory.SSRF,
        "medium",
        "CWE-918",
        re.compile(
            r"follow\s+redirect|allow\s+redirect|redirect.*(?:url|uri)",
            re.IGNORECASE,
        ),
    ),
    # -- PATH_TRAVERSAL (3 patterns) --
    (
        "path_traversal_dotdot",
        VulnCategory.PATH_TRAVERSAL,
        "high",
        "CWE-22",
        re.compile(
            r"(?:\.\./|\.\.\\|%2e%2e[/\\%])",
            re.IGNORECASE,
        ),
    ),
    (
        "path_traversal_absolute",
        VulnCategory.PATH_TRAVERSAL,
        "high",
        "CWE-22",
        re.compile(
            r"(?:any|arbitrary|user[\s-]*(?:provided|specified|supplied))\s+(?:file\s*)?path",
            re.IGNORECASE,
        ),
    ),
    (
        "path_traversal_sensitive",
        VulnCategory.PATH_TRAVERSAL,
        "critical",
        "CWE-22",
        re.compile(
            r"(?:/etc/(?:passwd|shadow)|\.ssh/|\.aws/|\.env\b|\.gnupg/|/proc/|/sys/)",
            re.IGNORECASE,
        ),
    ),
    # -- COMMAND_INJECTION (3 patterns) --
    (
        "cmd_injection_shell",
        VulnCategory.COMMAND_INJECTION,
        "critical",
        "CWE-78",
        re.compile(
            r"(?:execute|run|spawn|invoke|launch)\s+(?:any\s+)?(?:shell|system|os|bash|cmd|command|subprocess)",
            re.IGNORECASE,
        ),
    ),
    (
        "cmd_injection_eval",
        VulnCategory.COMMAND_INJECTION,
        "critical",
        "CWE-94",
        re.compile(
            r"(?:eval|exec)\s*\(|(?:execute|run)\s+(?:arbitrary|any|dynamic)\s+(?:code|script)",
            re.IGNORECASE,
        ),
    ),
    (
        "cmd_injection_pipe",
        VulnCategory.COMMAND_INJECTION,
        "high",
        "CWE-78",
        re.compile(
            r"(?:pipe|redirect|chain)\s+(?:to|into|output\s+to)\s+(?:another|next|shell|command)",
            re.IGNORECASE,
        ),
    ),
    # -- PRIVILEGE_ESCALATION (3 patterns) --
    (
        "priv_esc_sudo",
        VulnCategory.PRIVILEGE_ESCALATION,
        "critical",
        "CWE-269",
        re.compile(
            r"(?:sudo|root|admin(?:istrator)?|superuser|elevated)\s+(?:access|privilege|permission|mode|context)",
            re.IGNORECASE,
        ),
    ),
    (
        "priv_esc_permission_change",
        VulnCategory.PRIVILEGE_ESCALATION,
        "high",
        "CWE-269",
        re.compile(
            r"(?:chmod|chown|setuid|setgid|grant|escalat)\w*\s+(?:permission|privilege|access|role)",
            re.IGNORECASE,
        ),
    ),
    (
        "priv_esc_bypass",
        VulnCategory.PRIVILEGE_ESCALATION,
        "critical",
        "CWE-863",
        re.compile(
            r"(?:bypass|skip|disable|circumvent|ignore)\s+(?:auth(?:entication|orization)?|access\s+control|permission|policy|security)",
            re.IGNORECASE,
        ),
    ),
    # -- DATA_EXFIL (3 patterns) --
    (
        "data_exfil_send",
        VulnCategory.DATA_EXFIL,
        "critical",
        "CWE-200",
        re.compile(
            r"(?:send|transmit|upload|post|exfiltrate|forward)\s+(?:all\s+)?(?:data|content|files?|secrets?|credentials?|tokens?|keys?)\s+(?:to|via)",
            re.IGNORECASE,
        ),
    ),
    (
        "data_exfil_read_sensitive",
        VulnCategory.DATA_EXFIL,
        "high",
        "CWE-200",
        re.compile(
            r"(?:read|access|extract|dump|collect)\s+(?:all\s+)?(?:credentials?|secrets?|tokens?|api[\s_-]*keys?|passwords?|private[\s_-]*keys?)",
            re.IGNORECASE,
        ),
    ),
    (
        "data_exfil_env_access",
        VulnCategory.DATA_EXFIL,
        "high",
        "CWE-200",
        re.compile(
            r"(?:read|access|get|dump|list)\s+(?:all\s+)?(?:environment\s+variables?|env\s+vars?|process\s+env)",
            re.IGNORECASE,
        ),
    ),
    # -- SUPPLY_CHAIN (3 patterns) --
    (
        "supply_chain_install",
        VulnCategory.SUPPLY_CHAIN,
        "high",
        "CWE-829",
        re.compile(
            r"(?:install|download|fetch|pull)\s+(?:any\s+)?(?:package|module|library|dependency|plugin|extension)",
            re.IGNORECASE,
        ),
    ),
    (
        "supply_chain_remote_code",
        VulnCategory.SUPPLY_CHAIN,
        "critical",
        "CWE-829",
        re.compile(
            r"(?:download|fetch|load|import)\s+(?:and\s+)?(?:execute|run|eval)",
            re.IGNORECASE,
        ),
    ),
    (
        "supply_chain_untrusted_source",
        VulnCategory.SUPPLY_CHAIN,
        "high",
        "CWE-494",
        re.compile(
            r"(?:untrusted|unverified|unsigned|third[\s-]*party|external|unknown)\s+(?:source|origin|server|registry|repo)",
            re.IGNORECASE,
        ),
    ),
]

# ---------------------------------------------------------------------------
# Schema string extractor
# ---------------------------------------------------------------------------

_MAX_DEPTH = 20


def _extract_schema_strings(
    schema: dict[str, Any],
    depth: int = 0,
) -> list[str]:
    """Recursively extract descriptive strings from JSON Schema."""
    if depth > _MAX_DEPTH:
        return []

    strings: list[str] = []
    for key in ("description", "title", "default", "pattern"):
        val = schema.get(key)
        if isinstance(val, str):
            strings.append(val)

    for key in ("properties", "patternProperties"):
        props = schema.get(key)
        if isinstance(props, dict):
            for prop_name, prop_schema in props.items():
                strings.append(prop_name)
                if isinstance(prop_schema, dict):
                    strings.extend(_extract_schema_strings(prop_schema, depth + 1))

    items = schema.get("items")
    if isinstance(items, dict):
        strings.extend(_extract_schema_strings(items, depth + 1))

    for key in ("allOf", "anyOf", "oneOf"):
        variants = schema.get(key)
        if isinstance(variants, list):
            for v in variants:
                if isinstance(v, dict):
                    strings.extend(_extract_schema_strings(v, depth + 1))

    # Also check enum values
    enum_vals = schema.get("enum")
    if isinstance(enum_vals, list):
        for ev in enum_vals:
            if isinstance(ev, str):
                strings.append(ev)

    return strings


# ---------------------------------------------------------------------------
# MCPVulnScanner
# ---------------------------------------------------------------------------


class MCPVulnScanner:
    """Scan MCP tool definitions for known vulnerability patterns.

    Applies 22 regex-based detection patterns across 7 vulnerability
    categories.  The scanner is stateless and inherently thread-safe.

    Args:
        extra_patterns: Additional detection patterns in the format
            ``(name, category, severity, cwe_id, compiled_regex)``.
    """

    def __init__(
        self,
        extra_patterns: (list[tuple[str, VulnCategory, str, str, re.Pattern[str]]] | None) = None,
    ) -> None:
        self._patterns = list(_PATTERNS)
        if extra_patterns:
            self._patterns.extend(extra_patterns)

    def scan_tool(
        self,
        tool_name: str,
        description: str,
        schema: dict[str, Any] | None = None,
    ) -> list[VulnFinding]:
        """Scan a single tool definition for vulnerabilities.

        Args:
            tool_name: Canonical tool name.
            description: Tool description text.
            schema: JSON Schema for input parameters.

        Returns:
            List of :class:`VulnFinding` instances (empty = clean).
        """
        texts = [tool_name, description]
        if schema:
            texts.extend(_extract_schema_strings(schema))

        combined = " ".join(texts)
        findings: list[VulnFinding] = []

        for pname, category, severity, cwe_id, regex in self._patterns:
            match = regex.search(combined)
            if match:
                findings.append(
                    VulnFinding(
                        tool_name=tool_name,
                        vuln_type=category,
                        severity=severity,
                        description=f"Pattern '{pname}': potential {category} vuln",
                        cwe_id=cwe_id,
                        matched_text=match.group(0)[:200],
                    )
                )

        return findings

    def scan_all(
        self,
        tools: list[dict[str, Any]],
    ) -> ScanReport:
        """Scan all tool definitions and return an aggregate report.

        Each dict must contain ``"name"`` and ``"description"`` keys
        and optionally ``"schema"``.

        Args:
            tools: List of tool definition dicts.

        Returns:
            A :class:`ScanReport` with all findings and a risk score.
        """
        all_findings: list[VulnFinding] = []

        for tool in tools:
            findings = self.scan_tool(
                tool["name"],
                tool.get("description", ""),
                tool.get("schema"),
            )
            all_findings.extend(findings)

        risk_score = self._compute_risk_score(all_findings, len(tools))

        return ScanReport(
            total_tools=len(tools),
            findings=tuple(all_findings),
            risk_score=risk_score,
        )

    @staticmethod
    def _compute_risk_score(
        findings: list[VulnFinding],
        total_tools: int,
    ) -> float:
        """Compute aggregate risk score in [0.0, 10.0].

        Scoring: critical=4, high=2, medium=1, low=0.5.
        Normalized by total tools, capped at 10.0.
        """
        if total_tools == 0:
            return 0.0

        weights = {"critical": 4.0, "high": 2.0, "medium": 1.0, "low": 0.5}
        raw = sum(weights.get(f.severity, 0.0) for f in findings)
        normalized = raw / total_tools
        return min(10.0, round(normalized, 2))
