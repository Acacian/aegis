"""MCP supply chain security layer.

Inline runtime protection against MCP tool poisoning, rug pulls,
command injection, and path traversal. No LLM required — uses
deterministic pattern matching with Unicode normalization.

Components:
    - ToolDescriptionScanner: Detect hidden malicious instructions
    - RugPullDetector: Hash-based change detection for tool definitions
    - ArgumentSanitizer: Path traversal + command injection detection
    - ToolTrustScorer: L0-L4 trust levels with scoring
    - MCPSecurityGate: Unified gate integrating all components plus
      optional response scanning, escalation detection, shadow detection,
      and rate limiting

Example::

    scanner = ToolDescriptionScanner()
    findings = scanner.scan("read_file", "Read a file from disk", schema={})

    detector = RugPullDetector()
    detector.pin("server", "tool", "description", {})
    is_changed = detector.check("server", "tool", "new description", {})

    sanitizer = ArgumentSanitizer()
    findings = sanitizer.check({"path": "../../../etc/passwd"})
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
import unicodedata
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any

logger = logging.getLogger("aegis.core.mcp_security")

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class Severity(str):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class TrustLevel(IntEnum):
    """MCP tool trust levels (inspired by MCPS L0-L4)."""

    L0_UNTRUSTED = 0
    L1_SCANNED = 1
    L2_PINNED = 2
    L3_VERIFIED = 3
    L4_AUDITED = 4


@dataclass(frozen=True)
class MCPFinding:
    """A security finding from MCP tool analysis."""

    category: str
    severity: str
    pattern_name: str
    detail: str
    tool_name: str = ""
    server_name: str = ""
    matched_text: str = ""


@dataclass
class TrustScore:
    """Trust assessment for an MCP tool."""

    level: TrustLevel
    score: int
    findings: list[MCPFinding] = field(default_factory=list)
    pinned: bool = False
    audited: bool = False


# ---------------------------------------------------------------------------
# Unicode normalization helpers
# ---------------------------------------------------------------------------

# Zero-width characters to strip before analysis
_ZERO_WIDTH = re.compile(
    "[\u200b\u200c\u200d\ufeff\u00ad\u200e\u200f"
    "\u202a\u202b\u202c\u202d\u202e\u2060\u2061\u2062\u2063\u2064\ufeff]"
)

# Common confusable character mappings (Cyrillic -> Latin, etc.)
_CONFUSABLES: dict[str, str] = {
    "\u0410": "A",  # Cyrillic А
    "\u0412": "B",  # Cyrillic В
    "\u0421": "C",  # Cyrillic С
    "\u0415": "E",  # Cyrillic Е
    "\u041d": "H",  # Cyrillic Н
    "\u041a": "K",  # Cyrillic К
    "\u041c": "M",  # Cyrillic М
    "\u041e": "O",  # Cyrillic О
    "\u0420": "P",  # Cyrillic Р
    "\u0422": "T",  # Cyrillic Т
    "\u0425": "X",  # Cyrillic Х
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
}


def _normalize_text(text: str) -> str:
    """Normalize text for pattern matching.

    1. Strip zero-width characters
    2. NFKC normalization (collapses fullwidth, superscripts, ligatures)
    3. Confusable character mapping to ASCII
    """
    text = _ZERO_WIDTH.sub("", text)
    text = unicodedata.normalize("NFKC", text)
    for confusable, replacement in _CONFUSABLES.items():
        text = text.replace(confusable, replacement)
    return text


# ---------------------------------------------------------------------------
# Tool Description Scanner
# ---------------------------------------------------------------------------

# 10 compiled detection patterns (run against normalized text)
_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "authority_injection",
        Severity.CRITICAL,
        re.compile(
            r"<(?:IMPORTANT|CRITICAL|SYSTEM|INSTRUCTION|OVERRIDE)>",
            re.IGNORECASE,
        ),
    ),
    (
        "markdown_authority",
        Severity.HIGH,
        re.compile(
            r"\*\*(?:IMPORTANT|CRITICAL|SYSTEM)\*\*"
            r"|\[(?:IMPORTANT|CRITICAL|SYSTEM)\]",
            re.IGNORECASE,
        ),
    ),
    (
        "file_exfiltration",
        Severity.CRITICAL,
        re.compile(
            r"read\s+[~/.]*(\.ssh|\.env|\.aws|credentials|passwd|shadow|\.gnupg|\.config)",
            re.IGNORECASE,
        ),
    ),
    (
        "data_exfiltration",
        Severity.CRITICAL,
        re.compile(
            r"(?:read|access|get|fetch|extract).*?"
            r"(?:send|upload|post|transmit|forward|exfiltrate)\s+(?:to|it)",
            re.IGNORECASE,
        ),
    ),
    (
        "cross_tool_manipulation",
        Severity.HIGH,
        re.compile(
            r"(?:instead of|rather than|before|after)\s+"
            r"(?:using|calling|invoking)\s+(?:the\s+)?\w+\s+tool",
            re.IGNORECASE,
        ),
    ),
    (
        "dangerous_capabilities",
        Severity.HIGH,
        re.compile(
            r"(?:execut|run|launch|spawn)\w*\s+"
            r"(?:arbitrary|any|system|shell|os)\s+(?:command|script|code)",
            re.IGNORECASE,
        ),
    ),
    (
        "hidden_conditionals",
        Severity.HIGH,
        re.compile(
            r"(?:before|after|when|whenever|if)\s+(?:any|every|each|all)?\s*"
            r"(?:file|operation|call|request|tool).*?"
            r"(?:you must|always|first|required)",
            re.IGNORECASE,
        ),
    ),
    (
        "parameter_override",
        Severity.CRITICAL,
        re.compile(
            r"(?:change|replace|modify|redirect|alter)\s+(?:the\s+)?"
            r"(?:recipient|destination|target|path|url|endpoint|account)",
            re.IGNORECASE,
        ),
    ),
    (
        "stealth_suppression",
        Severity.CRITICAL,
        re.compile(
            r"(?:do not|don't|never|without)\s+"
            r"(?:log|record|notify|alert|show|display|mention|tell)",
            re.IGNORECASE,
        ),
    ),
    (
        "encoded_payloads",
        Severity.HIGH,
        re.compile(
            r"(?:base64|eval|exec|decode|fromCharCode|atob|btoa)\s*\(",
            re.IGNORECASE,
        ),
    ),
]

_MAX_SCHEMA_DEPTH = 20


def _extract_schema_strings(schema: dict[str, Any], depth: int = 0) -> list[str]:
    """Recursively extract description/title/default strings from JSON Schema."""
    if depth > _MAX_SCHEMA_DEPTH:
        return []

    strings: list[str] = []
    for key in ("description", "title", "default"):
        val = schema.get(key)
        if isinstance(val, str):
            strings.append(val)

    # Recurse into properties, items, etc.
    for key in ("properties", "patternProperties"):
        props = schema.get(key)
        if isinstance(props, dict):
            for prop_schema in props.values():
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

    return strings


class ToolDescriptionScanner:
    """Scan MCP tool descriptions for poisoning patterns.

    Uses 10 compiled regex patterns against Unicode-normalized text.
    No LLM calls. Sub-millisecond per tool.
    """

    def __init__(self, *, exempt_tools: set[str] | None = None) -> None:
        self._exempt = exempt_tools or set()

    def scan(
        self,
        tool_name: str,
        description: str,
        schema: dict[str, Any] | None = None,
        *,
        server_name: str = "",
    ) -> list[MCPFinding]:
        """Scan a tool description and schema for poisoning patterns.

        Returns a list of findings (empty = clean).
        """
        if tool_name in self._exempt:
            return []

        findings: list[MCPFinding] = []

        # Collect all text to scan
        texts = [description]
        if schema:
            texts.extend(_extract_schema_strings(schema))

        combined = _normalize_text(" ".join(texts))

        for pattern_name, severity, regex in _PATTERNS:
            match = regex.search(combined)
            if match:
                findings.append(
                    MCPFinding(
                        category="tool_poisoning",
                        severity=severity,
                        pattern_name=pattern_name,
                        detail=f"Pattern '{pattern_name}' matched in tool description",
                        tool_name=tool_name,
                        server_name=server_name,
                        matched_text=match.group(0)[:200],
                    )
                )

        return findings


# ---------------------------------------------------------------------------
# Rug Pull Detector
# ---------------------------------------------------------------------------


def _tool_hash(name: str, description: str, schema: dict[str, Any] | None) -> str:
    """Compute a canonical SHA-256 hash of a tool definition."""
    canonical = (
        name
        + "\0"
        + description
        + "\0"
        + json.dumps(schema or {}, sort_keys=True, separators=(",", ":"))
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class PinEntry:
    """A pinned tool definition."""

    hash: str
    approved_at: float
    description_preview: str
    version: int = 1


class RugPullDetector:
    """Detect when MCP tool definitions change after initial approval.

    Computes SHA-256 hashes of tool definitions and stores them in a
    pin store. On subsequent checks, compares the current hash against
    the pinned value.
    """

    def __init__(self, pin_store_path: str | Path | None = None) -> None:
        self._pins: dict[str, PinEntry] = {}
        self._path = Path(pin_store_path) if pin_store_path else None
        if self._path and self._path.exists():
            self._load()

    def pin(
        self,
        server: str,
        tool: str,
        description: str,
        schema: dict[str, Any] | None = None,
    ) -> str:
        """Pin a tool definition. Returns the hash."""
        key = f"{server}::{tool}"
        h = _tool_hash(tool, description, schema)
        self._pins[key] = PinEntry(
            hash=h,
            approved_at=time.time(),
            description_preview=description[:200],
        )
        self._save()
        return h

    def check(
        self,
        server: str,
        tool: str,
        description: str,
        schema: dict[str, Any] | None = None,
    ) -> MCPFinding | None:
        """Check if a tool definition has changed since pinning.

        Returns a finding if a rug pull is detected, None if clean.
        Returns None if the tool has never been pinned (first encounter).
        """
        key = f"{server}::{tool}"
        entry = self._pins.get(key)
        if entry is None:
            return None  # First encounter — not yet pinned

        current_hash = _tool_hash(tool, description, schema)
        if current_hash == entry.hash:
            return None

        return MCPFinding(
            category="rug_pull",
            severity=Severity.CRITICAL,
            pattern_name="definition_changed",
            detail=(
                f"Tool '{tool}' on server '{server}' has changed since approval. "
                f"Previous hash: {entry.hash[:16]}..., current: {current_hash[:16]}..."
            ),
            tool_name=tool,
            server_name=server,
        )

    def is_pinned(self, server: str, tool: str) -> bool:
        """Check if a tool has been pinned."""
        return f"{server}::{tool}" in self._pins

    def _save(self) -> None:
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = {}
        for key, entry in self._pins.items():
            data[key] = {
                "hash": entry.hash,
                "approved_at": entry.approved_at,
                "description_preview": entry.description_preview,
                "version": entry.version,
            }
        # Atomic write: write to temp file, then rename to avoid TOCTOU
        # corruption if the process crashes mid-write.
        import tempfile

        tmp_fd, tmp_path = tempfile.mkstemp(dir=str(self._path.parent), suffix=".tmp")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            Path(tmp_path).replace(self._path)
        except BaseException:
            Path(tmp_path).unlink(missing_ok=True)
            raise

    def _load(self) -> None:
        if not self._path or not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            for key, val in data.items():
                self._pins[key] = PinEntry(
                    hash=val["hash"],
                    approved_at=val.get("approved_at", 0),
                    description_preview=val.get("description_preview", ""),
                    version=val.get("version", 1),
                )
        except (json.JSONDecodeError, KeyError):
            logger.error(
                "Corrupted pin store at '%s' — resetting to empty. "
                "Tool integrity verification will restart from scratch.",
                self._path,
                exc_info=True,
            )
            self._pins.clear()


# ---------------------------------------------------------------------------
# Argument Sanitizer
# ---------------------------------------------------------------------------

# Path traversal patterns
_PATH_TRAVERSAL: list[re.Pattern[str]] = [
    re.compile(r"\.\./|\.\.\\"),  # ../  or  ..\
    re.compile(r"%2e%2e[%/\\]", re.IGNORECASE),  # URL-encoded
    re.compile(r"%00|\\x00"),  # Null byte injection
    re.compile(
        r"(?:^|/)(?:etc/(?:passwd|shadow)|\.ssh/|\.aws/|\.env$|\.gnupg/|proc/|sys/)",
        re.IGNORECASE,
    ),
]

# Command injection patterns
_CMD_INJECTION: list[re.Pattern[str]] = [
    re.compile(r"[;|]"),  # Shell command chaining
    re.compile(r"\$\(|\$\{|`"),  # Command substitution
    re.compile(r"&&|\|\|"),  # Logical operators
    re.compile(r">>?|<"),  # Redirection
    re.compile(r"%0[ad]|\\[rn]", re.IGNORECASE),  # Newline injection
]

_MAX_ARG_DEPTH = 10


class ArgumentSanitizer:
    """Detect path traversal and command injection in tool arguments.

    Scans all string-typed argument values recursively.
    """

    def __init__(self, *, allow_shell: bool = False) -> None:
        """Initialize the sanitizer.

        Args:
            allow_shell: If True, skip command injection checks
                (for intentional shell/terminal tools).
        """
        self._allow_shell = allow_shell

    def check(
        self,
        arguments: dict[str, Any],
        *,
        tool_name: str = "",
        server_name: str = "",
    ) -> list[MCPFinding]:
        """Check tool arguments for injection patterns.

        Returns a list of findings (empty = clean).
        """
        findings: list[MCPFinding] = []
        self._check_value(arguments, findings, tool_name, server_name, depth=0)
        return findings

    def _check_value(
        self,
        value: Any,
        findings: list[MCPFinding],
        tool_name: str,
        server_name: str,
        depth: int,
    ) -> None:
        if depth > _MAX_ARG_DEPTH:
            return

        if isinstance(value, str):
            self._check_string(value, findings, tool_name, server_name)
        elif isinstance(value, dict):
            for v in value.values():
                self._check_value(v, findings, tool_name, server_name, depth + 1)
        elif isinstance(value, list):
            for v in value:
                self._check_value(v, findings, tool_name, server_name, depth + 1)

    def _check_string(
        self,
        value: str,
        findings: list[MCPFinding],
        tool_name: str,
        server_name: str,
    ) -> None:
        # Normalize Unicode before pattern matching to prevent bypass via
        # fullwidth characters, NFKC-equivalent sequences, or confusables.
        value = _normalize_text(value)

        # Path traversal (always checked)
        for pattern in _PATH_TRAVERSAL:
            match = pattern.search(value)
            if match:
                findings.append(
                    MCPFinding(
                        category="path_traversal",
                        severity=Severity.HIGH,
                        pattern_name="path_traversal",
                        detail="Path traversal pattern detected in argument value",
                        tool_name=tool_name,
                        server_name=server_name,
                        matched_text=match.group(0)[:100],
                    )
                )
                break  # One finding per string is enough

        # Command injection (skip if allow_shell)
        if not self._allow_shell:
            for pattern in _CMD_INJECTION:
                match = pattern.search(value)
                if match:
                    findings.append(
                        MCPFinding(
                            category="command_injection",
                            severity=Severity.CRITICAL,
                            pattern_name="command_injection",
                            detail="Command injection pattern detected in argument value",
                            tool_name=tool_name,
                            server_name=server_name,
                            matched_text=match.group(0)[:100],
                        )
                    )
                    break


# ---------------------------------------------------------------------------
# Tool Trust Scorer
# ---------------------------------------------------------------------------


class ToolTrustScorer:
    """Compute trust levels (L0-L4) for MCP tools.

    Trust is computed from scan results, pin status, and manual audit.
    """

    def score(
        self,
        findings: list[MCPFinding],
        *,
        is_pinned: bool = False,
        is_audited: bool = False,
    ) -> TrustScore:
        """Score a tool based on security findings and status.

        Args:
            findings: Findings from description scan + argument check.
            is_pinned: Whether the tool definition is hash-pinned.
            is_audited: Whether the tool has been manually reviewed.

        Returns:
            A TrustScore with level, numeric score, and findings.
        """
        base = 100

        for f in findings:
            if f.severity == Severity.CRITICAL:
                base -= 50
            elif f.severity == Severity.HIGH:
                base -= 25
            elif f.severity == Severity.MEDIUM:
                base -= 10
            elif f.severity == Severity.LOW:
                base -= 5

        # Rug pull = immediate L0
        rug_pull = any(f.category == "rug_pull" for f in findings)
        if rug_pull:
            base = 0

        base = max(0, min(100, base))

        # Determine trust level
        if base < 25 or rug_pull:
            level = TrustLevel.L0_UNTRUSTED
        elif base < 50:
            level = TrustLevel.L1_SCANNED
        elif base < 75 and is_pinned:
            level = TrustLevel.L2_PINNED
        elif base >= 75 and is_pinned and is_audited:
            level = TrustLevel.L4_AUDITED
        elif base >= 75 and is_pinned:
            level = TrustLevel.L3_VERIFIED
        elif base >= 50:
            level = TrustLevel.L1_SCANNED  # Not pinned, cap at L1
        else:
            level = TrustLevel.L0_UNTRUSTED

        return TrustScore(
            level=level,
            score=base,
            findings=list(findings),
            pinned=is_pinned,
            audited=is_audited,
        )


# ---------------------------------------------------------------------------
# Unified MCP Security Gate
# ---------------------------------------------------------------------------


class MCPSecurityGate:
    """Unified security gate for MCP tool calls.

    Combines all four core security components into a single check that
    runs before the policy engine. Optionally integrates response
    scanning, escalation detection, shadow detection, and rate limiting
    when the corresponding module instances are provided.

    Example::

        gate = MCPSecurityGate()
        result = gate.evaluate(
            server="filesystem",
            tool="read_file",
            description="Read a file from disk",
            schema={"type": "object", "properties": {...}},
            arguments={"path": "/etc/passwd"},
        )
        if result.level == TrustLevel.L0_UNTRUSTED:
            # Block the tool call
            ...
    """

    def __init__(
        self,
        *,
        pin_store_path: str | Path | None = None,
        exempt_tools: set[str] | None = None,
        min_trust_level: TrustLevel = TrustLevel.L1_SCANNED,
        allow_shell_tools: set[str] | None = None,
        # Optional extended modules
        response_scanner: Any | None = None,
        escalation_detector: Any | None = None,
        shadow_detector: Any | None = None,
        rate_limiter: Any | None = None,
    ) -> None:
        self._scanner = ToolDescriptionScanner(exempt_tools=exempt_tools)
        self._rug_pull = RugPullDetector(pin_store_path=pin_store_path)
        self._sanitizer = ArgumentSanitizer()
        self._shell_sanitizer = ArgumentSanitizer(allow_shell=True)
        self._scorer = ToolTrustScorer()
        self._min_trust = min_trust_level
        self._shell_tools = allow_shell_tools or set()

        # Extended modules (all optional — lazy-validated on use)
        self._response_scanner = response_scanner
        self._escalation_detector = escalation_detector
        self._shadow_detector = shadow_detector
        self._rate_limiter = rate_limiter

    def evaluate(
        self,
        *,
        server: str,
        tool: str,
        description: str = "",
        schema: dict[str, Any] | None = None,
        arguments: dict[str, Any] | None = None,
    ) -> TrustScore:
        """Run all security checks on an MCP tool call.

        Returns a TrustScore. The caller should block if
        ``score.level < min_trust_level``.
        """
        all_findings: list[MCPFinding] = []

        # 1. Description scan
        all_findings.extend(self._scanner.scan(tool, description, schema, server_name=server))

        # 2. Rug pull check
        rug_finding = self._rug_pull.check(server, tool, description, schema)
        if rug_finding:
            all_findings.append(rug_finding)

        # 3. Argument sanitization
        if arguments:
            sanitizer = self._shell_sanitizer if tool in self._shell_tools else self._sanitizer
            all_findings.extend(sanitizer.check(arguments, tool_name=tool, server_name=server))

        # 4. Trust scoring
        is_pinned = self._rug_pull.is_pinned(server, tool)
        score = self._scorer.score(all_findings, is_pinned=is_pinned)

        return score

    def pin_tool(
        self,
        server: str,
        tool: str,
        description: str,
        schema: dict[str, Any] | None = None,
    ) -> str:
        """Pin a tool definition after approval. Returns the hash."""
        return self._rug_pull.pin(server, tool, description, schema)

    @property
    def min_trust_level(self) -> TrustLevel:
        """Minimum trust level required for tool execution."""
        return self._min_trust

    def should_block(self, score: TrustScore) -> bool:
        """Check if a tool should be blocked based on trust level."""
        return score.level < self._min_trust

    # ------------------------------------------------------------------
    # Extended module methods (all safe to call even without the module)
    # ------------------------------------------------------------------

    def check_response(
        self,
        tool_name: str,
        response: str | dict[str, Any],
        *,
        server_name: str = "",
    ) -> list[Any]:
        """Scan a tool response for security issues.

        Delegates to the configured :class:`MCPResponseScanner`. If no
        scanner is configured, returns an empty list.

        Args:
            tool_name: The tool that produced the response.
            response: Raw text or structured (dict/list) response.
            server_name: MCP server name (for context in findings).

        Returns:
            A list of :class:`~aegis.core.mcp_response_scanner.ResponseFinding`
            instances (empty when clean or when no scanner is configured).
        """
        if self._response_scanner is None:
            return []

        if isinstance(response, str):
            return list(self._response_scanner.scan(response, tool_name=tool_name))
        elif isinstance(response, dict | list):
            return list(self._response_scanner.scan_structured(response, tool_name=tool_name))
        return []

    def check_rate_limit(
        self,
        tool_name: str,
        server_name: str,
        *,
        session_id: str = "default",
    ) -> Any:
        """Check rate limit for a tool call.

        Delegates to the configured :class:`MCPRateLimiter`. If no
        rate limiter is configured, returns *None*.

        Args:
            tool_name: The tool being called.
            server_name: MCP server that owns the tool.
            session_id: Logical session identifier.

        Returns:
            A :class:`~aegis.core.mcp_rate_limiter.MCPRateLimitResult`
            if a rate limiter is configured, otherwise *None*.
        """
        if self._rate_limiter is None:
            return None

        return self._rate_limiter.check(tool_name, server_name, session_id=session_id)

    def register_tools(
        self,
        server_name: str,
        tools: list[dict[str, Any]],
    ) -> list[Any]:
        """Register tools from a server and check for shadows.

        Delegates to the configured :class:`ToolShadowDetector`. If no
        shadow detector is configured, returns an empty list.

        Args:
            server_name: Name of the MCP server providing the tools.
            tools: List of tool dicts, each with ``name``, ``description``,
                and optionally ``inputSchema``.

        Returns:
            A list of :class:`~aegis.core.mcp_shadow.ShadowFinding`
            instances (empty when clean or when no detector is configured).
        """
        if self._shadow_detector is None:
            return []

        return list(self._shadow_detector.register_tools(server_name, tools))

    def record_call(
        self,
        tool_name: str,
        server_name: str,
        arguments: dict[str, Any],
        *,
        session_id: str = "default",
    ) -> list[Any]:
        """Record a tool call and check for escalation patterns.

        Delegates to the configured :class:`EscalationDetector`. If no
        escalation detector is configured, returns an empty list.

        Args:
            tool_name: Fully-qualified tool name.
            server_name: MCP server that owns the tool.
            arguments: Arguments passed to the tool call.
            session_id: Logical session identifier.

        Returns:
            A list of :class:`~aegis.core.mcp_escalation.EscalationFinding`
            instances (empty when clean or when no detector is configured).
        """
        if self._escalation_detector is None:
            return []

        return list(
            self._escalation_detector.record_and_check(
                tool_name, server_name, arguments, session_id=session_id
            )
        )
