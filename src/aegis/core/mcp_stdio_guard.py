"""MCP STDIO injection guard — runtime protection for STDIO transport.

Addresses the systemic MCP STDIO vulnerability (OX Security, April 2026)
where malicious tool responses can inject additional JSON-RPC messages
into the STDIO stream. Anthropic declined to patch ("expected behavior"),
making client-side protection the only viable mitigation.

Attack vectors mitigated:
    1. Response injection: Tool output contains embedded JSON-RPC messages
       separated by newlines, which the client parses as separate messages.
    2. Notification injection: Crafted notifications trigger client actions.
    3. Request smuggling: Additional requests embedded within response payloads.
    4. Unicode/encoding attacks: Zero-width chars or BOM manipulation to
       bypass naive text parsing.

Components:
    - StdioInjectionScanner: Detects JSON-RPC payloads embedded in content
    - StdioFrameValidator: Validates message framing on byte streams
    - StdioGuard: Unified guard that wraps STDIO read streams

Example::

    from aegis.core.mcp_stdio_guard import StdioGuard, StdioScanResult

    guard = StdioGuard()

    # Scan a tool response before passing to client
    result = guard.scan_content("Here is the file content...")
    if result.has_injection:
        print(f"BLOCKED: {result.findings}")

    # Validate raw STDIO frame
    frame_result = guard.validate_frame(raw_bytes)
    if not frame_result.valid:
        print(f"Invalid frame: {frame_result.reason}")

Reference:
    - OX Security advisory (2026-04-15):
      https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/
    - The Hacker News coverage:
      https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("aegis.core.mcp_stdio_guard")

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StdioFinding:
    """A finding from STDIO injection analysis."""

    category: str  # "jsonrpc_injection", "notification_injection",
    # "request_smuggling", "frame_manipulation", "encoding_attack"
    severity: str  # "critical", "high", "medium", "low"
    detail: str
    matched_text: str = ""
    position: int = -1  # Byte/char offset where injection was detected


@dataclass
class StdioScanResult:
    """Result of scanning content for STDIO injection."""

    has_injection: bool
    findings: list[StdioFinding] = field(default_factory=list)
    sanitized_content: str | None = None  # Content with injections neutralized
    scan_time_ms: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")


@dataclass(frozen=True)
class FrameValidation:
    """Result of validating a raw STDIO frame."""

    valid: bool
    reason: str = ""
    message_count: int = 1  # Expected: 1 message per frame
    injected_count: int = 0  # Number of injected messages detected


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# JSON-RPC 2.0 message patterns (used to detect injection)
_JSONRPC_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    # Full JSON-RPC request/response embedded in content
    (
        "jsonrpc_request",
        "critical",
        re.compile(
            r'\{\s*"jsonrpc"\s*:\s*"2\.0"\s*,\s*"method"\s*:',
            re.DOTALL,
        ),
    ),
    (
        "jsonrpc_response",
        "critical",
        re.compile(
            r'\{\s*"jsonrpc"\s*:\s*"2\.0"\s*,\s*"(?:result|error)"\s*:',
            re.DOTALL,
        ),
    ),
    # Notification patterns (no "id" field)
    (
        "jsonrpc_notification",
        "critical",
        re.compile(
            r'\{\s*"jsonrpc"\s*:\s*"2\.0"\s*,\s*"method"\s*:\s*"(?:notifications/|tools/|resources/)',
            re.DOTALL,
        ),
    ),
    # MCP-specific method injection
    (
        "mcp_tool_call",
        "critical",
        re.compile(
            r'"method"\s*:\s*"tools/call"',
        ),
    ),
    (
        "mcp_resource_read",
        "high",
        re.compile(
            r'"method"\s*:\s*"resources/read"',
        ),
    ),
    (
        "mcp_prompt_get",
        "high",
        re.compile(
            r'"method"\s*:\s*"prompts/get"',
        ),
    ),
    # Initialize/capabilities manipulation
    (
        "mcp_initialize",
        "critical",
        re.compile(
            r'"method"\s*:\s*"initialize"',
        ),
    ),
]

# Newline-based frame boundary injection
_FRAME_BOUNDARY_PATTERN = re.compile(
    r'(?:\r?\n)\s*\{\s*"jsonrpc"\s*:\s*"2\.0"',
)

# Unicode/encoding attack patterns
_ENCODING_ATTACKS: list[tuple[str, str, re.Pattern[str]]] = [
    # BOM injection (can shift byte boundaries)
    (
        "bom_injection",
        "high",
        re.compile(r"\ufeff.{0,20}\{.*jsonrpc", re.DOTALL),
    ),
    # Null byte injection (can terminate strings prematurely in C-based parsers)
    (
        "null_byte",
        "high",
        re.compile(r"\x00"),
    ),
    # Overlong UTF-8 sequences (represented as escaped bytes in content)
    (
        "overlong_utf8",
        "medium",
        re.compile(r"\\xc0\\x(?:ae|af)|\\xe0\\x80\\x(?:ae|af)"),
    ),
    # Line separator/paragraph separator (U+2028, U+2029 — alternative newlines)
    (
        "unicode_newline",
        "high",
        re.compile(r"[\u2028\u2029]"),
    ),
]

# Content-Length manipulation (HTTP-style smuggling adapted to STDIO)
_CONTENT_LENGTH_PATTERN = re.compile(
    r"Content-Length\s*:\s*\d+\s*\r?\n\r?\n",
    re.IGNORECASE,
)

# JSON unicode escape pattern (used for normalization before scanning)
_JSON_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")


def _decode_json_unicode_escapes(text: str) -> str:
    """Decode JSON \\uXXXX escape sequences to actual characters.

    This prevents bypass via unicode-escaped keys like \\u006asonrpc
    which JSON parsers will decode but regex patterns won't match.
    """
    try:
        return _JSON_UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)
    except (ValueError, OverflowError):
        return text


# ---------------------------------------------------------------------------
# StdioInjectionScanner
# ---------------------------------------------------------------------------


class StdioInjectionScanner:
    """Scan MCP tool response content for embedded JSON-RPC injections.

    Detects attempts to smuggle additional JSON-RPC messages within
    tool output content. Operates on the text content of tool results
    BEFORE they are framed into JSON-RPC responses.

    This is the primary defense against the STDIO injection vulnerability
    where a malicious MCP server embeds extra messages in tool outputs.
    """

    def __init__(
        self,
        *,
        allow_jsonrpc_in_content: bool = False,
        max_content_length: int = 10 * 1024 * 1024,  # 10MB
    ) -> None:
        """Initialize the scanner.

        Args:
            allow_jsonrpc_in_content: If True, don't flag JSON-RPC patterns
                in content (for tools that legitimately return JSON-RPC
                examples, e.g., documentation tools). Default False.
            max_content_length: Maximum content length to scan. Content
                exceeding this is truncated for scanning (finding reported).
        """
        self._allow_jsonrpc = allow_jsonrpc_in_content
        self._max_length = max_content_length

    def scan(self, content: str, *, tool_name: str = "") -> StdioScanResult:
        """Scan content for STDIO injection patterns.

        Args:
            content: The text content from a tool response.
            tool_name: Name of the tool (for logging context).

        Returns:
            StdioScanResult with findings and optional sanitized content.
        """
        start = time.perf_counter()
        findings: list[StdioFinding] = []

        # Length check
        truncated = False
        scan_content = content
        if len(content) > self._max_length:
            scan_content = content[: self._max_length]
            truncated = True
            findings.append(
                StdioFinding(
                    category="oversized_content",
                    severity="medium",
                    detail=(
                        f"Content exceeds {self._max_length} bytes "
                        f"(actual: {len(content)}). Truncated for scanning."
                    ),
                )
            )

        # 0. Normalize JSON unicode escapes to prevent bypass via \u006asonrpc
        normalized = _decode_json_unicode_escapes(scan_content)

        # 1. JSON-RPC injection detection
        if not self._allow_jsonrpc:
            for pattern_name, severity, regex in _JSONRPC_PATTERNS:
                for match in regex.finditer(normalized):
                    findings.append(
                        StdioFinding(
                            category="jsonrpc_injection",
                            severity=severity,
                            detail=(
                                f"JSON-RPC {pattern_name} pattern detected in "
                                f"tool output{f' ({tool_name})' if tool_name else ''}"
                            ),
                            matched_text=match.group(0)[:200],
                            position=match.start(),
                        )
                    )

        # 2. Frame boundary injection (newline + JSON-RPC start)
        for match in _FRAME_BOUNDARY_PATTERN.finditer(normalized):
            findings.append(
                StdioFinding(
                    category="frame_injection",
                    severity="critical",
                    detail=(
                        "Newline followed by JSON-RPC message start detected — "
                        "possible STDIO frame injection"
                    ),
                    matched_text=match.group(0)[:200],
                    position=match.start(),
                )
            )

        # 3. Encoding attacks
        for pattern_name, severity, regex in _ENCODING_ATTACKS:
            for match in regex.finditer(scan_content):
                findings.append(
                    StdioFinding(
                        category="encoding_attack",
                        severity=severity,
                        detail=f"Encoding attack pattern '{pattern_name}' detected",
                        matched_text=repr(match.group(0))[:100],
                        position=match.start(),
                    )
                )

        # 4. Content-Length header smuggling
        for match in _CONTENT_LENGTH_PATTERN.finditer(scan_content):
            findings.append(
                StdioFinding(
                    category="request_smuggling",
                    severity="high",
                    detail=(
                        "Content-Length header in tool output — possible HTTP request smuggling"
                    ),
                    matched_text=match.group(0)[:100],
                    position=match.start(),
                )
            )

        has_injection = len(findings) > 0
        elapsed_ms = (time.perf_counter() - start) * 1000

        # Generate sanitized content if injection detected
        sanitized = None
        if has_injection:
            sanitized = self._sanitize(scan_content)
            if truncated:
                sanitized = sanitized  # Already truncated

        return StdioScanResult(
            has_injection=has_injection,
            findings=findings,
            sanitized_content=sanitized,
            scan_time_ms=elapsed_ms,
        )

    def _sanitize(self, content: str) -> str:
        """Neutralize injection patterns in content.

        Breaks ALL JSON-RPC-identifiable patterns so they cannot be
        parsed as valid messages by ANY downstream consumer.
        """
        sanitized = content

        # 1. Break "jsonrpc" key (literal and unicode-escaped variants)
        sanitized = sanitized.replace('"jsonrpc"', '"_blocked_jsonrpc"')
        sanitized = re.sub(
            r"\\u006[aA]sonrpc",
            "_blocked_jsonrpc",
            sanitized,
        )

        # 2. Break MCP method patterns that could trigger client actions
        sanitized = re.sub(
            r'"method"\s*:\s*"(tools/|resources/|prompts/|notifications/|initialize)',
            '"_blocked_method": "_\\1',
            sanitized,
        )

        # 3. Neutralize frame boundaries (newline + opening brace)
        sanitized = re.sub(
            r"(\r?\n)(\s*\{)",
            r"\1/* aegis-blocked */\2",
            sanitized,
        )

        # 4. Remove null bytes
        sanitized = sanitized.replace("\x00", "")
        # 5. Replace unicode line separators with standard newlines
        sanitized = sanitized.replace("\u2028", "\n").replace("\u2029", "\n")
        return sanitized


# ---------------------------------------------------------------------------
# StdioFrameValidator
# ---------------------------------------------------------------------------


class StdioFrameValidator:
    """Validate raw STDIO frames for message integrity.

    Ensures each frame contains exactly one well-formed JSON-RPC message
    and detects attempts to inject additional messages through framing
    manipulation.

    The MCP STDIO transport uses newline-delimited JSON. Each line should
    be exactly one JSON-RPC message. This validator ensures that constraint.
    """

    def __init__(
        self,
        *,
        max_message_size: int = 50 * 1024 * 1024,  # 50MB per MCP spec
        burst_window_seconds: float = 1.0,
        burst_threshold: int = 100,
    ) -> None:
        """Initialize the frame validator.

        Args:
            max_message_size: Maximum allowed size for a single message.
            burst_window_seconds: Time window for burst detection.
            burst_threshold: Max messages in burst window before flagging.
        """
        self._max_size = max_message_size
        self._burst_window = burst_window_seconds
        self._burst_threshold = burst_threshold
        self._message_times: list[float] = []

    def validate_frame(self, raw: bytes | str) -> FrameValidation:
        """Validate a single STDIO frame (one line from the stream).

        Args:
            raw: Raw bytes or string from the STDIO stream.

        Returns:
            FrameValidation indicating whether the frame is valid.
        """
        if isinstance(raw, bytes):
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                return FrameValidation(
                    valid=False,
                    reason="Frame contains invalid UTF-8 — possible encoding attack",
                )
        else:
            text = raw

        # Strip trailing newline (the delimiter)
        text = text.rstrip("\r\n")

        if not text:
            return FrameValidation(valid=True, reason="Empty frame (keepalive)")

        # Size check
        if len(text.encode("utf-8")) > self._max_size:
            return FrameValidation(
                valid=False,
                reason=f"Frame exceeds maximum size ({self._max_size} bytes)",
            )

        # Must be valid JSON
        try:
            msg = json.loads(text)
        except json.JSONDecodeError as e:
            # "Extra data" means multiple JSON values concatenated
            if "Extra data" in str(e):
                obj_count = self._count_json_objects(text)
                return FrameValidation(
                    valid=False,
                    reason=(
                        f"Frame contains {obj_count} concatenated"
                        " JSON objects — injection detected"
                    ),
                    message_count=1,
                    injected_count=max(0, obj_count - 1),
                )
            return FrameValidation(
                valid=False,
                reason=f"Frame is not valid JSON: {e}",
            )

        # Must be a JSON object (not array or primitive)
        if not isinstance(msg, dict):
            return FrameValidation(
                valid=False,
                reason=f"Frame is not a JSON object (got {type(msg).__name__})",
            )

        # Must have "jsonrpc": "2.0"
        if msg.get("jsonrpc") != "2.0":
            return FrameValidation(
                valid=False,
                reason='Frame missing or invalid "jsonrpc": "2.0" field',
            )

        # NOTE: If json.loads succeeded without "Extra data" error,
        # the frame contains exactly 1 JSON object — no need to re-count.
        # Concatenated objects are caught in the JSONDecodeError handler above.

        # Burst detection
        now = time.time()
        self._message_times.append(now)
        # Prune old entries
        cutoff = now - self._burst_window
        self._message_times = [t for t in self._message_times if t > cutoff]
        if len(self._message_times) > self._burst_threshold:
            return FrameValidation(
                valid=False,
                reason=(
                    f"Message burst detected: {len(self._message_times)} messages "
                    f"in {self._burst_window}s (threshold: {self._burst_threshold})"
                ),
            )

        return FrameValidation(valid=True)

    def _count_json_objects(self, text: str) -> int:
        """Count the number of top-level JSON objects in a string.

        Uses a brace-depth counter to find object boundaries.
        """
        count = 0
        depth = 0
        in_string = False
        escape_next = False
        i = 0

        while i < len(text):
            ch = text[i]

            if escape_next:
                escape_next = False
                i += 1
                continue

            if ch == "\\" and in_string:
                escape_next = True
                i += 1
                continue

            if ch == '"' and not escape_next:
                in_string = not in_string
                i += 1
                continue

            if in_string:
                i += 1
                continue

            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    count += 1

            i += 1

        return count

    def reset_burst_counter(self) -> None:
        """Reset the burst detection counter."""
        self._message_times.clear()


# ---------------------------------------------------------------------------
# StdioGuard — unified guard
# ---------------------------------------------------------------------------


class StdioGuard:
    """Unified STDIO injection guard for MCP transport.

    Combines content scanning and frame validation into a single
    interface. Use this as the primary entry point for STDIO protection.

    Example::

        guard = StdioGuard()

        # Protect tool responses (content-level)
        result = guard.scan_content(tool_response_text)
        if result.has_injection:
            # Block or sanitize
            safe_content = result.sanitized_content

        # Protect raw STDIO frames (transport-level)
        frame_result = guard.validate_frame(raw_line)
        if not frame_result.valid:
            # Drop the frame
            log.warning("Dropped frame: %s", frame_result.reason)
    """

    def __init__(
        self,
        *,
        allow_jsonrpc_in_content: bool = False,
        max_content_length: int = 10 * 1024 * 1024,
        max_message_size: int = 50 * 1024 * 1024,
        burst_window_seconds: float = 1.0,
        burst_threshold: int = 100,
        auto_sanitize: bool = True,
    ) -> None:
        """Initialize the STDIO guard.

        Args:
            allow_jsonrpc_in_content: Allow JSON-RPC patterns in content
                (for documentation tools that return examples).
            max_content_length: Max content size to scan (bytes).
            max_message_size: Max STDIO frame size (bytes).
            burst_window_seconds: Time window for burst detection.
            burst_threshold: Max messages per burst window.
            auto_sanitize: If True, always generate sanitized content
                when injection is detected.
        """
        self._scanner = StdioInjectionScanner(
            allow_jsonrpc_in_content=allow_jsonrpc_in_content,
            max_content_length=max_content_length,
        )
        self._validator = StdioFrameValidator(
            max_message_size=max_message_size,
            burst_window_seconds=burst_window_seconds,
            burst_threshold=burst_threshold,
        )
        self._auto_sanitize = auto_sanitize

        # Statistics
        self._total_scans: int = 0
        self._total_blocked: int = 0
        self._total_frames: int = 0
        self._total_invalid_frames: int = 0

    def scan_content(self, content: str, *, tool_name: str = "") -> StdioScanResult:
        """Scan tool response content for injection patterns.

        Args:
            content: Text content from a tool response.
            tool_name: Tool name for context in findings.

        Returns:
            StdioScanResult with findings and optional sanitized content.
        """
        self._total_scans += 1
        result = self._scanner.scan(content, tool_name=tool_name)
        if result.has_injection:
            self._total_blocked += 1
            logger.warning(
                "[aegis] STDIO injection detected in tool '%s': %d findings "
                "(%d critical, %d high)",
                tool_name or "unknown",
                len(result.findings),
                result.critical_count,
                result.high_count,
            )
        return result

    def validate_frame(self, raw: bytes | str) -> FrameValidation:
        """Validate a raw STDIO frame.

        Args:
            raw: Raw bytes or string from the STDIO stream.

        Returns:
            FrameValidation indicating frame integrity.
        """
        self._total_frames += 1
        result = self._validator.validate_frame(raw)
        if not result.valid:
            self._total_invalid_frames += 1
            logger.warning("[aegis] Invalid STDIO frame: %s", result.reason)
        return result

    def scan_jsonrpc_result(
        self,
        message: dict[str, Any],
        *,
        tool_name: str = "",
    ) -> StdioScanResult:
        """Scan a parsed JSON-RPC result message for injection in content fields.

        This scans the content/text fields within a tools/call response
        AFTER JSON parsing but BEFORE forwarding to the client.

        Args:
            message: Parsed JSON-RPC response message.
            tool_name: Tool name for context.

        Returns:
            StdioScanResult aggregating findings from all content fields.
        """
        all_findings: list[StdioFinding] = []
        start = time.perf_counter()

        # Extract text content from MCP tool response format
        result = message.get("result", {})
        content_list = result.get("content", [])

        if isinstance(content_list, list):
            for item in content_list:
                if isinstance(item, dict) and item.get("type") == "text":
                    text = item.get("text", "")
                    if text:
                        scan = self._scanner.scan(text, tool_name=tool_name)
                        all_findings.extend(scan.findings)

        has_injection = len(all_findings) > 0
        elapsed_ms = (time.perf_counter() - start) * 1000

        if has_injection:
            self._total_blocked += 1

        return StdioScanResult(
            has_injection=has_injection,
            findings=all_findings,
            scan_time_ms=elapsed_ms,
        )

    @property
    def stats(self) -> dict[str, int]:
        """Return guard statistics."""
        return {
            "total_scans": self._total_scans,
            "total_blocked": self._total_blocked,
            "total_frames": self._total_frames,
            "total_invalid_frames": self._total_invalid_frames,
        }

    def reset_stats(self) -> None:
        """Reset all counters."""
        self._total_scans = 0
        self._total_blocked = 0
        self._total_frames = 0
        self._total_invalid_frames = 0
        self._validator.reset_burst_counter()
