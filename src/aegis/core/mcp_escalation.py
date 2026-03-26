"""MCP cross-server escalation detection.

Detects when an AI agent chains tool calls across multiple MCP servers
to escalate privileges — e.g., reading credentials from one server and
relaying them to an external endpoint via another.

Components:
    - EscalationRule: Defines a dangerous source→sink tool call pattern
    - ToolCallRecord: Immutable record of a single observed tool call
    - EscalationFinding: A detected escalation chain with timing data
    - EscalationDetector: Sliding-window tracker that evaluates each new
      tool call against known escalation patterns

Example::

    detector = EscalationDetector()
    findings = detector.record_and_check(
        "filesystem.read_file", "filesystem", {"path": "/etc/passwd"}
    )
    assert findings == []
    findings = detector.record_and_check(
        "slack.send_message", "slack", {"text": "exfil data"}
    )
    assert len(findings) >= 1  # data_exfil_filesystem triggered
"""

from __future__ import annotations

import fnmatch
import threading
import time
from dataclasses import dataclass
from typing import Any

from aegis.core.mcp_security import Severity

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EscalationRule:
    """Defines a dangerous cross-server tool call chain.

    Attributes:
        name: Unique identifier for the rule.
        description: Human-readable explanation of the attack pattern.
        severity: Finding severity (from :class:`Severity`).
        source_pattern: Glob pattern matching source tool names
            (e.g. ``"filesystem.*"``, ``"*.read_*"``).
        sink_pattern: Glob pattern matching sink tool names
            (e.g. ``"slack.*"``, ``"*.send_*"``).
        data_flow: Label for the data-flow category
            (e.g. ``"read_to_send"``, ``"cred_to_fetch"``).
        source_arg_pattern: Optional glob pattern applied to stringified
            source-call arguments. When set, the rule only fires if at
            least one argument value matches (e.g. ``"*.env*"``).
        sink_arg_pattern: Optional glob applied to sink-call arguments.
        min_source_count: Minimum number of matching source calls required
            in the window before the rule can fire. Default is 1; set
            higher to detect bulk-read-then-send patterns.
        cross_server_only: When *True* (default) the rule only fires when
            source and sink come from **different** MCP servers.
    """

    name: str
    description: str
    severity: str
    source_pattern: str
    sink_pattern: str
    data_flow: str
    source_arg_pattern: str | None = None
    sink_arg_pattern: str | None = None
    min_source_count: int = 1
    cross_server_only: bool = True


@dataclass(frozen=True)
class ToolCallRecord:
    """Record of a single tool call for chain tracking.

    Attributes:
        tool_name: Fully-qualified tool name (e.g. ``"filesystem.read_file"``).
        server_name: Name of the MCP server that owns the tool.
        arguments: Argument dict passed to the tool call.
        timestamp: ``time.monotonic()`` value when the call was recorded.
        session_id: Logical session that owns this call.
    """

    tool_name: str
    server_name: str
    arguments: dict[str, Any]
    timestamp: float
    session_id: str


@dataclass(frozen=True)
class EscalationFinding:
    """A detected escalation pattern.

    Attributes:
        rule: The :class:`EscalationRule` that matched.
        source_call: The most recent matching source call.
        sink_call: The sink call that completed the chain.
        time_delta_ms: Milliseconds between source and sink.
        detail: Human-readable explanation of the finding.
    """

    rule: EscalationRule
    source_call: ToolCallRecord
    sink_call: ToolCallRecord
    time_delta_ms: float
    detail: str


# ---------------------------------------------------------------------------
# Pattern matching helpers
# ---------------------------------------------------------------------------


def _match_tool(pattern: str, tool_name: str) -> bool:
    """Match a tool name against a glob pattern.

    Supports pipe-separated alternatives inside parentheses:
    ``"(slack|email|fetch).send"`` expands into three individual fnmatch
    checks.
    """
    return any(fnmatch.fnmatch(tool_name, expanded) for expanded in _expand_pattern(pattern))


def _expand_pattern(pattern: str) -> list[str]:
    """Expand ``(a|b).suffix`` into ``["a.suffix", "b.suffix"]``.

    Returns a single-element list when there is nothing to expand.
    """
    import re

    m = re.search(r"\(([^)]+)\)", pattern)
    if not m:
        return [pattern]
    prefix = pattern[: m.start()]
    suffix = pattern[m.end() :]
    alternatives = m.group(1).split("|")
    return [f"{prefix}{alt}{suffix}" for alt in alternatives]


def _match_args(pattern: str, arguments: dict[str, Any]) -> bool:
    """Return *True* if any string value in *arguments* matches *pattern*."""
    return any(fnmatch.fnmatch(value, pattern) for value in _iter_strings(arguments))


def _iter_strings(obj: Any, depth: int = 0) -> list[str]:
    """Recursively extract string values from a nested structure."""
    if depth > 10:
        return []
    result: list[str] = []
    if isinstance(obj, str):
        result.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            result.extend(_iter_strings(v, depth + 1))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            result.extend(_iter_strings(v, depth + 1))
    return result


# ---------------------------------------------------------------------------
# Built-in rules
# ---------------------------------------------------------------------------

_BUILTIN_RULES: list[EscalationRule] = [
    # 1. data_exfil_filesystem
    EscalationRule(
        name="data_exfil_filesystem",
        description=(
            "File system read followed by a send/post via messaging or HTTP — "
            "potential data exfiltration."
        ),
        severity=Severity.CRITICAL,
        source_pattern="filesystem.*",
        sink_pattern="(slack|email|fetch).*",
        data_flow="read_to_send",
    ),
    # 2. data_exfil_database
    EscalationRule(
        name="data_exfil_database",
        description=(
            "Database query followed by a send/post via messaging or HTTP — "
            "potential PII exfiltration."
        ),
        severity=Severity.CRITICAL,
        source_pattern="database.*",
        sink_pattern="(slack|email|fetch).*",
        data_flow="query_to_external",
    ),
    # 3. cred_relay
    EscalationRule(
        name="cred_relay",
        description=(
            "Credential or config read followed by an external HTTP request — "
            "potential credential relay."
        ),
        severity=Severity.HIGH,
        source_pattern="(filesystem|git|memory).*",
        sink_pattern="fetch.*",
        data_flow="cred_to_fetch",
    ),
    # 4. config_then_destroy
    EscalationRule(
        name="config_then_destroy",
        description=(
            "Read operation followed by a destructive action (delete/drop) — "
            "recon-then-destroy pattern."
        ),
        severity=Severity.CRITICAL,
        source_pattern="*.read_*",
        sink_pattern="*.*",
        sink_arg_pattern="*",
        data_flow="read_then_destroy",
        cross_server_only=False,
    ),
    # 5. memory_to_external
    EscalationRule(
        name="memory_to_external",
        description=(
            "Memory/state access followed by an external channel — session data theft risk."
        ),
        severity=Severity.HIGH,
        source_pattern="memory.*",
        sink_pattern="(fetch|slack|email).*",
        data_flow="memory_to_external",
    ),
    # 6. env_exfil
    EscalationRule(
        name="env_exfil",
        description=(
            "Reading a .env file followed by a send/post/request — "
            "environment secret exfiltration."
        ),
        severity=Severity.CRITICAL,
        source_pattern="*.read_file",
        sink_pattern="*.*",
        source_arg_pattern="*.env*",
        data_flow="env_to_external",
        cross_server_only=False,
    ),
    # 7. bulk_read_then_send
    EscalationRule(
        name="bulk_read_then_send",
        description=("Three or more read operations followed by a send — bulk data exfiltration."),
        severity=Severity.HIGH,
        source_pattern="*.read_*",
        sink_pattern="*.send_*",
        data_flow="bulk_read_to_send",
        min_source_count=3,
        cross_server_only=False,
    ),
    # 8. git_secret_relay
    EscalationRule(
        name="git_secret_relay",
        description=(
            "Git operation followed by an external fetch or messaging call — "
            "potential secret relay from repository."
        ),
        severity=Severity.HIGH,
        source_pattern="git.*",
        sink_pattern="(fetch|slack).*",
        data_flow="git_to_external",
    ),
    # 9. db_dump_exfil
    EscalationRule(
        name="db_dump_exfil",
        description=(
            "Broad database query (SELECT *) followed by a file write or "
            "send — database dump exfiltration."
        ),
        severity=Severity.CRITICAL,
        source_pattern="database.query",
        sink_pattern="*.*",
        source_arg_pattern="*SELECT [*]*",
        data_flow="db_dump_to_external",
        cross_server_only=False,
    ),
    # 10. permission_probe_then_act
    EscalationRule(
        name="permission_probe_then_act",
        description=(
            "Permission or listing probe followed by an execute or admin "
            "action — privilege escalation recon."
        ),
        severity=Severity.HIGH,
        source_pattern="*.*",
        sink_pattern="*.*",
        data_flow="probe_then_act",
        cross_server_only=False,
    ),
]


def _is_destructive_tool(tool_name: str) -> bool:
    """Check if a tool name looks destructive (delete/drop)."""
    lower = tool_name.lower()
    return any(kw in lower for kw in ("delete_", "drop_", ".delete", ".drop"))


def _is_probe_tool(tool_name: str) -> bool:
    """Check if a tool name looks like a permission or listing probe."""
    lower = tool_name.lower()
    return any(kw in lower for kw in ("list_", "get_permissions", ".list_", ".get_permissions"))


def _is_admin_or_execute_tool(tool_name: str) -> bool:
    """Check if a tool name looks like an execute or admin action."""
    lower = tool_name.lower()
    return any(kw in lower for kw in ("execute", "admin"))


def _is_send_or_write_tool(tool_name: str) -> bool:
    """Check if a tool name looks like a send or write action."""
    lower = tool_name.lower()
    return any(
        kw in lower
        for kw in (
            ".send",
            "send_",
            ".post",
            "post_",
            ".request",
            ".write_file",
            "write_file",
        )
    )


# ---------------------------------------------------------------------------
# Escalation Detector
# ---------------------------------------------------------------------------


class EscalationDetector:
    """Tracks tool call sequences and detects cross-server privilege escalation.

    Maintains a sliding window of recent tool calls per session and
    evaluates each new call against known escalation patterns.

    The detector is **thread-safe**: concurrent calls to
    :meth:`record_and_check` on different (or the same) sessions are
    serialised via an internal lock.
    """

    def __init__(
        self,
        *,
        rules: list[EscalationRule] | None = None,
        window_seconds: float = 300.0,
        max_history: int = 100,
    ) -> None:
        """Initialise the detector.

        Args:
            rules: Escalation rules to evaluate. *None* (default) uses
                :meth:`builtin_rules`.
            window_seconds: Sliding window in seconds. Source calls older
                than this are ignored.
            max_history: Maximum tool call records kept per session.
                Oldest records are evicted first.
        """
        self._rules: list[EscalationRule] = rules if rules is not None else self.builtin_rules()
        self._window: float = window_seconds
        self._max_history: int = max_history
        self._sessions: dict[str, list[ToolCallRecord]] = {}
        self._lock = threading.Lock()

    # -- public API ----------------------------------------------------------

    def record_and_check(
        self,
        tool_name: str,
        server_name: str,
        arguments: dict[str, Any],
        *,
        session_id: str = "default",
    ) -> list[EscalationFinding]:
        """Record a tool call and check for escalation patterns.

        The call is appended to the session history, stale entries are
        pruned, and every rule is evaluated. Returns a (possibly empty)
        list of findings if the new call completes a dangerous chain.

        Args:
            tool_name: Fully-qualified tool name (e.g. ``"filesystem.read_file"``).
            server_name: MCP server that owns the tool.
            arguments: Arguments passed to the tool call.
            session_id: Logical session identifier.

        Returns:
            List of :class:`EscalationFinding` instances for every rule
            triggered by this call (empty if clean).
        """
        now = time.monotonic()
        record = ToolCallRecord(
            tool_name=tool_name,
            server_name=server_name,
            arguments=arguments,
            timestamp=now,
            session_id=session_id,
        )

        with self._lock:
            history = self._sessions.setdefault(session_id, [])
            history.append(record)

            # Prune stale entries
            cutoff = now - self._window
            self._sessions[session_id] = [r for r in history if r.timestamp >= cutoff]
            history = self._sessions[session_id]

            # Enforce max_history
            if len(history) > self._max_history:
                self._sessions[session_id] = history[-self._max_history :]
                history = self._sessions[session_id]

            return self._evaluate(record, history)

    def get_history(self, session_id: str) -> list[ToolCallRecord]:
        """Get recent tool call history for a session.

        Args:
            session_id: Logical session identifier.

        Returns:
            Shallow copy of the session's call history (oldest first).
            Empty list if the session has no recorded calls.
        """
        with self._lock:
            return list(self._sessions.get(session_id, []))

    def clear_session(self, session_id: str) -> None:
        """Clear tracking for a session.

        Args:
            session_id: Logical session identifier to remove.
        """
        with self._lock:
            self._sessions.pop(session_id, None)

    @staticmethod
    def builtin_rules() -> list[EscalationRule]:
        """Return the default set of escalation rules.

        Returns:
            A copy of the built-in rule list so callers can safely
            mutate it.
        """
        return list(_BUILTIN_RULES)

    # -- internal evaluation -------------------------------------------------

    def _evaluate(
        self,
        new_call: ToolCallRecord,
        history: list[ToolCallRecord],
    ) -> list[EscalationFinding]:
        """Evaluate all rules against the new call and session history."""
        findings: list[EscalationFinding] = []

        for rule in self._rules:
            finding = self._check_rule(rule, new_call, history)
            if finding is not None:
                findings.append(finding)

        return findings

    def _check_rule(
        self,
        rule: EscalationRule,
        new_call: ToolCallRecord,
        history: list[ToolCallRecord],
    ) -> EscalationFinding | None:
        """Check a single rule. Returns a finding or *None*."""

        # Special handling for rules with semantic sink checks
        if rule.name == "config_then_destroy":
            if not _is_destructive_tool(new_call.tool_name):
                return None
        elif rule.name == "permission_probe_then_act":
            if not _is_admin_or_execute_tool(new_call.tool_name):
                return None
        elif rule.name == "env_exfil" or rule.name == "db_dump_exfil":
            if not _is_send_or_write_tool(new_call.tool_name):
                return None
        else:
            # Standard sink pattern match
            if not _match_tool(rule.sink_pattern, new_call.tool_name):
                return None

        # Sink argument pattern (if specified)
        if (
            rule.sink_arg_pattern is not None
            and rule.name
            not in (
                "config_then_destroy",
                "env_exfil",
                "db_dump_exfil",
                "permission_probe_then_act",
            )
            and not _match_args(rule.sink_arg_pattern, new_call.arguments)
        ):
            return None

        # Collect matching source calls (excluding the new call itself)
        source_calls: list[ToolCallRecord] = []
        for rec in history:
            if rec is new_call:
                continue

            # Source tool pattern
            if rule.name == "permission_probe_then_act":
                if not _is_probe_tool(rec.tool_name):
                    continue
            else:
                if not _match_tool(rule.source_pattern, rec.tool_name):
                    continue

            # Cross-server constraint
            if rule.cross_server_only and rec.server_name == new_call.server_name:
                continue

            # Source argument pattern (if specified)
            if rule.source_arg_pattern is not None and not _match_args(
                rule.source_arg_pattern, rec.arguments
            ):
                continue

            source_calls.append(rec)

        if len(source_calls) < rule.min_source_count:
            return None

        # Use the most recent matching source call for the finding
        best_source = source_calls[-1]
        delta_ms = (new_call.timestamp - best_source.timestamp) * 1000.0

        return EscalationFinding(
            rule=rule,
            source_call=best_source,
            sink_call=new_call,
            time_delta_ms=delta_ms,
            detail=(
                f"[{rule.severity}] {rule.name}: "
                f"{best_source.tool_name} ({best_source.server_name}) → "
                f"{new_call.tool_name} ({new_call.server_name}) "
                f"within {delta_ms:.0f}ms — {rule.description}"
            ),
        )
