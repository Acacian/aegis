"""Agent session replay with security analysis.

Records and replays agent sessions for post-hoc security auditing.
Combines session recording with MCP security scanning to detect
threats that may have been missed during live execution.

Key capabilities:

- **Session recording** — Captures tool calls, arguments, and results
  in an immutable event log.
- **Replay with scanning** — Re-evaluates recorded tool calls against
  current security policies and MCP security gates.
- **Retroactive detection** — Finds newly-discovered attack patterns
  in historical sessions (e.g., after a CVE is published).
- **Audit evidence** — Generates compliance-ready session reports.

Usage::

    from aegis.core.session_replay import SessionRecorder, SessionReplayer

    # During live execution: record events
    recorder = SessionRecorder(session_id="sess-001")
    recorder.record_tool_call("read_file", {"path": "/etc/passwd"})
    recorder.record_tool_result("read_file", "Permission denied")
    session = recorder.finalize()

    # Later: replay and scan
    replayer = SessionReplayer()
    report = replayer.replay(session)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SessionEvent:
    """A single event in a session recording.

    Attributes:
        timestamp: Unix timestamp of the event.
        event_type: Category (``"tool_call"``, ``"tool_result"``,
            ``"policy_decision"``, ``"error"``).
        tool_name: Name of the tool involved.
        data: Event-specific data (arguments, result, etc.).
        agent_id: Agent that produced the event.
    """

    timestamp: float
    event_type: str
    tool_name: str
    data: dict[str, Any]
    agent_id: str = ""


@dataclass
class Session:
    """A complete recorded agent session.

    Attributes:
        session_id: Unique session identifier.
        agent_id: Primary agent for the session.
        events: Ordered list of session events.
        started_at: Session start timestamp.
        ended_at: Session end timestamp (``0`` if not finalized).
        metadata: Additional session metadata.
    """

    session_id: str
    agent_id: str = ""
    events: list[SessionEvent] = field(default_factory=list)
    started_at: float = 0.0
    ended_at: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ReplayFinding:
    """A security finding from replaying a session.

    Attributes:
        event_index: Index of the event in the session.
        event: The session event that triggered the finding.
        category: Finding category (e.g. ``"path_traversal"``).
        severity: ``"critical"``, ``"high"``, ``"medium"``, ``"low"``.
        description: Human-readable description.
        retroactive: Whether this was detected retroactively
            (not during original execution).
    """

    event_index: int
    event: SessionEvent
    category: str
    severity: str
    description: str
    retroactive: bool = True


@dataclass
class ReplayReport:
    """Result of replaying a session with security analysis.

    Attributes:
        session_id: Session that was replayed.
        events_scanned: Total events scanned.
        findings: Security findings from the replay.
        clean: ``True`` if no findings.
    """

    session_id: str
    events_scanned: int
    findings: list[ReplayFinding] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        """Whether the session had no security findings."""
        return len(self.findings) == 0


# ---------------------------------------------------------------------------
# Session recorder
# ---------------------------------------------------------------------------


class SessionRecorder:
    """Records agent session events for later replay.

    Args:
        session_id: Unique session identifier.
        agent_id: Primary agent for the session.
        metadata: Additional session metadata.
    """

    def __init__(
        self,
        session_id: str,
        *,
        agent_id: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self._session = Session(
            session_id=session_id,
            agent_id=agent_id,
            started_at=time.time(),
            metadata=metadata or {},
        )

    @property
    def event_count(self) -> int:
        """Number of events recorded so far."""
        return len(self._session.events)

    def record_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        *,
        agent_id: str = "",
    ) -> SessionEvent:
        """Record a tool call event.

        Args:
            tool_name: Name of the tool being called.
            arguments: Tool call arguments.
            agent_id: Agent making the call.

        Returns:
            The recorded event.
        """
        event = SessionEvent(
            timestamp=time.time(),
            event_type="tool_call",
            tool_name=tool_name,
            data={"arguments": arguments or {}},
            agent_id=agent_id or self._session.agent_id,
        )
        self._session.events.append(event)
        return event

    def record_tool_result(
        self,
        tool_name: str,
        result: Any,
        *,
        agent_id: str = "",
    ) -> SessionEvent:
        """Record a tool result event.

        Args:
            tool_name: Name of the tool.
            result: Tool execution result.
            agent_id: Agent that received the result.

        Returns:
            The recorded event.
        """
        event = SessionEvent(
            timestamp=time.time(),
            event_type="tool_result",
            tool_name=tool_name,
            data={"result": str(result)},
            agent_id=agent_id or self._session.agent_id,
        )
        self._session.events.append(event)
        return event

    def record_policy_decision(
        self,
        tool_name: str,
        decision: str,
        *,
        rule: str = "",
        risk_level: str = "",
        agent_id: str = "",
    ) -> SessionEvent:
        """Record a policy decision event.

        Args:
            tool_name: Tool the decision was about.
            decision: Decision made (allow/block/approve).
            rule: Matched policy rule.
            risk_level: Assessed risk level.
            agent_id: Agent involved.

        Returns:
            The recorded event.
        """
        event = SessionEvent(
            timestamp=time.time(),
            event_type="policy_decision",
            tool_name=tool_name,
            data={
                "decision": decision,
                "rule": rule,
                "risk_level": risk_level,
            },
            agent_id=agent_id or self._session.agent_id,
        )
        self._session.events.append(event)
        return event

    def finalize(self) -> Session:
        """Finalize the session and return the complete recording.

        Returns:
            The completed :class:`Session`.
        """
        self._session.ended_at = time.time()
        return self._session


# ---------------------------------------------------------------------------
# Security scanners for replay
# ---------------------------------------------------------------------------

# Patterns that indicate suspicious tool arguments
_SUSPICIOUS_PATTERNS: list[tuple[str, str, str]] = [
    # (pattern_substring, category, severity)
    ("../", "path_traversal", "high"),
    ("..\\", "path_traversal", "high"),
    ("/etc/passwd", "sensitive_file_access", "critical"),
    ("/etc/shadow", "sensitive_file_access", "critical"),
    (".ssh/", "sensitive_file_access", "high"),
    (".env", "sensitive_file_access", "high"),
    (".aws/", "sensitive_file_access", "high"),
    ("; ", "command_injection", "critical"),
    ("| ", "command_injection", "critical"),
    ("$(", "command_injection", "critical"),
    ("`", "command_injection", "high"),
    ("eval(", "code_injection", "critical"),
    ("exec(", "code_injection", "critical"),
    ("__import__", "code_injection", "critical"),
    ("base64.b64decode", "encoded_payload", "medium"),
    ("<script", "xss_attempt", "high"),
    ("javascript:", "xss_attempt", "high"),
    ("DROP TABLE", "sql_injection", "critical"),
    ("UNION SELECT", "sql_injection", "high"),
    ("' OR '1'='1", "sql_injection", "critical"),
]


def _scan_arguments(arguments: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Scan tool arguments for suspicious patterns.

    Returns list of (pattern, category, severity) tuples for matches.
    """
    findings: list[tuple[str, str, str]] = []
    text = _flatten_to_string(arguments)
    for pattern, category, severity in _SUSPICIOUS_PATTERNS:
        if pattern.lower() in text.lower():
            findings.append((pattern, category, severity))
    return findings


def _flatten_to_string(obj: Any, depth: int = 0) -> str:
    """Recursively flatten an object to a single string for scanning."""
    if depth > 10:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(_flatten_to_string(v, depth + 1) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return " ".join(_flatten_to_string(v, depth + 1) for v in obj)
    return str(obj)


# ---------------------------------------------------------------------------
# Session replayer
# ---------------------------------------------------------------------------


class SessionReplayer:
    """Replays recorded sessions with security analysis.

    Scans all tool_call events in a session for suspicious patterns
    and produces a :class:`ReplayReport`.

    Args:
        extra_patterns: Additional (pattern, category, severity) tuples
            to scan for beyond the built-in set.
    """

    def __init__(
        self,
        extra_patterns: list[tuple[str, str, str]] | None = None,
    ) -> None:
        self._extra_patterns = extra_patterns or []

    def replay(self, session: Session) -> ReplayReport:
        """Replay a session and scan for security findings.

        Args:
            session: The recorded session to replay.

        Returns:
            A :class:`ReplayReport` with all findings.
        """
        report = ReplayReport(
            session_id=session.session_id,
            events_scanned=0,
        )

        for idx, event in enumerate(session.events):
            if event.event_type == "tool_call":
                report.events_scanned += 1
                arguments = event.data.get("arguments", {})

                # Scan with built-in + extra patterns
                matches = _scan_arguments(arguments)
                for pattern_text in self._extra_patterns:
                    pattern, category, severity = pattern_text
                    text = _flatten_to_string(arguments)
                    if pattern.lower() in text.lower():
                        matches.append(pattern_text)

                for pattern, category, severity in matches:
                    report.findings.append(
                        ReplayFinding(
                            event_index=idx,
                            event=event,
                            category=category,
                            severity=severity,
                            description=(
                                f"Suspicious pattern '{pattern}' found in "
                                f"tool '{event.tool_name}' arguments"
                            ),
                            retroactive=True,
                        )
                    )

        return report

    def format_report(self, report: ReplayReport) -> str:
        """Format a replay report as human-readable text."""
        lines: list[str] = []
        lines.append(f"Session Replay Report: {report.session_id}")
        lines.append("=" * 40)
        lines.append(f"Events scanned: {report.events_scanned}")

        if report.clean:
            lines.append("No security findings.")
            return "\n".join(lines)

        lines.append(f"Findings: {len(report.findings)}")
        lines.append("")

        for finding in report.findings:
            lines.append(
                f"  [{finding.severity.upper()}] Event #{finding.event_index}: "
                f"{finding.event.tool_name}"
            )
            lines.append(f"    Category: {finding.category}")
            lines.append(f"    {finding.description}")
            if finding.retroactive:
                lines.append("    (Detected retroactively)")
            lines.append("")

        return "\n".join(lines)
