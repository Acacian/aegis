"""MCP security audit dashboard.

Terminal-based security audit dashboard that collects and presents
real-time MCP security status. Provides a single-pane-of-glass view of:

- Active servers and their trust levels
- Recent tool calls and their governance decisions
- Active escalation patterns
- Rate limit status and shadow conflicts
- Response scan findings

The ``MCPAuditDashboard`` class is the data model / collector layer.
Rendering is handled by ``render_text()`` (full dashboard),
``render_compact()`` (one-line summary), and ``to_dict()`` (JSON API).

Example::

    dash = MCPAuditDashboard()
    dash.register_server("filesystem", 4, "L3_VERIFIED")
    dash.record_call("read_file", "filesystem", decision="allowed")
    dash.record_alert("high", "shadow", "duplicate tool 'search'")
    print(dash.render_text())
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ServerStatus:
    """Status of a single MCP server."""

    server_name: str
    tool_count: int
    trust_level: str  # L0-L4
    calls_last_minute: int = 0
    calls_last_hour: int = 0
    blocked_count: int = 0
    shadow_conflicts: int = 0
    is_healthy: bool = True


@dataclass
class CallRecord:
    """Record of a tool call for dashboard display."""

    timestamp: float
    tool_name: str
    server_name: str
    decision: str  # "allowed", "blocked", "rate_limited", "consent_required"
    risk_level: str
    findings_count: int
    session_id: str


@dataclass
class Alert:
    """Security alert for dashboard display."""

    alert_id: str
    timestamp: float
    severity: str  # "critical", "high", "medium", "low"
    category: str  # "escalation", "shadow", "response_injection", "rate_limit_burst", "rug_pull"
    detail: str
    server_name: str
    tool_name: str
    resolved: bool = False


@dataclass
class DashboardStats:
    """Aggregate statistics."""

    total_calls: int = 0
    total_blocked: int = 0
    total_allowed: int = 0
    block_rate_percent: float = 0.0
    escalation_count: int = 0
    shadow_count: int = 0
    response_findings_count: int = 0
    uptime_seconds: float = 0.0


@dataclass
class DashboardState:
    """Current state of the MCP security dashboard."""

    servers: dict[str, ServerStatus] = field(default_factory=dict)
    recent_calls: list[CallRecord] = field(default_factory=list)
    active_alerts: list[Alert] = field(default_factory=list)
    stats: DashboardStats = field(default_factory=DashboardStats)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

_VALID_DECISIONS = {"allowed", "blocked", "rate_limited", "consent_required"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_CATEGORIES = {
    "escalation",
    "shadow",
    "response_injection",
    "rate_limit_burst",
    "rug_pull",
}


class MCPAuditDashboard:
    """Collects and presents MCP security audit data.

    This is the data model / collector -- rendering is separate.
    Can be used by CLI dashboards, web UIs, or monitoring exporters.

    Thread-safe: all mutations are guarded by an internal lock.
    """

    def __init__(self, *, max_history: int = 1000, max_alerts: int = 500) -> None:
        self._lock = threading.Lock()
        self._max_history = max_history
        self._max_alerts = max_alerts

        self._servers: dict[str, ServerStatus] = {}
        self._calls: list[CallRecord] = []
        self._alerts: list[Alert] = []

        # Monotonic uptime reference
        self._start_mono = time.monotonic()

    # -- Recording methods ---------------------------------------------------

    def record_call(
        self,
        tool_name: str,
        server_name: str,
        *,
        decision: str = "allowed",
        risk_level: str = "low",
        findings_count: int = 0,
        session_id: str = "default",
    ) -> None:
        """Record a tool call.

        Args:
            tool_name: Name of the tool that was called.
            server_name: MCP server that owns the tool.
            decision: Governance decision (allowed/blocked/rate_limited/consent_required).
            risk_level: Risk level assigned to the call.
            findings_count: Number of security findings from scans.
            session_id: Session identifier for grouping calls.
        """
        record = CallRecord(
            timestamp=time.time(),
            tool_name=tool_name,
            server_name=server_name,
            decision=decision,
            risk_level=risk_level,
            findings_count=findings_count,
            session_id=session_id,
        )
        with self._lock:
            self._calls.append(record)
            # Enforce max history
            if len(self._calls) > self._max_history:
                self._calls = self._calls[-self._max_history :]

            # Update server stats if registered
            srv = self._servers.get(server_name)
            if srv is not None and decision == "blocked":
                srv.blocked_count += 1

    def record_alert(
        self,
        severity: str,
        category: str,
        detail: str,
        *,
        server_name: str = "",
        tool_name: str = "",
    ) -> str:
        """Record a security alert.

        Args:
            severity: Alert severity (critical/high/medium/low).
            category: Alert category
                (escalation/shadow/response_injection/rate_limit_burst/rug_pull).
            detail: Human-readable description of the alert.
            server_name: Related server name (optional).
            tool_name: Related tool name (optional).

        Returns:
            The generated alert_id.
        """
        alert_id = uuid.uuid4().hex[:12]
        alert = Alert(
            alert_id=alert_id,
            timestamp=time.time(),
            severity=severity,
            category=category,
            detail=detail,
            server_name=server_name,
            tool_name=tool_name,
        )
        with self._lock:
            self._alerts.append(alert)
            # Enforce max alerts
            if len(self._alerts) > self._max_alerts:
                self._alerts = self._alerts[-self._max_alerts :]
        return alert_id

    def resolve_alert(self, alert_id: str) -> bool:
        """Mark an alert as resolved.

        Returns:
            True if the alert was found and resolved, False otherwise.
        """
        with self._lock:
            for alert in self._alerts:
                if alert.alert_id == alert_id:
                    alert.resolved = True
                    return True
        return False

    def register_server(
        self,
        server_name: str,
        tool_count: int,
        trust_level: str = "L0_UNTRUSTED",
    ) -> None:
        """Register or update a server status.

        Args:
            server_name: Name of the MCP server.
            tool_count: Number of tools provided by the server.
            trust_level: Trust level string (L0_UNTRUSTED through L4_AUDITED).
        """
        with self._lock:
            existing = self._servers.get(server_name)
            if existing is not None:
                existing.tool_count = tool_count
                existing.trust_level = trust_level
            else:
                self._servers[server_name] = ServerStatus(
                    server_name=server_name,
                    tool_count=tool_count,
                    trust_level=trust_level,
                )

    # -- Query methods -------------------------------------------------------

    def get_state(self) -> DashboardState:
        """Get current dashboard state snapshot.

        Returns a fully independent copy of the current state.
        """
        with self._lock:
            now = time.time()
            one_min_ago = now - 60
            one_hour_ago = now - 3600

            # Compute per-server call rates
            servers_copy: dict[str, ServerStatus] = {}
            for name, srv in self._servers.items():
                calls_min = sum(
                    1 for c in self._calls if c.server_name == name and c.timestamp >= one_min_ago
                )
                calls_hour = sum(
                    1 for c in self._calls if c.server_name == name and c.timestamp >= one_hour_ago
                )
                shadow = sum(
                    1
                    for a in self._alerts
                    if a.server_name == name and a.category == "shadow" and not a.resolved
                )
                servers_copy[name] = ServerStatus(
                    server_name=srv.server_name,
                    tool_count=srv.tool_count,
                    trust_level=srv.trust_level,
                    calls_last_minute=calls_min,
                    calls_last_hour=calls_hour,
                    blocked_count=srv.blocked_count,
                    shadow_conflicts=shadow,
                    is_healthy=srv.is_healthy,
                )

            recent = list(self._calls[-50:])  # Last 50 for display

            active = [a for a in self._alerts if not a.resolved]

            # Aggregate stats
            total = len(self._calls)
            blocked = sum(1 for c in self._calls if c.decision == "blocked")
            allowed = sum(1 for c in self._calls if c.decision == "allowed")
            block_rate = (blocked / total * 100) if total > 0 else 0.0
            escalations = sum(
                1 for a in self._alerts if a.category == "escalation" and not a.resolved
            )
            shadows = sum(1 for a in self._alerts if a.category == "shadow" and not a.resolved)
            resp_findings = sum(
                1 for a in self._alerts if a.category == "response_injection" and not a.resolved
            )
            uptime = time.monotonic() - self._start_mono

            stats = DashboardStats(
                total_calls=total,
                total_blocked=blocked,
                total_allowed=allowed,
                block_rate_percent=round(block_rate, 1),
                escalation_count=escalations,
                shadow_count=shadows,
                response_findings_count=resp_findings,
                uptime_seconds=uptime,
            )

            return DashboardState(
                servers=servers_copy,
                recent_calls=recent,
                active_alerts=active,
                stats=stats,
            )

    def get_alerts(
        self,
        *,
        severity: str | None = None,
        unresolved_only: bool = True,
    ) -> list[Alert]:
        """Get alerts, optionally filtered.

        Args:
            severity: Filter by severity level (optional).
            unresolved_only: If True, return only unresolved alerts.

        Returns:
            List of matching alerts.
        """
        with self._lock:
            result: list[Alert] = []
            for a in self._alerts:
                if unresolved_only and a.resolved:
                    continue
                if severity is not None and a.severity != severity:
                    continue
                result.append(a)
            return result

    def get_server_stats(self, server_name: str) -> ServerStatus | None:
        """Get stats for a specific server.

        Returns:
            ServerStatus if found, None otherwise.
        """
        with self._lock:
            srv = self._servers.get(server_name)
            if srv is None:
                return None
            # Compute live rates
            now = time.time()
            one_min_ago = now - 60
            one_hour_ago = now - 3600
            calls_min = sum(
                1
                for c in self._calls
                if c.server_name == server_name and c.timestamp >= one_min_ago
            )
            calls_hour = sum(
                1
                for c in self._calls
                if c.server_name == server_name and c.timestamp >= one_hour_ago
            )
            shadow = sum(
                1
                for a in self._alerts
                if a.server_name == server_name and a.category == "shadow" and not a.resolved
            )
            return ServerStatus(
                server_name=srv.server_name,
                tool_count=srv.tool_count,
                trust_level=srv.trust_level,
                calls_last_minute=calls_min,
                calls_last_hour=calls_hour,
                blocked_count=srv.blocked_count,
                shadow_conflicts=shadow,
                is_healthy=srv.is_healthy,
            )

    # -- Rendering -----------------------------------------------------------

    def render_text(self, *, width: int = 80) -> str:
        """Render the dashboard as a formatted text string.

        Uses Unicode box-drawing characters for layout.

        Args:
            width: Target width in characters (minimum 60).

        Returns:
            Multi-line string with the full dashboard layout.
        """
        width = max(60, width)
        state = self.get_state()
        inner = width - 2  # Inside the box (excluding left/right borders)

        lines: list[str] = []

        def hline_top() -> str:
            return "\u2554" + "\u2550" * inner + "\u2557"

        def hline_mid() -> str:
            return "\u2560" + "\u2550" * inner + "\u2563"

        def hline_bot() -> str:
            return "\u255a" + "\u2550" * inner + "\u255d"

        def row(text: str) -> str:
            return "\u2551" + " " + text.ljust(inner - 1) + "\u2551"

        # Header
        title = "Aegis MCP Security Dashboard"
        lines.append(hline_top())
        lines.append("\u2551" + title.center(inner) + "\u2551")
        lines.append(hline_mid())

        # Summary bar
        uptime_str = _format_uptime(state.stats.uptime_seconds)
        total_fmt = f"{state.stats.total_calls:,}"
        blocked_fmt = f"{state.stats.total_blocked:,}"
        block_pct = f"{state.stats.block_rate_percent:.1f}%"
        summary = (
            f"Uptime: {uptime_str} \u2502 "
            f"Calls: {total_fmt} \u2502 "
            f"Blocked: {blocked_fmt} ({block_pct})"
        )
        lines.append(row(summary))
        lines.append(hline_mid())

        # Servers section
        lines.append(row("SERVERS"))
        if state.servers:
            for srv in state.servers.values():
                # Healthy = filled circle, unhealthy = open circle
                dot = "\u25cf" if srv.is_healthy else "\u25cb"
                srv_line = (
                    f"{dot} {srv.server_name:<14s}\u2502 "
                    f"{srv.tool_count} tools \u2502 "
                    f"{srv.trust_level:<12s}\u2502 "
                    f"{srv.calls_last_minute} calls/min"
                )
                lines.append(row(srv_line))
        else:
            lines.append(row("  (no servers registered)"))
        lines.append(hline_mid())

        # Active alerts section
        active = state.active_alerts
        lines.append(row(f"ACTIVE ALERTS ({len(active)})"))
        if active:
            # Show up to 10 most recent
            for alert in active[-10:]:
                sev_label = alert.severity.upper()
                alert_line = f"[{sev_label}] {alert.category}: {alert.detail}"
                # Truncate to fit
                max_len = inner - 2
                if len(alert_line) > max_len:
                    alert_line = alert_line[: max_len - 3] + "..."
                lines.append(row(alert_line))
        else:
            lines.append(row("  (no active alerts)"))
        lines.append(hline_mid())

        # Recent calls section
        lines.append(row("RECENT CALLS"))
        if state.recent_calls:
            # Show up to 10 most recent
            for call in state.recent_calls[-10:]:
                ts_str = _format_timestamp(call.timestamp)
                call_line = (
                    f"{ts_str} "
                    f"{call.server_name}.{call.tool_name:<20s} "
                    f"{call.decision.upper():<14s} "
                    f"{call.risk_level}"
                )
                max_len = inner - 2
                if len(call_line) > max_len:
                    call_line = call_line[: max_len - 3] + "..."
                lines.append(row(call_line))
        else:
            lines.append(row("  (no calls recorded)"))

        lines.append(hline_bot())
        return "\n".join(lines)

    def render_compact(self) -> str:
        """Render a compact one-line summary.

        Returns:
            A single-line string summarising key metrics.
        """
        state = self.get_state()
        s = state.stats
        alert_count = len(state.active_alerts)
        return (
            f"[Aegis] "
            f"calls={s.total_calls} "
            f"blocked={s.total_blocked} "
            f"({s.block_rate_percent:.1f}%) "
            f"alerts={alert_count} "
            f"servers={len(state.servers)} "
            f"uptime={_format_uptime(s.uptime_seconds)}"
        )

    def to_dict(self) -> dict[str, Any]:
        """Export dashboard state as a dict (for JSON API).

        Returns:
            Serialisable dictionary of the full dashboard state.
        """
        state = self.get_state()
        return {
            "servers": {
                name: {
                    "server_name": srv.server_name,
                    "tool_count": srv.tool_count,
                    "trust_level": srv.trust_level,
                    "calls_last_minute": srv.calls_last_minute,
                    "calls_last_hour": srv.calls_last_hour,
                    "blocked_count": srv.blocked_count,
                    "shadow_conflicts": srv.shadow_conflicts,
                    "is_healthy": srv.is_healthy,
                }
                for name, srv in state.servers.items()
            },
            "recent_calls": [
                {
                    "timestamp": c.timestamp,
                    "tool_name": c.tool_name,
                    "server_name": c.server_name,
                    "decision": c.decision,
                    "risk_level": c.risk_level,
                    "findings_count": c.findings_count,
                    "session_id": c.session_id,
                }
                for c in state.recent_calls
            ],
            "active_alerts": [
                {
                    "alert_id": a.alert_id,
                    "timestamp": a.timestamp,
                    "severity": a.severity,
                    "category": a.category,
                    "detail": a.detail,
                    "server_name": a.server_name,
                    "tool_name": a.tool_name,
                    "resolved": a.resolved,
                }
                for a in state.active_alerts
            ],
            "stats": {
                "total_calls": state.stats.total_calls,
                "total_blocked": state.stats.total_blocked,
                "total_allowed": state.stats.total_allowed,
                "block_rate_percent": state.stats.block_rate_percent,
                "escalation_count": state.stats.escalation_count,
                "shadow_count": state.stats.shadow_count,
                "response_findings_count": state.stats.response_findings_count,
                "uptime_seconds": state.stats.uptime_seconds,
            },
        }


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def _format_uptime(seconds: float) -> str:
    """Format seconds into human-readable uptime string."""
    seconds = max(0.0, seconds)
    total = int(seconds)
    if total < 60:
        return f"{total}s"
    minutes = total // 60
    if minutes < 60:
        secs = total % 60
        return f"{minutes}m {secs}s"
    hours = minutes // 60
    mins = minutes % 60
    return f"{hours}h {mins:02d}m"


def _format_timestamp(ts: float) -> str:
    """Format a UNIX timestamp into HH:MM:SS local time."""
    t = time.localtime(ts)
    return f"{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}"
