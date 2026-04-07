"""Real-Time Agent Monitoring Dashboard (TUI).

Provides a text-based dashboard that shows live agent activity,
anomaly alerts, and policy enforcement statistics. No curses
dependency -- the dashboard is rendered as a plain formatted string
that can be reprinted to the terminal after a clear.

Thread-safe: all mutable state is guarded by a single lock so
``record_event`` can be called from multiple threads.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field

from aegis.core.action import Action
from aegis.core.anomaly import AnomalyDetector, AnomalyResult
from aegis.core.budget import CostRecord, CostTracker, TokenUsage

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class MonitorState:
    """Snapshot of all dashboard metrics.

    Attributes:
        active_agents: Mapping of agent_id to cumulative action count.
        blocked_counts: Per-agent count of blocked actions.
        anomaly_counts: Per-agent count of anomalies detected.
        recent_alerts: Most recent anomaly alert strings (bounded).
        decision_counters: Counts keyed by decision type (auto/approve/block).
        action_type_counts: Frequency counter for action types.
        total_actions: Total events recorded since start.
        start_time: Monotonic time when monitoring started.
        event_timestamps: Rolling window of event timestamps for rate calc.
        max_alerts: Maximum number of recent alerts to retain.
    """

    active_agents: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    blocked_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    anomaly_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    recent_alerts: list[str] = field(default_factory=list)
    decision_counters: dict[str, int] = field(
        default_factory=lambda: defaultdict(int),
    )
    action_type_counts: dict[str, int] = field(
        default_factory=lambda: defaultdict(int),
    )
    total_actions: int = 0
    start_time: float = field(default_factory=time.monotonic)
    event_timestamps: list[float] = field(default_factory=list)
    max_alerts: int = 20


# ---------------------------------------------------------------------------
# Monitor
# ---------------------------------------------------------------------------

# Maximum number of timestamps kept for rate calculation.
_MAX_RATE_WINDOW: int = 500


class AgentMonitor:
    """Live agent monitor that collects events and renders a dashboard.

    Parameters:
        detector: An optional :class:`AnomalyDetector` instance.  When
            provided, every recorded event is also checked for anomalies.
        max_alerts: Maximum number of recent alert strings to keep.
        rate_window: Seconds over which the actions-per-minute rate is
            calculated.  Default ``60.0``.
    """

    def __init__(
        self,
        detector: AnomalyDetector | None = None,
        *,
        max_alerts: int = 20,
        rate_window: float = 60.0,
        cost_tracker: CostTracker | None = None,
    ) -> None:
        self._detector = detector or AnomalyDetector()
        self._state = MonitorState(max_alerts=max_alerts)
        self._rate_window = rate_window
        self._cost_tracker = cost_tracker
        self._lock = threading.Lock()

    # -- public API ---------------------------------------------------------

    @property
    def state(self) -> MonitorState:
        """Return the current state (for testing/inspection)."""
        return self._state

    def record_event(
        self,
        action: str | Action,
        agent_id: str = "default",
        decision: str = "auto",
        *,
        target: str = "",
    ) -> AnomalyResult | None:
        """Record an action event and optionally run anomaly detection.

        Args:
            action: Either an :class:`Action` object or a string action
                type.  When a string is provided, *target* is used.
            agent_id: Agent identifier.
            decision: Policy decision -- one of ``"auto"``,
                ``"approve"``, ``"block"``.
            target: Action target (used when *action* is a string).

        Returns:
            An :class:`AnomalyResult` when the detector flags an anomaly,
            otherwise ``None``.
        """
        if isinstance(action, str):
            action_obj = Action(type=action, target=target or "unknown")
        else:
            action_obj = action

        blocked = decision == "block"
        now = time.monotonic()

        # Check for anomalies *before* recording so that the detector
        # compares against the historical profile (not the new event).
        anomaly = self._detector.check(action_obj, agent_id)
        self._detector.record(action_obj, agent_id, blocked=blocked)

        with self._lock:
            s = self._state

            # Agent tracking
            s.active_agents[agent_id] += 1
            if blocked:
                s.blocked_counts[agent_id] += 1

            # Decision counters
            s.decision_counters[decision] += 1

            # Action type frequency
            s.action_type_counts[action_obj.type] += 1

            # Total
            s.total_actions += 1

            # Rate timestamps (bounded)
            s.event_timestamps.append(now)
            if len(s.event_timestamps) > _MAX_RATE_WINDOW:
                s.event_timestamps[:] = s.event_timestamps[-_MAX_RATE_WINDOW:]

            # Anomaly alerts
            if anomaly is not None and anomaly.is_anomalous:
                s.anomaly_counts[agent_id] += 1
                alert = f"[WARN] {agent_id}: {anomaly.anomaly_type} on {action_obj.type}"
                if anomaly.anomaly_type == "unusual_target":
                    alert = f'[WARN] {agent_id}: {anomaly.anomaly_type} "{action_obj.target}"'
                s.recent_alerts.append(alert)
                if len(s.recent_alerts) > s.max_alerts:
                    s.recent_alerts[:] = s.recent_alerts[-s.max_alerts :]
                return anomaly

        return None

    @property
    def cost_tracker(self) -> CostTracker | None:
        """Return the attached cost tracker, if any."""
        return self._cost_tracker

    def record_cost(
        self,
        usage: TokenUsage,
        *,
        agent_id: str = "",
        action_type: str = "",
    ) -> CostRecord | None:
        """Record a cost event if a cost tracker is attached.

        Returns the :class:`CostRecord` from the tracker, or ``None``
        if no tracker is configured.
        """
        if self._cost_tracker is None:
            return None
        return self._cost_tracker.record(usage, agent_id=agent_id, action_type=action_type)

    def actions_per_minute(self) -> float:
        """Compute the current actions-per-minute rate.

        Uses event timestamps within ``rate_window`` seconds of now.
        """
        now = time.monotonic()
        with self._lock:
            timestamps = self._state.event_timestamps
            cutoff = now - self._rate_window
            recent = [t for t in timestamps if t >= cutoff]
        if len(recent) < 2:
            return 0.0
        span = recent[-1] - recent[0]
        if span <= 0:
            return 0.0
        return (len(recent) - 1) / (span / 60.0)

    def top_action_types(self, n: int = 5) -> list[tuple[str, int]]:
        """Return the top *n* action types by frequency."""
        with self._lock:
            items = sorted(
                self._state.action_type_counts.items(),
                key=lambda kv: kv[1],
                reverse=True,
            )
        return items[:n]

    def uptime_str(self) -> str:
        """Return a human-readable uptime string like ``2h 15m``."""
        elapsed = time.monotonic() - self._state.start_time
        return _format_duration(elapsed)

    def render(self, width: int = 56) -> str:
        """Render the dashboard as a formatted string.

        Args:
            width: Inner width of the box (between the vertical bars).

        Returns:
            A multi-line string containing the full dashboard.
        """
        with self._lock:
            s = self._state
            total = s.total_actions
            rate = self._actions_per_minute_unlocked()
            uptime = _format_duration(time.monotonic() - s.start_time)

            # --- agent table ---
            agents: list[tuple[str, int, int, int]] = []
            for aid in sorted(s.active_agents):
                agents.append(
                    (
                        aid,
                        s.active_agents[aid],
                        s.blocked_counts.get(aid, 0),
                        s.anomaly_counts.get(aid, 0),
                    )
                )

            # --- decision distribution ---
            auto = s.decision_counters.get("auto", 0)
            approve = s.decision_counters.get("approve", 0)
            block = s.decision_counters.get("block", 0)

            alerts = list(s.recent_alerts)

        lines: list[str] = []
        iw = width  # inner width
        h_bar = "\u2550"

        # Top border
        lines.append(f"\u2554\u2550\u2550 Aegis Agent Monitor {h_bar * (iw - 21)}\u2557")

        # Summary line
        summary = f" Uptime: {uptime} | Actions: {total:,} | Rate: {rate:.1f}/min "
        lines.append(f"\u2551{summary:<{iw}}\u2551")

        # Separator
        lines.append(f"\u2560{h_bar * iw}\u2563")

        # Agent table header
        hdr = f" {'Agent':<12} | {'Actions':>7} | {'Blocked':>7} | {'Anomalies':>9} "
        lines.append(f"\u2551{hdr:<{iw}}\u2551")
        for aid, acts, blk, ano in agents:
            row = f" {aid:<12} | {acts:>7,} | {blk:>7,} | {ano:>9,} "
            lines.append(f"\u2551{row:<{iw}}\u2551")

        # Separator
        lines.append(f"\u2560{h_bar * iw}\u2563")

        # Recent alerts
        alert_hdr = " Recent Alerts"
        lines.append(f"\u2551{alert_hdr:<{iw}}\u2551")
        if alerts:
            for a in alerts[-5:]:
                lines.append(f"\u2551 {a:<{iw - 1}}\u2551")
        else:
            lines.append(f"\u2551{' (none)':<{iw}}\u2551")

        # Separator
        lines.append(f"\u2560{h_bar * iw}\u2563")

        # Decision distribution
        dist_hdr = " Decision Distribution"
        lines.append(f"\u2551{dist_hdr:<{iw}}\u2551")
        dist_parts: list[str] = []
        for label, cnt in [("auto", auto), ("approve", approve), ("block", block)]:
            pct = (cnt / total * 100) if total > 0 else 0.0
            dist_parts.append(f"{label}: {cnt:,} ({pct:.1f}%)")
        dist_line = " " + " | ".join(dist_parts) + " "
        lines.append(f"\u2551{dist_line:<{iw}}\u2551")

        # Cost section (only if tracker attached)
        if self._cost_tracker is not None:
            lines.append(f"\u2560{h_bar * iw}\u2563")
            cost_hdr = " Cost Tracking"
            lines.append(f"\u2551{cost_hdr:<{iw}}\u2551")

            tracker = self._cost_tracker
            spent = tracker.spent
            remaining = tracker.remaining
            util = tracker.utilization

            if tracker.max_budget > 0:
                remaining_str = f"${remaining:.4f}"
                bar_len = iw - 22  # space for label + borders
                filled = int(util * bar_len)
                bar = "\u2588" * filled + "\u2591" * (bar_len - filled)
                cost_line = f" Spent: ${spent:.4f} / ${tracker.max_budget:.2f} ({util:.0%})"
                lines.append(f"\u2551{cost_line:<{iw}}\u2551")
                bar_line = f" [{bar}] {remaining_str} left"
                lines.append(f"\u2551{bar_line:<{iw}}\u2551")
            else:
                cost_line = f" Spent: ${spent:.4f} (no budget limit)"
                lines.append(f"\u2551{cost_line:<{iw}}\u2551")

            # Per-model breakdown (top 5)
            report = tracker.get_report()
            by_model = report.get("by_model", {})
            if by_model:
                model_hdr = " By Model:"
                lines.append(f"\u2551{model_hdr:<{iw}}\u2551")
                sorted_models = sorted(by_model.items(), key=lambda kv: kv[1], reverse=True)
                for model, cost in sorted_models[:5]:
                    model_line = f"   {model:<28} ${cost:.6f}"
                    lines.append(f"\u2551{model_line:<{iw}}\u2551")

            # Per-agent cost breakdown
            by_agent = report.get("by_agent", {})
            if by_agent:
                agent_cost_hdr = " By Agent:"
                lines.append(f"\u2551{agent_cost_hdr:<{iw}}\u2551")
                sorted_agents = sorted(by_agent.items(), key=lambda kv: kv[1], reverse=True)
                for agent, cost in sorted_agents[:5]:
                    agent_line = f"   {agent:<28} ${cost:.6f}"
                    lines.append(f"\u2551{agent_line:<{iw}}\u2551")

        # Bottom border
        lines.append(f"\u255a{h_bar * iw}\u255d")

        return "\n".join(lines)

    # -- helpers (private) --------------------------------------------------

    def _actions_per_minute_unlocked(self) -> float:
        """Compute rate without acquiring the lock (caller holds it)."""
        now = time.monotonic()
        cutoff = now - self._rate_window
        recent = [t for t in self._state.event_timestamps if t >= cutoff]
        if len(recent) < 2:
            return 0.0
        span = recent[-1] - recent[0]
        if span <= 0:
            return 0.0
        return (len(recent) - 1) / (span / 60.0)

    def reset(self) -> None:
        """Reset all monitor state."""
        with self._lock:
            self._state = MonitorState(max_alerts=self._state.max_alerts)
        self._detector.reset()


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def _format_duration(seconds: float) -> str:
    """Format *seconds* as a human-readable duration string.

    Examples: ``"0m"``, ``"5m"``, ``"2h 15m"``, ``"1d 3h 12m"``.
    """
    total_minutes = int(seconds) // 60
    if total_minutes < 60:
        return f"{total_minutes}m"
    hours = total_minutes // 60
    mins = total_minutes % 60
    if hours < 24:
        return f"{hours}h {mins}m"
    days = hours // 24
    hours = hours % 24
    return f"{days}d {hours}h {mins}m"


# ---------------------------------------------------------------------------
# CLI command implementation
# ---------------------------------------------------------------------------


def run_monitor(db_path: str, interval: float = 2.0) -> None:  # pragma: no cover
    """Poll an audit database and display a live dashboard.

    This is the implementation behind ``aegis monitor --db <path>``.

    Args:
        db_path: Path to the Aegis audit SQLite database.
        interval: Seconds between refreshes.
    """
    import os
    import sqlite3
    import sys

    from aegis.core.anomaly import AnomalyDetector as _AD

    monitor = AgentMonitor(detector=_AD(), max_alerts=10)
    last_id = 0

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    try:
        while True:
            rows = conn.execute(
                "SELECT * FROM audit_log WHERE id > ? ORDER BY id",
                (last_id,),
            ).fetchall()

            for row in rows:
                row_id: int = row["id"]
                if row_id > last_id:
                    last_id = row_id
                action_type: str = row["action_type"]
                target: str = row["action_target"]
                agent_id: str = row["agent_id"] or "default"
                approval: str = row["approval"] or "auto"

                monitor.record_event(
                    action_type,
                    agent_id=agent_id,
                    decision=approval,
                    target=target,
                )

            # Clear + reprint
            if sys.platform == "win32":
                os.system("cls")  # aegis: ignore
            else:
                os.system("clear")  # aegis: ignore

            sys.stdout.write(monitor.render() + "\n")
            sys.stdout.flush()

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nMonitor stopped.")
    finally:
        conn.close()
