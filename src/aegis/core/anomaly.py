"""Behavioral Anomaly Detection engine for AI agent actions.

Learns per-agent behavioral profiles over time and detects anomalies
without requiring explicit YAML rules. Acts as an "immune system" layer
that auto-flags rate spikes, bursts, unknown action types, unusual
targets, and high block rates.

Thread-safe: all profile mutations are guarded by a per-profile lock.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime

from aegis.core.action import Action

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class BehaviorProfile:
    """Per-agent behavioral statistics accumulated over time.

    Attributes:
        agent_id: Identifier for the agent being profiled.
        action_counts: Mapping of action type to total count.
        action_rate: Mapping of action type to recent timestamps (bounded).
        avg_rate_per_minute: Exponentially-smoothed rate per action type.
        target_counts: Mapping of action target to total count.
        blocked_count: Number of times an action was recorded as blocked.
        total_actions: Total actions ever recorded.
        first_seen: Timestamp of the first recorded action.
        last_seen: Timestamp of the most recent recorded action.
    """

    agent_id: str
    action_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    action_rate: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))
    avg_rate_per_minute: dict[str, float] = field(default_factory=lambda: defaultdict(float))
    target_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    blocked_count: int = 0
    total_actions: int = 0
    first_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class AnomalyResult:
    """Outcome of an anomaly check against an agent profile.

    Attributes:
        is_anomalous: ``True`` when an anomaly was detected.
        anomaly_type: Classification string (e.g. ``"rate_spike"``).
        severity: Value between 0.0 (benign) and 1.0 (critical).
        message: Human-readable explanation.
        recommendation: Suggested policy action.
    """

    is_anomalous: bool
    anomaly_type: str | None = None
    severity: float = 0.0
    message: str = ""
    recommendation: str = ""


_OK = AnomalyResult(is_anomalous=False, message="No anomaly detected")

# Maximum number of timestamps kept per action type for rate calculation.
_MAX_RATE_SAMPLES: int = 200


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class AnomalyDetector:
    """Stateful anomaly detector that builds per-agent behavior profiles.

    Parameters:
        rate_threshold: A multiplier applied to the running average rate.
            If the instantaneous rate exceeds ``avg * rate_threshold`` the
            action is flagged as a *rate_spike*.  Default ``5.0``.
        burst_window: Time window in seconds used for burst detection.
            Default ``60.0``.
        burst_limit: Maximum number of actions within *burst_window*
            before flagging a *burst*.  Default ``10``.
        new_action_alert: When ``True``, flag the first occurrence of a
            previously-unseen action type for a given agent.
        block_rate_threshold: Fraction (0-1).  When the proportion of
            blocked actions exceeds this value the agent is flagged with
            *high_block_rate*.  Default ``0.5``.
    """

    def __init__(
        self,
        *,
        rate_threshold: float = 5.0,
        burst_window: float = 60.0,
        burst_limit: int = 10,
        new_action_alert: bool = True,
        block_rate_threshold: float = 0.5,
    ) -> None:
        self._rate_threshold = rate_threshold
        self._burst_window = burst_window
        self._burst_limit = burst_limit
        self._new_action_alert = new_action_alert
        self._block_rate_threshold = block_rate_threshold

        # Profiles keyed by agent_id.
        self._profiles: dict[str, BehaviorProfile] = {}
        # One lock per agent_id to minimise contention.
        self._locks: dict[str, threading.Lock] = {}
        # Global lock only for creating new per-agent entries.
        self._global_lock = threading.Lock()

    # -- helpers ------------------------------------------------------------

    def _get_lock(self, agent_id: str) -> threading.Lock:
        """Return the per-agent lock, creating it if necessary."""
        lock = self._locks.get(agent_id)
        if lock is not None:
            return lock
        with self._global_lock:
            # Double-check after acquiring global lock.
            if agent_id not in self._locks:
                self._locks[agent_id] = threading.Lock()
            return self._locks[agent_id]

    def _ensure_profile(self, agent_id: str) -> BehaviorProfile:
        """Return existing profile or create a new empty one.

        Must be called while holding the per-agent lock.
        """
        profile = self._profiles.get(agent_id)
        if profile is not None:
            return profile
        profile = BehaviorProfile(agent_id=agent_id)
        self._profiles[agent_id] = profile
        return profile

    @staticmethod
    def _prune_timestamps(timestamps: list[float], window: float, now: float) -> list[float]:
        """Remove timestamps older than *window* seconds from *now*."""
        cutoff = now - window
        # Timestamps are appended in order so we can bisect, but a simple
        # filter is fast enough for bounded lists.
        return [t for t in timestamps if t >= cutoff]

    @staticmethod
    def _compute_rate_per_minute(timestamps: list[float]) -> float:
        """Compute actions-per-minute from a list of epoch timestamps."""
        if len(timestamps) < 2:
            return 0.0
        span = timestamps[-1] - timestamps[0]
        if span <= 0:
            return 0.0
        return (len(timestamps) - 1) / (span / 60.0)

    # -- public API ---------------------------------------------------------

    def record(self, action: Action, agent_id: str = "default", *, blocked: bool = False) -> None:
        """Record an action to build/update the behavior profile.

        Args:
            action: The action being performed.
            agent_id: Agent identifier (falls back to ``action.agent_id``
                then ``"default"``).
            blocked: Set to ``True`` when the action was blocked by policy.
        """
        agent_id = agent_id or action.agent_id or "default"
        now = time.monotonic()

        lock = self._get_lock(agent_id)
        with lock:
            profile = self._ensure_profile(agent_id)

            profile.action_counts[action.type] += 1
            profile.target_counts[action.target] += 1
            profile.total_actions += 1
            if blocked:
                profile.blocked_count += 1
            profile.last_seen = datetime.now(UTC)

            # Maintain bounded timestamp list for rate calculation.
            ts_list = profile.action_rate[action.type]
            ts_list.append(now)
            if len(ts_list) > _MAX_RATE_SAMPLES:
                ts_list[:] = ts_list[-_MAX_RATE_SAMPLES:]

            # Update exponentially-smoothed average rate.
            rate = self._compute_rate_per_minute(ts_list)
            prev = profile.avg_rate_per_minute.get(action.type, 0.0)
            alpha = 0.3  # smoothing factor
            if prev == 0.0:
                profile.avg_rate_per_minute[action.type] = rate
            else:
                profile.avg_rate_per_minute[action.type] = alpha * rate + (1 - alpha) * prev

    def check(self, action: Action, agent_id: str = "default") -> AnomalyResult:
        """Check whether *action* is anomalous for the given agent.

        Returns :class:`AnomalyResult` with ``is_anomalous=True`` when a
        problem is detected.  The result includes a severity score, anomaly
        classification, and a human-readable recommendation.

        When no profile exists yet (first-ever action) the check always
        returns OK -- you cannot detect anomalies without history.
        """
        agent_id = agent_id or action.agent_id or "default"

        lock = self._get_lock(agent_id)
        with lock:
            profile = self._profiles.get(agent_id)
            if profile is None:
                return _OK
            if profile.total_actions == 0:
                return _OK

            # --- 1. New action type ------------------------------------------
            if self._new_action_alert and action.type not in profile.action_counts:
                return AnomalyResult(
                    is_anomalous=True,
                    anomaly_type="new_action",
                    severity=0.6,
                    message=(
                        f"Agent '{agent_id}' has never performed action '{action.type}' before."
                    ),
                    recommendation=(f"Consider adding a rule for action type '{action.type}'."),
                )

            # --- 2. Unusual target -------------------------------------------
            if action.target not in profile.target_counts:
                return AnomalyResult(
                    is_anomalous=True,
                    anomaly_type="unusual_target",
                    severity=0.5,
                    message=(f"Agent '{agent_id}' has never targeted '{action.target}' before."),
                    recommendation=(f"Consider adding a rule for target '{action.target}'."),
                )

            # --- 3. Rate spike -----------------------------------------------
            avg = profile.avg_rate_per_minute.get(action.type, 0.0)
            ts_list = profile.action_rate.get(action.type, [])
            if avg > 0 and len(ts_list) >= 3:
                recent_rate = self._compute_rate_per_minute(ts_list[-10:])
                if recent_rate > avg * self._rate_threshold:
                    severity = min(1.0, recent_rate / (avg * self._rate_threshold * 2))
                    return AnomalyResult(
                        is_anomalous=True,
                        anomaly_type="rate_spike",
                        severity=severity,
                        message=(
                            f"Agent '{agent_id}' action '{action.type}' rate "
                            f"spiked to {recent_rate:.1f}/min (avg {avg:.1f}/min)."
                        ),
                        recommendation=(f"Consider adding a rate-limit rule for '{action.type}'."),
                    )

            # --- 4. Burst detection ------------------------------------------
            now = time.monotonic()
            if ts_list:
                recent = self._prune_timestamps(ts_list, self._burst_window, now)
                if len(recent) >= self._burst_limit:
                    severity = min(1.0, len(recent) / (self._burst_limit * 2))
                    return AnomalyResult(
                        is_anomalous=True,
                        anomaly_type="burst",
                        severity=severity,
                        message=(
                            f"Agent '{agent_id}' performed {len(recent)} "
                            f"'{action.type}' actions in the last "
                            f"{self._burst_window:.0f}s."
                        ),
                        recommendation=(
                            f"Consider adding a burst-limit rule for '{action.type}'."
                        ),
                    )

            # --- 5. High block rate ------------------------------------------
            if profile.total_actions >= 5:
                block_ratio = profile.blocked_count / profile.total_actions
                if block_ratio > self._block_rate_threshold:
                    return AnomalyResult(
                        is_anomalous=True,
                        anomaly_type="high_block_rate",
                        severity=min(1.0, block_ratio),
                        message=(
                            f"Agent '{agent_id}' has been blocked "
                            f"{profile.blocked_count}/{profile.total_actions} "
                            f"times ({block_ratio:.0%})."
                        ),
                        recommendation=(
                            f"Investigate agent '{agent_id}' "
                            f"-- possible misconfiguration or attack."
                        ),
                    )

        return _OK

    def get_profile(self, agent_id: str) -> BehaviorProfile | None:
        """Return a snapshot of the profile for *agent_id*, or ``None``."""
        lock = self._get_lock(agent_id)
        with lock:
            return self._profiles.get(agent_id)

    def generate_policy(self, agent_id: str) -> dict[str, object]:
        """Generate a YAML-ready policy dict from the agent's observed behavior.

        Examines the profile to produce sensible rules:
        - Frequently-used read-like actions get ``auto`` approval.
        - Write-like actions get ``approve``.
        - Never-seen destructive patterns get ``block``.
        - Targets are included in match clauses.

        Returns an empty dict when no profile exists.
        """
        lock = self._get_lock(agent_id)
        with lock:
            profile = self._profiles.get(agent_id)
            if profile is None or profile.total_actions == 0:
                return {}

            rules: list[dict[str, object]] = []

            # Group action types by inferred risk category.
            for idx, (action_type, _count) in enumerate(
                sorted(
                    profile.action_counts.items(),
                    key=lambda kv: kv[1],
                    reverse=True,
                )
            ):
                risk, approval = self._classify_action_type(action_type)
                # Find the most common target for this action type.
                rule: dict[str, object] = {
                    "name": f"auto_{action_type}_{idx}",
                    "match": {"type": action_type},
                    "risk_level": risk,
                    "approval": approval,
                }
                rules.append(rule)

            # Add blanket block rules for common destructive patterns
            # that have never been observed.
            for prefix in ("delete", "drop", "destroy", "purge"):
                if not any(a.startswith(prefix) for a in profile.action_counts):
                    rules.append(
                        {
                            "name": f"block_{prefix}",
                            "match": {"type": f"{prefix}_*"},
                            "risk_level": "critical",
                            "approval": "block",
                        }
                    )

            return {
                "version": "1",
                "defaults": {"risk_level": "medium", "approval": "approve"},
                "rules": rules,
            }

    @staticmethod
    def _classify_action_type(action_type: str) -> tuple[str, str]:
        """Heuristic classification of an action type.

        Returns ``(risk_level, approval)`` strings suitable for YAML.
        """
        lower = action_type.lower()
        if any(lower.startswith(p) for p in ("read", "get", "list", "fetch", "query", "search")):
            return ("low", "auto")
        if any(lower.startswith(p) for p in ("write", "update", "create", "put", "set", "send")):
            return ("medium", "approve")
        if any(
            lower.startswith(p)
            for p in ("delete", "drop", "destroy", "purge", "remove", "truncate")
        ):
            return ("critical", "block")
        # Default for unknown types.
        return ("medium", "approve")

    def reset(self, agent_id: str | None = None) -> None:
        """Clear profile data.

        When *agent_id* is given only that agent's profile is removed.
        Otherwise all profiles are cleared.
        """
        if agent_id is not None:
            lock = self._get_lock(agent_id)
            with lock:
                self._profiles.pop(agent_id, None)
        else:
            with self._global_lock:
                self._profiles.clear()
                self._locks.clear()
