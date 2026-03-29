"""Behavioral Drift Detection engine for AI agent actions.

Computes behavioral baselines from historical BehaviorProfile data and
detects statistically significant changes in agent behavior over time.
Works ON TOP of the existing AnomalyDetector/BehaviorProfile system.

Thread-safe: all baseline state is guarded by a per-agent lock.
"""

from __future__ import annotations

import math
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from aegis.core.anomaly import AnomalyDetector, BehaviorProfile

# ---------------------------------------------------------------------------
# Enums and constants
# ---------------------------------------------------------------------------


class DriftType(StrEnum):
    """Classification of behavioral drift."""

    TOOL_DISTRIBUTION = "tool_distribution"
    RESPONSE_LATENCY = "response_latency"
    ERROR_RATE = "error_rate"
    TOKEN_USAGE = "token_usage"
    ACTION_FREQUENCY = "action_frequency"


class DriftSeverity(StrEnum):
    """Severity level of detected drift."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DriftAction(StrEnum):
    """Enforcement action to take when drift is detected."""

    LOG = "log"
    WARN = "warn"
    ALERT = "alert"
    BLOCK = "block"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DriftResult:
    """Outcome of a drift detection check.

    Attributes:
        drifted: ``True`` when drift exceeds the configured threshold.
        drift_type: Which metric drifted.
        severity: Computed severity level.
        baseline_value: The expected baseline value.
        current_value: The observed current value.
        deviation_pct: Percentage deviation from baseline.
        message: Human-readable explanation.
        action: Recommended enforcement action.
    """

    drifted: bool
    drift_type: DriftType
    severity: DriftSeverity = DriftSeverity.LOW
    baseline_value: float = 0.0
    current_value: float = 0.0
    deviation_pct: float = 0.0
    message: str = ""
    action: DriftAction = DriftAction.LOG


@dataclass
class DriftBaseline:
    """Computed baseline for a single metric of a single agent.

    Attributes:
        agent_id: Agent being profiled.
        metric_name: Name of the metric (matches :class:`DriftType` values).
        window_days: Number of days used to compute the baseline.
        baseline_value: Mean/expected value over the window.
        stddev: Standard deviation over the window.
        sample_count: Number of samples used.
        computed_at: When the baseline was computed.
    """

    agent_id: str
    metric_name: str
    window_days: int
    baseline_value: float
    stddev: float
    sample_count: int
    computed_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class DriftMetricConfig:
    """Configuration for a single drift metric.

    Parsed from YAML drift config baselines.

    Attributes:
        name: Metric name (must match a :class:`DriftType` value).
        window_days: Rolling window size in days for baseline computation.
        threshold: Deviation threshold (interpretation depends on metric).
        action: Action to take when threshold is exceeded.
    """

    name: str
    window_days: int = 30
    threshold: float = 0.2
    action: DriftAction = DriftAction.WARN


# ---------------------------------------------------------------------------
# Historical snapshot for baseline computation
# ---------------------------------------------------------------------------


@dataclass
class HistoricalSnapshot:
    """A point-in-time snapshot of agent behavior for baseline computation.

    In production this would come from the audit database.  For in-memory
    usage the DriftDetector can also compute from BehaviorProfile directly.

    Attributes:
        agent_id: Agent identifier.
        timestamp: When the snapshot was taken.
        action_counts: Mapping of action type to count in this period.
        total_actions: Total actions in this period.
        blocked_count: Blocked actions in this period.
        avg_latency_ms: Average response latency in milliseconds.
        total_tokens: Total tokens consumed in this period.
        period_minutes: Duration of the observation period in minutes.
    """

    agent_id: str
    timestamp: datetime
    action_counts: dict[str, int] = field(default_factory=dict)
    total_actions: int = 0
    blocked_count: int = 0
    avg_latency_ms: float = 0.0
    total_tokens: int = 0
    period_minutes: float = 60.0


# ---------------------------------------------------------------------------
# Drift Detector
# ---------------------------------------------------------------------------


def _parse_window(window_str: str) -> int:
    """Parse a window string like '30d', '7d', '14d' into days."""
    s = window_str.strip().lower()
    if s.endswith("d"):
        return int(s[:-1])
    # Fallback: try parsing as plain integer (assume days).
    return int(s)


def _kl_divergence(p: dict[str, float], q: dict[str, float]) -> float:
    """Compute KL-divergence D(P || Q) for discrete distributions.

    Both *p* and *q* must be normalized probability distributions over
    the same key set.  Keys missing from *q* are assigned a small
    epsilon to avoid division by zero.
    """
    eps = 1e-10
    all_keys = set(p) | set(q)
    divergence = 0.0
    for k in all_keys:
        pk = p.get(k, eps)
        qk = q.get(k, eps)
        if pk > 0:
            divergence += pk * math.log(pk / qk)
    return divergence


def _normalize(counts: dict[str, int]) -> dict[str, float]:
    """Normalize integer counts to a probability distribution."""
    total = sum(counts.values())
    if total == 0:
        return {}
    return {k: v / total for k, v in counts.items()}


def _severity_from_deviation(deviation_pct: float, threshold: float) -> DriftSeverity:
    """Compute severity based on how far deviation exceeds the threshold."""
    if deviation_pct <= threshold:
        return DriftSeverity.LOW
    ratio = deviation_pct / threshold if threshold > 0 else deviation_pct
    if ratio < 2.0:
        return DriftSeverity.MEDIUM
    if ratio < 4.0:
        return DriftSeverity.HIGH
    return DriftSeverity.CRITICAL


class DriftDetector:
    """Detects behavioral drift by comparing current behavior against baselines.

    Works on top of :class:`AnomalyDetector` and :class:`BehaviorProfile`.
    Baselines can be computed from historical snapshots or directly from
    the current profile.

    Parameters:
        anomaly_detector: Optional AnomalyDetector instance to read
            BehaviorProfile data from.
        metric_configs: Per-metric configuration (thresholds, windows, actions).
    """

    def __init__(
        self,
        *,
        anomaly_detector: AnomalyDetector | None = None,
        metric_configs: list[DriftMetricConfig] | None = None,
    ) -> None:
        self._anomaly_detector = anomaly_detector
        self._metric_configs: dict[str, DriftMetricConfig] = {}
        for cfg in metric_configs or []:
            self._metric_configs[cfg.name] = cfg

        # Baselines keyed by (agent_id, metric_name).
        self._baselines: dict[tuple[str, str], DriftBaseline] = {}
        # Per-agent locks.
        self._locks: dict[str, threading.Lock] = {}
        self._global_lock = threading.Lock()

        # In-memory latency tracking (monotonic timestamps per agent).
        self._latency_samples: dict[str, list[float]] = defaultdict(list)
        # In-memory token tracking per agent.
        self._token_samples: dict[str, list[int]] = defaultdict(list)

    # -- helpers ------------------------------------------------------------

    def _get_lock(self, agent_id: str) -> threading.Lock:
        """Return per-agent lock, creating if necessary."""
        lock = self._locks.get(agent_id)
        if lock is not None:
            return lock
        with self._global_lock:
            if agent_id not in self._locks:
                self._locks[agent_id] = threading.Lock()
            return self._locks[agent_id]

    def _get_config(self, metric_name: str) -> DriftMetricConfig:
        """Return config for a metric, with sensible defaults."""
        return self._metric_configs.get(
            metric_name,
            DriftMetricConfig(name=metric_name),
        )

    # -- baseline management ------------------------------------------------

    def compute_baseline(
        self,
        agent_id: str,
        metric_name: str,
        snapshots: list[HistoricalSnapshot],
        window_days: int | None = None,
    ) -> DriftBaseline:
        """Compute a baseline from historical snapshots.

        Filters snapshots to the configured (or provided) window and
        calculates mean and standard deviation.

        Args:
            agent_id: Agent to compute baseline for.
            metric_name: Which metric to compute.
            snapshots: Historical data points.
            window_days: Override the configured window.

        Returns:
            The computed :class:`DriftBaseline`.
        """
        cfg = self._get_config(metric_name)
        window = window_days or cfg.window_days
        cutoff = datetime.now(UTC).timestamp() - (window * 86400)

        # Filter to agent + window.
        relevant = [
            s for s in snapshots if s.agent_id == agent_id and s.timestamp.timestamp() >= cutoff
        ]

        values = self._extract_metric_values(metric_name, relevant)

        mean = sum(values) / len(values) if values else 0.0
        variance = sum((v - mean) ** 2 for v in values) / len(values) if len(values) > 1 else 0.0
        stddev = math.sqrt(variance)

        baseline = DriftBaseline(
            agent_id=agent_id,
            metric_name=metric_name,
            window_days=window,
            baseline_value=mean,
            stddev=stddev,
            sample_count=len(values),
        )

        lock = self._get_lock(agent_id)
        with lock:
            self._baselines[(agent_id, metric_name)] = baseline

        return baseline

    def compute_baseline_from_profile(
        self,
        agent_id: str,
        metric_name: str,
    ) -> DriftBaseline | None:
        """Compute a baseline directly from the current BehaviorProfile.

        Requires an ``anomaly_detector`` to be set.  Returns ``None``
        when no profile exists.
        """
        if self._anomaly_detector is None:
            return None
        profile = self._anomaly_detector.get_profile(agent_id)
        if profile is None:
            return None
        return self._baseline_from_profile(profile, metric_name)

    def _baseline_from_profile(
        self,
        profile: BehaviorProfile,
        metric_name: str,
    ) -> DriftBaseline:
        """Build a baseline from a single BehaviorProfile snapshot."""
        cfg = self._get_config(metric_name)
        value = 0.0

        if metric_name == DriftType.ERROR_RATE:
            if profile.total_actions > 0:
                value = profile.blocked_count / profile.total_actions
        elif metric_name == DriftType.ACTION_FREQUENCY:
            rates = list(profile.avg_rate_per_minute.values())
            value = sum(rates) / len(rates) if rates else 0.0
        elif metric_name == DriftType.TOOL_DISTRIBUTION:
            # For distribution metrics, store entropy as scalar baseline.
            dist = _normalize(dict(profile.action_counts))
            value = self._entropy(dist)
        elif metric_name == DriftType.TOKEN_USAGE:
            tok_samples = self._token_samples.get(profile.agent_id, [])
            value = sum(tok_samples) / len(tok_samples) if tok_samples else 0.0
        elif metric_name == DriftType.RESPONSE_LATENCY:
            lat_samples = self._latency_samples.get(profile.agent_id, [])
            value = sum(lat_samples) / len(lat_samples) if lat_samples else 0.0

        baseline = DriftBaseline(
            agent_id=profile.agent_id,
            metric_name=metric_name,
            window_days=cfg.window_days,
            baseline_value=value,
            stddev=0.0,
            sample_count=profile.total_actions,
        )

        lock = self._get_lock(profile.agent_id)
        with lock:
            self._baselines[(profile.agent_id, metric_name)] = baseline

        return baseline

    def set_baseline(self, baseline: DriftBaseline) -> None:
        """Manually set a baseline (e.g. loaded from config or DB)."""
        lock = self._get_lock(baseline.agent_id)
        with lock:
            self._baselines[(baseline.agent_id, baseline.metric_name)] = baseline

    def get_baseline(self, agent_id: str, metric_name: str) -> DriftBaseline | None:
        """Return the stored baseline, or ``None``."""
        lock = self._get_lock(agent_id)
        with lock:
            return self._baselines.get((agent_id, metric_name))

    # -- recording extra metrics -------------------------------------------

    def record_latency(self, agent_id: str, latency_ms: float) -> None:
        """Record a response latency sample for drift tracking."""
        lock = self._get_lock(agent_id)
        with lock:
            samples = self._latency_samples[agent_id]
            samples.append(latency_ms)
            # Keep bounded.
            if len(samples) > 1000:
                samples[:] = samples[-1000:]

    def record_tokens(self, agent_id: str, tokens: int) -> None:
        """Record a token usage sample for drift tracking."""
        lock = self._get_lock(agent_id)
        with lock:
            samples = self._token_samples[agent_id]
            samples.append(tokens)
            if len(samples) > 1000:
                samples[:] = samples[-1000:]

    # -- drift detection ----------------------------------------------------

    def check(self, agent_id: str, metric_name: str) -> DriftResult:
        """Check for drift on a single metric for an agent.

        Compares the current value against the stored baseline.
        Returns a :class:`DriftResult` with drift details.
        """
        cfg = self._get_config(metric_name)

        lock = self._get_lock(agent_id)
        with lock:
            baseline = self._baselines.get((agent_id, metric_name))

        if baseline is None or baseline.sample_count == 0:
            return DriftResult(
                drifted=False,
                drift_type=DriftType(metric_name),
                message=f"No baseline for {metric_name}",
            )

        current = self._compute_current_value(agent_id, metric_name)
        deviation = self._compute_deviation(baseline, current, metric_name)
        drifted = deviation > cfg.threshold
        severity = _severity_from_deviation(deviation, cfg.threshold)

        return DriftResult(
            drifted=drifted,
            drift_type=DriftType(metric_name),
            severity=severity if drifted else DriftSeverity.LOW,
            baseline_value=baseline.baseline_value,
            current_value=current,
            deviation_pct=deviation,
            message=self._build_message(
                agent_id, metric_name, baseline.baseline_value, current, deviation, drifted
            ),
            action=DriftAction(cfg.action) if drifted else DriftAction.LOG,
        )

    def check_all(self, agent_id: str) -> list[DriftResult]:
        """Check all configured metrics for drift.

        Returns a list of :class:`DriftResult` for each metric that
        has a stored baseline.
        """
        results: list[DriftResult] = []
        metrics = list(self._metric_configs.keys()) or [dt.value for dt in DriftType]

        for metric_name in metrics:
            result = self.check(agent_id, metric_name)
            results.append(result)

        return results

    def check_from_snapshot(
        self,
        snapshot: HistoricalSnapshot,
        metric_name: str,
    ) -> DriftResult:
        """Check drift using an explicit snapshot as the current value.

        Useful when computing drift from audit log data rather than
        live BehaviorProfile.
        """
        cfg = self._get_config(metric_name)
        agent_id = snapshot.agent_id

        lock = self._get_lock(agent_id)
        with lock:
            baseline = self._baselines.get((agent_id, metric_name))

        if baseline is None or baseline.sample_count == 0:
            return DriftResult(
                drifted=False,
                drift_type=DriftType(metric_name),
                message=f"No baseline for {metric_name}",
            )

        values = self._extract_metric_values(metric_name, [snapshot])
        current = values[0] if values else 0.0

        deviation = self._compute_deviation(baseline, current, metric_name)
        drifted = deviation > cfg.threshold
        severity = _severity_from_deviation(deviation, cfg.threshold)

        return DriftResult(
            drifted=drifted,
            drift_type=DriftType(metric_name),
            severity=severity if drifted else DriftSeverity.LOW,
            baseline_value=baseline.baseline_value,
            current_value=current,
            deviation_pct=deviation,
            message=self._build_message(
                agent_id, metric_name, baseline.baseline_value, current, deviation, drifted
            ),
            action=DriftAction(cfg.action) if drifted else DriftAction.LOG,
        )

    # -- internal computations ----------------------------------------------

    def _compute_current_value(self, agent_id: str, metric_name: str) -> float:
        """Compute the current live value for a metric.

        Metrics that depend on BehaviorProfile (error_rate, action_frequency,
        tool_distribution) require an ``anomaly_detector``.  Metrics stored
        directly on the DriftDetector (token_usage, response_latency) work
        regardless.
        """
        # Metrics stored directly on the DriftDetector.
        if metric_name == DriftType.TOKEN_USAGE:
            lock = self._get_lock(agent_id)
            with lock:
                tok = self._token_samples.get(agent_id, [])
                return sum(tok) / len(tok) if tok else 0.0

        if metric_name == DriftType.RESPONSE_LATENCY:
            lock = self._get_lock(agent_id)
            with lock:
                lat = self._latency_samples.get(agent_id, [])
                return sum(lat) / len(lat) if lat else 0.0

        # Metrics that require BehaviorProfile from AnomalyDetector.
        if self._anomaly_detector is None:
            return 0.0

        profile = self._anomaly_detector.get_profile(agent_id)
        if profile is None:
            return 0.0

        if metric_name == DriftType.ERROR_RATE:
            if profile.total_actions == 0:
                return 0.0
            return profile.blocked_count / profile.total_actions

        if metric_name == DriftType.ACTION_FREQUENCY:
            rates = list(profile.avg_rate_per_minute.values())
            return sum(rates) / len(rates) if rates else 0.0

        if metric_name == DriftType.TOOL_DISTRIBUTION:
            dist = _normalize(dict(profile.action_counts))
            return self._entropy(dist)

        return 0.0

    def _compute_deviation(
        self,
        baseline: DriftBaseline,
        current: float,
        metric_name: str,
    ) -> float:
        """Compute deviation between current and baseline.

        For tool_distribution, this is the absolute difference in entropy.
        For other metrics, this is the relative percentage deviation.
        """
        if metric_name == DriftType.TOOL_DISTRIBUTION:
            # For distribution: absolute difference in entropy works well
            # as distributions may shift without baseline being non-zero.
            return abs(current - baseline.baseline_value)

        if baseline.baseline_value == 0:
            return current  # Pure absolute deviation when baseline is zero.

        return abs(current - baseline.baseline_value) / abs(baseline.baseline_value)

    @staticmethod
    def _entropy(dist: dict[str, float]) -> float:
        """Shannon entropy of a probability distribution."""
        if not dist:
            return 0.0
        return -sum(p * math.log(p) for p in dist.values() if p > 0)

    def _extract_metric_values(
        self,
        metric_name: str,
        snapshots: list[HistoricalSnapshot],
    ) -> list[float]:
        """Extract numeric values for a metric from snapshots."""
        values: list[float] = []

        for snap in snapshots:
            if metric_name == DriftType.ERROR_RATE:
                if snap.total_actions > 0:
                    values.append(snap.blocked_count / snap.total_actions)
                else:
                    values.append(0.0)
            elif metric_name == DriftType.ACTION_FREQUENCY:
                if snap.period_minutes > 0:
                    values.append(snap.total_actions / snap.period_minutes)
                else:
                    values.append(0.0)
            elif metric_name == DriftType.TOOL_DISTRIBUTION:
                dist = _normalize(snap.action_counts)
                values.append(self._entropy(dist))
            elif metric_name == DriftType.TOKEN_USAGE:
                values.append(float(snap.total_tokens))
            elif metric_name == DriftType.RESPONSE_LATENCY:
                values.append(snap.avg_latency_ms)

        return values

    @staticmethod
    def _build_message(
        agent_id: str,
        metric_name: str,
        baseline: float,
        current: float,
        deviation: float,
        drifted: bool,
    ) -> str:
        """Build a human-readable drift message."""
        status = "DRIFT DETECTED" if drifted else "within normal range"
        return (
            f"Agent '{agent_id}' {metric_name}: {status}. "
            f"Baseline={baseline:.4f}, Current={current:.4f}, "
            f"Deviation={deviation:.2%}."
        )

    # -- configuration from dict/YAML ---------------------------------------

    @classmethod
    def from_config(
        cls,
        config: dict[str, Any],
        *,
        anomaly_detector: AnomalyDetector | None = None,
    ) -> DriftDetector:
        """Create a DriftDetector from a parsed YAML config dict.

        Expected format::

            enabled: true
            baselines:
              - name: tool_distribution
                window: 30d
                threshold: 0.2
                action: warn
        """
        metric_configs: list[DriftMetricConfig] = []
        for item in config.get("baselines", []):
            window_str = str(item.get("window", "30d"))
            metric_configs.append(
                DriftMetricConfig(
                    name=item["name"],
                    window_days=_parse_window(window_str),
                    threshold=float(item.get("threshold", 0.2)),
                    action=DriftAction(item.get("action", "warn")),
                )
            )
        return cls(
            anomaly_detector=anomaly_detector,
            metric_configs=metric_configs,
        )

    def reset(self, agent_id: str | None = None) -> None:
        """Clear baselines and tracking data.

        When *agent_id* is given only that agent's data is cleared.
        Otherwise all data is cleared.
        """
        if agent_id is not None:
            lock = self._get_lock(agent_id)
            with lock:
                keys = [k for k in self._baselines if k[0] == agent_id]
                for k in keys:
                    del self._baselines[k]
                self._latency_samples.pop(agent_id, None)
                self._token_samples.pop(agent_id, None)
        else:
            with self._global_lock:
                self._baselines.clear()
                self._latency_samples.clear()
                self._token_samples.clear()
                self._locks.clear()
