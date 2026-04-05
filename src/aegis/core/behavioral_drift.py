"""Behavioral Drift Detection for AI agents (OWASP ASI10 -- Rogue Agents).

Maintains per-agent baselines from a sliding observation window and
detects deviations across five axes: action distribution shift, risk
escalation, target novelty, velocity anomaly, and repetition anomaly.

Thread-safe via :class:`threading.Lock`.  Pure Python, no external deps.

References:
- OWASP Agentic AI Threats ASI10: https://owasp.org/www-project-agentic-ai-threats/
- Amodei et al. "Concrete Problems in AI Safety": https://arxiv.org/abs/1606.06565
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_RISK_MAP: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BehaviorSignal:
    """A single observed agent behavior."""

    agent_id: str
    action_type: str
    target: str
    risk_level: str = "low"
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DriftFinding:
    """A single detected drift deviation (score 0.0-1.0)."""

    agent_id: str
    drift_type: str
    severity: str
    score: float
    description: str
    baseline_value: Any = None
    current_value: Any = None
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BehavioralBaseline:
    """Established behavioral profile for an agent."""

    agent_id: str
    action_distribution: dict[str, float] = field(default_factory=dict)
    target_distribution: dict[str, float] = field(default_factory=dict)
    avg_risk_level: float = 1.0
    observation_count: int = 0
    established_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class DriftReport:
    """Summary report across all tracked agents."""

    total_agents: int
    drifting_agents: int
    findings: list[DriftFinding] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _to_distribution(items: list[str]) -> dict[str, float]:
    """Return frequency-ratio distribution from a list of strings."""
    if not items:
        return {}
    counts: dict[str, int] = {}
    for item in items:
        counts[item] = counts.get(item, 0) + 1
    total = len(items)
    return {k: v / total for k, v in counts.items()}


def _distribution_distance(a: dict[str, float], b: dict[str, float]) -> float:
    """Sum of absolute differences in frequency ratios (0.0-2.0 range)."""
    keys = set(a) | set(b)
    return sum(abs(a.get(k, 0.0) - b.get(k, 0.0)) for k in keys)


def _severity_from_score(score: float) -> str:
    """Map a 0.0-1.0 score to a severity label."""
    if score >= 0.8:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------


class DriftDetector:
    """Maintains per-agent behavioral baselines and detects drift.

    Parameters
    ----------
    baseline_window:
        Number of most-recent observations to retain per agent.
    drift_threshold:
        Minimum score (0.0-1.0) for a finding to be reported.
    min_observations:
        Observations required before drift checking activates.
    """

    def __init__(
        self,
        baseline_window: int = 100,
        drift_threshold: float = 0.3,
        min_observations: int = 20,
    ) -> None:
        self._baseline_window = baseline_window
        self._drift_threshold = drift_threshold
        self._min_observations = min_observations

        self._signals: dict[str, list[BehaviorSignal]] = {}
        self._baselines: dict[str, BehavioralBaseline] = {}
        self._lock = threading.Lock()

    # -- public API --------------------------------------------------------

    def observe(
        self,
        agent_id: str,
        action_type: str,
        target: str,
        risk_level: str = "low",
    ) -> None:
        """Record an agent behavior observation.

        The first *min_observations* signals are used to establish the
        baseline.  Subsequent signals are compared against it.
        """
        signal = BehaviorSignal(
            agent_id=agent_id,
            action_type=action_type,
            target=target,
            risk_level=risk_level,
        )
        with self._lock:
            buf = self._signals.setdefault(agent_id, [])
            buf.append(signal)
            # Keep the sliding window bounded.
            if len(buf) > self._baseline_window * 2:
                self._signals[agent_id] = buf[-self._baseline_window * 2 :]

            # Build / rebuild baseline once we have enough observations.
            if len(buf) >= self._min_observations and agent_id not in self._baselines:
                self._build_baseline(agent_id)

    def check_drift(self, agent_id: str) -> list[DriftFinding]:
        """Check for behavioral drift against the established baseline.

        Returns an empty list when the agent has no baseline yet (i.e.
        fewer than *min_observations*).
        """
        with self._lock:
            baseline = self._baselines.get(agent_id)
            signals = self._signals.get(agent_id, [])

        if baseline is None or len(signals) < self._min_observations:
            return []

        # Compare the most recent half of the window against baseline.
        recent = signals[-(self._min_observations) :]
        findings: list[DriftFinding] = []

        findings.extend(self._check_action_shift(agent_id, baseline, recent))
        findings.extend(self._check_risk_escalation(agent_id, baseline, recent))
        findings.extend(self._check_target_novelty(agent_id, baseline, recent))
        findings.extend(self._check_velocity(agent_id, baseline, signals))
        findings.extend(self._check_repetition(agent_id, baseline, signals))

        return [f for f in findings if f.score >= self._drift_threshold]

    def get_baseline(self, agent_id: str) -> BehavioralBaseline | None:
        """Return the established baseline for *agent_id*, or ``None``."""
        with self._lock:
            return self._baselines.get(agent_id)

    def report(self) -> DriftReport:
        """Generate a summary report across all tracked agents."""
        with self._lock:
            agent_ids = list(self._signals.keys())

        all_findings: list[DriftFinding] = []
        drifting: set[str] = set()
        for aid in agent_ids:
            findings = self.check_drift(aid)
            if findings:
                drifting.add(aid)
                all_findings.extend(findings)

        return DriftReport(
            total_agents=len(agent_ids),
            drifting_agents=len(drifting),
            findings=all_findings,
        )

    # -- baseline construction ---------------------------------------------

    def _build_baseline(self, agent_id: str) -> None:
        """Build a baseline from the first *min_observations* signals.

        Must be called with ``self._lock`` held.
        """
        signals = self._signals[agent_id][: self._min_observations]

        action_types = [s.action_type for s in signals]
        targets = [s.target for s in signals]
        risk_values = [_RISK_MAP.get(s.risk_level, 1) for s in signals]

        self._baselines[agent_id] = BehavioralBaseline(
            agent_id=agent_id,
            action_distribution=_to_distribution(action_types),
            target_distribution=_to_distribution(targets),
            avg_risk_level=sum(risk_values) / len(risk_values),
            observation_count=len(signals),
        )

    # -- drift checks ------------------------------------------------------

    def _check_action_shift(
        self,
        agent_id: str,
        baseline: BehavioralBaseline,
        recent: list[BehaviorSignal],
    ) -> list[DriftFinding]:
        current_dist = _to_distribution([s.action_type for s in recent])
        distance = _distribution_distance(baseline.action_distribution, current_dist)
        # Normalize: max distance is 2.0 (completely disjoint distributions).
        score = min(distance / 2.0, 1.0)
        if score < self._drift_threshold:
            return []
        return [
            DriftFinding(
                agent_id=agent_id,
                drift_type="action_shift",
                severity=_severity_from_score(score),
                score=score,
                description=(f"Action distribution shifted (distance={distance:.3f})."),
                baseline_value=baseline.action_distribution,
                current_value=current_dist,
                evidence={"distance": distance},
            )
        ]

    def _check_risk_escalation(
        self,
        agent_id: str,
        baseline: BehavioralBaseline,
        recent: list[BehaviorSignal],
    ) -> list[DriftFinding]:
        risk_values = [_RISK_MAP.get(s.risk_level, 1) for s in recent]
        current_avg = sum(risk_values) / len(risk_values)
        delta = current_avg - baseline.avg_risk_level
        # Normalize: max delta is 3.0 (low→critical).
        score = min(max(delta / 3.0, 0.0), 1.0)
        if score < self._drift_threshold:
            return []
        return [
            DriftFinding(
                agent_id=agent_id,
                drift_type="risk_escalation",
                severity=_severity_from_score(score),
                score=score,
                description=(
                    f"Risk level escalated from {baseline.avg_risk_level:.2f} "
                    f"to {current_avg:.2f}."
                ),
                baseline_value=baseline.avg_risk_level,
                current_value=current_avg,
                evidence={"delta": delta},
            )
        ]

    def _check_target_novelty(
        self,
        agent_id: str,
        baseline: BehavioralBaseline,
        recent: list[BehaviorSignal],
    ) -> list[DriftFinding]:
        baseline_targets = set(baseline.target_distribution.keys())
        recent_targets = [s.target for s in recent]
        novel = [t for t in recent_targets if t not in baseline_targets]
        if not novel:
            return []
        score = min(len(novel) / len(recent_targets), 1.0)
        if score < self._drift_threshold:
            return []
        novel_set = sorted(set(novel))
        return [
            DriftFinding(
                agent_id=agent_id,
                drift_type="target_novelty",
                severity=_severity_from_score(score),
                score=score,
                description=(
                    f"Agent accessing {len(novel_set)} novel target(s): {', '.join(novel_set)}."
                ),
                baseline_value=sorted(baseline_targets),
                current_value=novel_set,
                evidence={"novel_fraction": score, "novel_targets": novel_set},
            )
        ]

    def _check_velocity(
        self,
        agent_id: str,
        baseline: BehavioralBaseline,
        signals: list[BehaviorSignal],
    ) -> list[DriftFinding]:
        if len(signals) < self._min_observations + 10:
            return []

        baseline_signals = signals[: self._min_observations]
        recent_signals = signals[-self._min_observations :]

        def _rate(sigs: list[BehaviorSignal]) -> float:
            if len(sigs) < 2:
                return 0.0
            span = sigs[-1].timestamp - sigs[0].timestamp
            if span <= 0:
                return float(len(sigs))
            return len(sigs) / span

        baseline_rate = _rate(baseline_signals)
        current_rate = _rate(recent_signals)

        if baseline_rate <= 0:
            return []

        ratio = current_rate / baseline_rate
        score = min(max((ratio - 1.0) / 9.0, 0.0), 1.0)  # 10x → score 1.0
        if score < self._drift_threshold:
            return []
        return [
            DriftFinding(
                agent_id=agent_id,
                drift_type="velocity_anomaly",
                severity=_severity_from_score(score),
                score=score,
                description=(
                    f"Action velocity {ratio:.1f}x baseline "
                    f"({current_rate:.2f}/s vs {baseline_rate:.2f}/s)."
                ),
                baseline_value=baseline_rate,
                current_value=current_rate,
                evidence={"ratio": ratio},
            )
        ]

    def _check_repetition(
        self,
        agent_id: str,
        baseline: BehavioralBaseline,
        signals: list[BehaviorSignal],
    ) -> list[DriftFinding]:
        if len(signals) < self._min_observations:
            return []

        # If the baseline itself is mono-action (only 1 action+target pair),
        # then long consecutive runs of that pair are expected, not anomalous.
        baseline_diversity = len(baseline.action_distribution) * len(baseline.target_distribution)
        if baseline_diversity <= 1:
            return []

        # Count the longest tail run of identical (action_type, target) pairs.
        tail = signals[-self._min_observations :]
        max_run = 1
        current_run = 1
        for i in range(1, len(tail)):
            if (
                tail[i].action_type == tail[i - 1].action_type
                and tail[i].target == tail[i - 1].target
            ):
                current_run += 1
                max_run = max(max_run, current_run)
            else:
                current_run = 1

        # Normalize: a run of min_observations/2 or more → score 1.0.
        threshold_run = max(self._min_observations // 2, 3)
        score = min(max((max_run - 2) / (threshold_run - 2), 0.0), 1.0)
        if score < self._drift_threshold:
            return []
        return [
            DriftFinding(
                agent_id=agent_id,
                drift_type="repetition_anomaly",
                severity=_severity_from_score(score),
                score=score,
                description=(
                    f"Detected {max_run} consecutive identical actions "
                    f"(possible reward-hacking loop)."
                ),
                baseline_value=1,
                current_value=max_run,
                evidence={"max_consecutive_run": max_run},
            )
        ]
