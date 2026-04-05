"""Tests for the Behavioral Drift Detection module."""

from __future__ import annotations

import threading

import pytest

from aegis.core.behavioral_drift import (
    BehavioralBaseline,
    BehaviorSignal,
    DriftDetector,
    DriftFinding,
    DriftReport,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MIN_OBS = 20  # default min_observations


def _populate_baseline(
    detector: DriftDetector,
    agent_id: str = "agent-1",
    count: int = MIN_OBS,
    action_type: str = "read",
    target: str = "database",
    risk_level: str = "low",
) -> None:
    """Feed enough consistent observations to establish a baseline."""
    for _ in range(count):
        detector.observe(agent_id, action_type, target, risk_level)


# ---------------------------------------------------------------------------
# Frozen dataclass smoke tests
# ---------------------------------------------------------------------------


class TestDataModels:
    def test_behavior_signal_frozen(self) -> None:
        sig = BehaviorSignal(agent_id="a", action_type="read", target="db")
        with pytest.raises(AttributeError):
            sig.agent_id = "b"  # type: ignore[misc]

    def test_drift_finding_frozen(self) -> None:
        f = DriftFinding(
            agent_id="a",
            drift_type="action_shift",
            severity="low",
            score=0.5,
            description="test",
        )
        with pytest.raises(AttributeError):
            f.score = 0.9  # type: ignore[misc]

    def test_behavioral_baseline_frozen(self) -> None:
        b = BehavioralBaseline(agent_id="a")
        with pytest.raises(AttributeError):
            b.agent_id = "b"  # type: ignore[misc]

    def test_drift_report_frozen(self) -> None:
        r = DriftReport(total_agents=1, drifting_agents=0)
        with pytest.raises(AttributeError):
            r.total_agents = 5  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Baseline establishment
# ---------------------------------------------------------------------------


class TestBaselineEstablishment:
    def test_no_baseline_before_min_observations(self) -> None:
        d = DriftDetector()
        for _ in range(MIN_OBS - 1):
            d.observe("agent-1", "read", "database")
        assert d.get_baseline("agent-1") is None

    def test_baseline_established_at_min_observations(self) -> None:
        d = DriftDetector()
        _populate_baseline(d, "agent-1")
        bl = d.get_baseline("agent-1")
        assert bl is not None
        assert bl.agent_id == "agent-1"
        assert bl.observation_count == MIN_OBS
        assert bl.action_distribution == {"read": 1.0}
        assert bl.target_distribution == {"database": 1.0}
        assert bl.avg_risk_level == 1.0

    def test_baseline_with_mixed_actions(self) -> None:
        d = DriftDetector()
        for i in range(MIN_OBS):
            action = "read" if i < 16 else "write"
            d.observe("agent-1", action, "database")
        bl = d.get_baseline("agent-1")
        assert bl is not None
        assert bl.action_distribution["read"] == pytest.approx(0.8)
        assert bl.action_distribution["write"] == pytest.approx(0.2)


# ---------------------------------------------------------------------------
# No drift with consistent behavior
# ---------------------------------------------------------------------------


class TestNoDrift:
    def test_consistent_behavior_produces_no_findings(self) -> None:
        d = DriftDetector()
        _populate_baseline(d, "agent-1")
        # Continue with identical behavior.
        for _ in range(30):
            d.observe("agent-1", "read", "database", "low")
        findings = d.check_drift("agent-1")
        assert findings == []

    def test_below_min_observations_returns_empty(self) -> None:
        d = DriftDetector()
        for _ in range(5):
            d.observe("agent-1", "read", "database")
        assert d.check_drift("agent-1") == []


# ---------------------------------------------------------------------------
# Action distribution shift
# ---------------------------------------------------------------------------


class TestActionShift:
    def test_action_distribution_shift_detected(self) -> None:
        d = DriftDetector(drift_threshold=0.2)
        # Baseline: 100% read
        _populate_baseline(d, "agent-1", action_type="read")
        # Shift: 100% delete
        for _ in range(MIN_OBS):
            d.observe("agent-1", "delete", "database", "low")
        findings = d.check_drift("agent-1")
        shifts = [f for f in findings if f.drift_type == "action_shift"]
        assert len(shifts) >= 1
        assert shifts[0].score > 0.0

    def test_small_shift_below_threshold(self) -> None:
        d = DriftDetector(drift_threshold=0.5)
        # Baseline: 80% read, 20% write
        for i in range(MIN_OBS):
            d.observe("agent-1", "read" if i < 16 else "write", "database")
        # Slight shift: 70% read, 30% write -- small change
        for i in range(MIN_OBS):
            d.observe("agent-1", "read" if i < 14 else "write", "database")
        findings = d.check_drift("agent-1")
        shifts = [f for f in findings if f.drift_type == "action_shift"]
        assert len(shifts) == 0


# ---------------------------------------------------------------------------
# Risk escalation
# ---------------------------------------------------------------------------


class TestRiskEscalation:
    def test_risk_escalation_detected(self) -> None:
        d = DriftDetector(drift_threshold=0.2)
        _populate_baseline(d, "agent-1", risk_level="low")
        # Escalate to critical.
        for _ in range(MIN_OBS):
            d.observe("agent-1", "read", "database", "critical")
        findings = d.check_drift("agent-1")
        esc = [f for f in findings if f.drift_type == "risk_escalation"]
        assert len(esc) >= 1
        assert esc[0].score > 0.0
        assert esc[0].current_value > esc[0].baseline_value

    def test_no_escalation_when_risk_stable(self) -> None:
        d = DriftDetector()
        _populate_baseline(d, "agent-1", risk_level="medium")
        for _ in range(MIN_OBS):
            d.observe("agent-1", "read", "database", "medium")
        findings = d.check_drift("agent-1")
        esc = [f for f in findings if f.drift_type == "risk_escalation"]
        assert len(esc) == 0


# ---------------------------------------------------------------------------
# Target novelty
# ---------------------------------------------------------------------------


class TestTargetNovelty:
    def test_novel_target_detected(self) -> None:
        d = DriftDetector(drift_threshold=0.2)
        _populate_baseline(d, "agent-1", target="database")
        # All new targets.
        for _ in range(MIN_OBS):
            d.observe("agent-1", "read", "admin_panel", "low")
        findings = d.check_drift("agent-1")
        novel = [f for f in findings if f.drift_type == "target_novelty"]
        assert len(novel) >= 1
        assert "admin_panel" in novel[0].description

    def test_no_novelty_with_known_targets(self) -> None:
        d = DriftDetector()
        _populate_baseline(d, "agent-1", target="database")
        for _ in range(MIN_OBS):
            d.observe("agent-1", "read", "database", "low")
        findings = d.check_drift("agent-1")
        novel = [f for f in findings if f.drift_type == "target_novelty"]
        assert len(novel) == 0


# ---------------------------------------------------------------------------
# Velocity anomaly
# ---------------------------------------------------------------------------


class TestVelocityAnomaly:
    def test_velocity_spike_detected(self) -> None:
        d = DriftDetector(min_observations=10, drift_threshold=0.2)
        # Baseline: slow -- 1 signal per 0.1s
        for i in range(10):
            sig = BehaviorSignal(
                agent_id="agent-1",
                action_type="read",
                target="database",
                timestamp=1000.0 + i * 0.1,
            )
            with d._lock:
                buf = d._signals.setdefault("agent-1", [])
                buf.append(sig)
                if len(buf) == d._min_observations:
                    d._build_baseline("agent-1")
        # Rapid burst: 20 signals in 0.02s total
        for i in range(20):
            sig = BehaviorSignal(
                agent_id="agent-1",
                action_type="read",
                target="database",
                timestamp=1001.0 + i * 0.001,
            )
            with d._lock:
                d._signals["agent-1"].append(sig)
        findings = d.check_drift("agent-1")
        vel = [f for f in findings if f.drift_type == "velocity_anomaly"]
        assert len(vel) >= 1
        assert vel[0].score > 0.0

    def test_no_velocity_anomaly_with_steady_rate(self) -> None:
        d = DriftDetector(min_observations=10, drift_threshold=0.3)
        # Uniform rate throughout.
        for i in range(30):
            sig = BehaviorSignal(
                agent_id="agent-1",
                action_type="read",
                target="database",
                timestamp=1000.0 + i * 0.1,
            )
            with d._lock:
                buf = d._signals.setdefault("agent-1", [])
                buf.append(sig)
                if len(buf) == d._min_observations:
                    d._build_baseline("agent-1")
        findings = d.check_drift("agent-1")
        vel = [f for f in findings if f.drift_type == "velocity_anomaly"]
        assert len(vel) == 0


# ---------------------------------------------------------------------------
# Repetition anomaly
# ---------------------------------------------------------------------------


class TestRepetitionAnomaly:
    def test_repetition_anomaly_detected(self) -> None:
        d = DriftDetector(min_observations=10, drift_threshold=0.2)
        # Build a varied baseline.
        actions = ["read", "write", "delete", "read", "list"]
        for i in range(10):
            d.observe("agent-1", actions[i % len(actions)], "database")
        # Then hammer the same action repeatedly.
        for _ in range(20):
            d.observe("agent-1", "read", "database")
        findings = d.check_drift("agent-1")
        rep = [f for f in findings if f.drift_type == "repetition_anomaly"]
        assert len(rep) >= 1
        assert rep[0].current_value > 2

    def test_no_repetition_with_varied_actions(self) -> None:
        d = DriftDetector(min_observations=10, drift_threshold=0.3)
        actions = ["read", "write", "delete", "list", "update"]
        for i in range(30):
            d.observe("agent-1", actions[i % len(actions)], "database")
        findings = d.check_drift("agent-1")
        rep = [f for f in findings if f.drift_type == "repetition_anomaly"]
        assert len(rep) == 0


# ---------------------------------------------------------------------------
# Multiple agents tracked independently
# ---------------------------------------------------------------------------


class TestMultipleAgents:
    def test_agents_tracked_independently(self) -> None:
        d = DriftDetector(drift_threshold=0.2)
        # Agent-1: stable reads
        _populate_baseline(d, "agent-1", action_type="read")
        for _ in range(MIN_OBS):
            d.observe("agent-1", "read", "database", "low")

        # Agent-2: starts stable, then drifts to deletes
        _populate_baseline(d, "agent-2", action_type="read")
        for _ in range(MIN_OBS):
            d.observe("agent-2", "delete", "database", "critical")

        findings_1 = d.check_drift("agent-1")
        findings_2 = d.check_drift("agent-2")

        # Agent-1 should be clean; Agent-2 should have findings.
        assert len(findings_1) == 0
        assert len(findings_2) > 0
        assert all(f.agent_id == "agent-2" for f in findings_2)

    def test_unknown_agent_returns_no_baseline(self) -> None:
        d = DriftDetector()
        assert d.get_baseline("nonexistent") is None
        assert d.check_drift("nonexistent") == []


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


class TestReport:
    def test_report_with_no_agents(self) -> None:
        d = DriftDetector()
        r = d.report()
        assert r.total_agents == 0
        assert r.drifting_agents == 0
        assert r.findings == []

    def test_report_with_drifting_agent(self) -> None:
        d = DriftDetector(drift_threshold=0.2)
        _populate_baseline(d, "agent-1", action_type="read")
        for _ in range(MIN_OBS):
            d.observe("agent-1", "delete", "admin_panel", "critical")
        r = d.report()
        assert r.total_agents == 1
        assert r.drifting_agents == 1
        assert len(r.findings) > 0

    def test_report_with_mixed_agents(self) -> None:
        d = DriftDetector(drift_threshold=0.2)
        # Stable agent.
        _populate_baseline(d, "stable")
        for _ in range(MIN_OBS):
            d.observe("stable", "read", "database", "low")
        # Drifting agent.
        _populate_baseline(d, "drifter", action_type="read")
        for _ in range(MIN_OBS):
            d.observe("drifter", "delete", "admin_panel", "critical")
        r = d.report()
        assert r.total_agents == 2
        assert r.drifting_agents == 1


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_observe_and_check(self) -> None:
        d = DriftDetector(min_observations=10, drift_threshold=0.3)
        errors: list[Exception] = []

        def observer() -> None:
            try:
                for _ in range(50):
                    d.observe("agent-1", "read", "database")
            except Exception as exc:
                errors.append(exc)

        def checker() -> None:
            try:
                for _ in range(50):
                    d.check_drift("agent-1")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=observer) for _ in range(4)]
        threads += [threading.Thread(target=checker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        assert errors == []


# ---------------------------------------------------------------------------
# Drift score severity mapping
# ---------------------------------------------------------------------------


class TestSeverityMapping:
    def test_severity_levels(self) -> None:
        from aegis.core.behavioral_drift import _severity_from_score

        assert _severity_from_score(0.1) == "low"
        assert _severity_from_score(0.4) == "medium"
        assert _severity_from_score(0.6) == "high"
        assert _severity_from_score(0.9) == "critical"
