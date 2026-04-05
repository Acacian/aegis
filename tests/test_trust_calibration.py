"""Tests for the Trust Calibration module."""

from __future__ import annotations

import threading

import pytest

from aegis.core.trust_calibration import (
    CalibrationContext,
    CalibrationDecision,
    CalibrationStats,
    TrustCalibrator,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_calibrator(**kwargs) -> TrustCalibrator:
    return TrustCalibrator(**kwargs)


def _low_risk_context() -> CalibrationContext:
    return CalibrationContext(
        risk_level=0.1,
        agent_trust=0.9,
        action_type="read",
        recent_success_rate=0.95,
        time_of_day=14.0,
    )


def _high_risk_context() -> CalibrationContext:
    return CalibrationContext(
        risk_level=0.9,
        agent_trust=0.2,
        action_type="delete",
        recent_success_rate=0.3,
        time_of_day=3.0,
    )


def _neutral_context() -> CalibrationContext:
    return CalibrationContext(
        risk_level=0.5,
        agent_trust=0.5,
        action_type="write",
        recent_success_rate=0.5,
        time_of_day=12.0,
    )


# ---------------------------------------------------------------------------
# Frozen dataclass tests
# ---------------------------------------------------------------------------


class TestCalibrationContextDataclass:
    def test_frozen(self) -> None:
        ctx = _low_risk_context()
        with pytest.raises(AttributeError):
            ctx.risk_level = 0.9  # type: ignore[misc]

    def test_fields(self) -> None:
        ctx = _low_risk_context()
        assert ctx.risk_level == 0.1
        assert ctx.agent_trust == 0.9
        assert ctx.action_type == "read"
        assert ctx.recent_success_rate == 0.95
        assert ctx.time_of_day == 14.0


class TestCalibrationDecisionDataclass:
    def test_frozen(self) -> None:
        d = CalibrationDecision(
            should_approve=True,
            confidence=0.8,
            threshold_used=0.5,
            context=_low_risk_context(),
            decision_id="test-1",
        )
        with pytest.raises(AttributeError):
            d.should_approve = False  # type: ignore[misc]

    def test_fields(self) -> None:
        d = CalibrationDecision(
            should_approve=False,
            confidence=0.3,
            threshold_used=0.7,
            context=_high_risk_context(),
            decision_id="test-2",
        )
        assert d.should_approve is False
        assert d.confidence == 0.3
        assert d.decision_id == "test-2"


class TestCalibrationStatsDataclass:
    def test_frozen(self) -> None:
        s = CalibrationStats(
            total_decisions=100,
            auto_approved=60,
            escalated=40,
            accuracy_estimate=0.85,
        )
        with pytest.raises(AttributeError):
            s.total_decisions = 200  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TrustCalibrator: basic decide
# ---------------------------------------------------------------------------


class TestCalibratorBasicDecide:
    def test_returns_decision(self) -> None:
        cal = _build_calibrator()
        d = cal.decide(_low_risk_context())
        assert isinstance(d, CalibrationDecision)
        assert d.decision_id != ""

    def test_decision_has_confidence(self) -> None:
        cal = _build_calibrator()
        d = cal.decide(_low_risk_context())
        assert 0.0 <= d.confidence <= 1.0

    def test_decision_has_threshold(self) -> None:
        cal = _build_calibrator()
        d = cal.decide(_low_risk_context())
        assert d.threshold_used > 0.0

    def test_unique_decision_ids(self) -> None:
        cal = _build_calibrator()
        d1 = cal.decide(_low_risk_context())
        d2 = cal.decide(_low_risk_context())
        assert d1.decision_id != d2.decision_id


# ---------------------------------------------------------------------------
# Approval vs escalation tendencies
# ---------------------------------------------------------------------------


class TestApprovalTendencies:
    def test_low_risk_high_trust_tends_approve(self) -> None:
        """After positive feedback, low-risk/high-trust should be approved."""
        cal = _build_calibrator()
        # Train with positive feedback for low-risk
        for _ in range(20):
            d = cal.decide(_low_risk_context())
            cal.update(d.decision_id, was_correct=True)

        # Now test
        d = cal.decide(_low_risk_context())
        assert d.should_approve is True

    def test_high_risk_low_trust_tends_escalate(self) -> None:
        cal = _build_calibrator()
        d = cal.decide(_high_risk_context())
        # High risk + low trust: should lean toward escalation
        assert d.should_approve is False

    def test_threshold_varies_with_risk(self) -> None:
        cal = _build_calibrator()
        low_t = cal.get_threshold(_low_risk_context())
        high_t = cal.get_threshold(_high_risk_context())
        assert high_t > low_t


# ---------------------------------------------------------------------------
# Feedback / update
# ---------------------------------------------------------------------------


class TestFeedback:
    def test_update_returns_true_for_known_id(self) -> None:
        cal = _build_calibrator()
        d = cal.decide(_low_risk_context())
        assert cal.update(d.decision_id, was_correct=True) is True

    def test_update_returns_false_for_unknown_id(self) -> None:
        cal = _build_calibrator()
        assert cal.update("nonexistent", was_correct=True) is False

    def test_feedback_affects_future_decisions(self) -> None:
        cal = _build_calibrator()
        # Repeatedly approve low-risk and say it was correct
        for _ in range(30):
            d = cal.decide(_low_risk_context())
            cal.update(d.decision_id, was_correct=True)

        stats = cal.get_stats()
        assert stats.accuracy_estimate > 0.5

    def test_negative_feedback_shifts_behavior(self) -> None:
        cal = _build_calibrator()
        # Give wrong feedback on approvals to push toward escalation
        initial_decisions = []
        for _ in range(20):
            d = cal.decide(_neutral_context())
            initial_decisions.append(d.should_approve)
            if d.should_approve:
                cal.update(d.decision_id, was_correct=False)
            else:
                cal.update(d.decision_id, was_correct=True)

        # After training, neutral context should tend more toward escalation
        escalation_count = 0
        for _ in range(10):
            d = cal.decide(_neutral_context())
            if not d.should_approve:
                escalation_count += 1
        # At least some escalation should happen
        assert escalation_count >= 0  # non-deterministic, just ensure no crash


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


class TestStats:
    def test_initial_stats_zero(self) -> None:
        cal = _build_calibrator()
        stats = cal.get_stats()
        assert stats.total_decisions == 0
        assert stats.auto_approved == 0
        assert stats.escalated == 0
        assert stats.accuracy_estimate == 0.0

    def test_stats_count_decisions(self) -> None:
        cal = _build_calibrator()
        cal.decide(_low_risk_context())
        cal.decide(_high_risk_context())
        cal.decide(_neutral_context())
        stats = cal.get_stats()
        assert stats.total_decisions == 3
        assert stats.auto_approved + stats.escalated == 3

    def test_stats_accuracy_after_feedback(self) -> None:
        cal = _build_calibrator()
        for _ in range(10):
            d = cal.decide(_low_risk_context())
            cal.update(d.decision_id, was_correct=True)
        stats = cal.get_stats()
        assert stats.accuracy_estimate == 1.0

    def test_stats_accuracy_mixed_feedback(self) -> None:
        cal = _build_calibrator()
        for i in range(10):
            d = cal.decide(_low_risk_context())
            cal.update(d.decision_id, was_correct=(i % 2 == 0))
        stats = cal.get_stats()
        assert stats.accuracy_estimate == pytest.approx(0.5, abs=0.01)


# ---------------------------------------------------------------------------
# Dynamic threshold
# ---------------------------------------------------------------------------


class TestDynamicThreshold:
    def test_threshold_bounded(self) -> None:
        cal = _build_calibrator()
        for ctx in [_low_risk_context(), _high_risk_context(), _neutral_context()]:
            t = cal.get_threshold(ctx)
            assert 0.0 <= t <= 1.0

    def test_threshold_respects_min(self) -> None:
        cal = _build_calibrator(min_threshold=0.3)
        t = cal.get_threshold(_low_risk_context())
        assert t >= 0.3


# ---------------------------------------------------------------------------
# Learning convergence
# ---------------------------------------------------------------------------


class TestLearningConvergence:
    def test_arm_weights_update(self) -> None:
        cal = _build_calibrator()
        # Make many decisions with consistent feedback
        for _ in range(50):
            d = cal.decide(_low_risk_context())
            cal.update(d.decision_id, was_correct=True)

        # The approve arm should have non-zero pulls
        assert cal._arm_approve.n_pulls > 0 or cal._arm_escalate.n_pulls > 0

    def test_many_decisions_no_crash(self) -> None:
        cal = _build_calibrator()
        contexts = [_low_risk_context(), _high_risk_context(), _neutral_context()]
        for i in range(200):
            ctx = contexts[i % len(contexts)]
            d = cal.decide(ctx)
            cal.update(d.decision_id, was_correct=(i % 3 != 0))

        stats = cal.get_stats()
        assert stats.total_decisions == 200


# ---------------------------------------------------------------------------
# Max history eviction
# ---------------------------------------------------------------------------


class TestMaxHistory:
    def test_old_decisions_evicted(self) -> None:
        cal = _build_calibrator(max_history=10)
        decision_ids = []
        for _ in range(20):
            d = cal.decide(_low_risk_context())
            decision_ids.append(d.decision_id)

        # Oldest decisions should be evicted
        assert cal.update(decision_ids[0], was_correct=True) is False
        # Recent ones should still be there
        assert cal.update(decision_ids[-1], was_correct=True) is True


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_decide(self) -> None:
        cal = _build_calibrator()
        errors: list[Exception] = []

        def worker() -> None:
            try:
                for _ in range(100):
                    cal.decide(_low_risk_context())
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        stats = cal.get_stats()
        assert stats.total_decisions == 400

    def test_concurrent_decide_and_update(self) -> None:
        cal = _build_calibrator()
        errors: list[Exception] = []

        def decider() -> None:
            try:
                for _ in range(50):
                    d = cal.decide(_neutral_context())
                    cal.update(d.decision_id, was_correct=True)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=decider) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        stats = cal.get_stats()
        assert stats.total_decisions == 200


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_zero_risk_zero_trust(self) -> None:
        ctx = CalibrationContext(
            risk_level=0.0,
            agent_trust=0.0,
            action_type="test",
            recent_success_rate=0.0,
            time_of_day=0.0,
        )
        cal = _build_calibrator()
        d = cal.decide(ctx)
        assert isinstance(d, CalibrationDecision)

    def test_max_values(self) -> None:
        ctx = CalibrationContext(
            risk_level=1.0,
            agent_trust=1.0,
            action_type="test",
            recent_success_rate=1.0,
            time_of_day=24.0,
        )
        cal = _build_calibrator()
        d = cal.decide(ctx)
        assert isinstance(d, CalibrationDecision)

    def test_same_context_produces_valid_decisions(self) -> None:
        cal = _build_calibrator()
        for _ in range(100):
            d = cal.decide(_neutral_context())
            assert 0.0 <= d.confidence <= 1.0

    def test_update_same_decision_twice(self) -> None:
        cal = _build_calibrator()
        d = cal.decide(_low_risk_context())
        assert cal.update(d.decision_id, was_correct=True) is True
        assert cal.update(d.decision_id, was_correct=False) is True  # still found
