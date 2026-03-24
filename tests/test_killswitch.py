"""Tests for aegis.core.killswitch.

All tests are synchronous — no async/await needed.
"""

import pytest

from aegis.core.killswitch import KillSwitch, KillSwitchStatus, KillSwitchTriggered

# Force sync mode: this module has no async tests.
# pytest-asyncio auto mode can cause hangs with threading + sync fixtures.
pytestmark = [
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
]


class TestKillSwitchBasic:
    def test_not_triggered_by_default(self):
        ks = KillSwitch()
        assert ks.is_triggered is False

    def test_check_passes_when_not_triggered(self):
        ks = KillSwitch()
        ks.check_or_raise(action_type="read")  # Should not raise

    def test_manual_trigger(self):
        ks = KillSwitch()
        ks.trigger("test reason")
        assert ks.is_triggered is True
        with pytest.raises(KillSwitchTriggered, match="test reason"):
            ks.check_or_raise()

    def test_reset_clears_trigger(self):
        ks = KillSwitch()
        ks.trigger("test")
        assert ks.is_triggered is True
        ks.reset()
        assert ks.is_triggered is False
        ks.check_or_raise()  # Should not raise

    def test_status_snapshot(self):
        ks = KillSwitch()
        ks.check_or_raise(cost_usd=1.5)
        ks.check_or_raise(cost_usd=2.0, is_error=True)
        status = ks.status
        assert isinstance(status, KillSwitchStatus)
        assert status.total_actions == 2
        assert status.total_cost_usd == pytest.approx(3.5)
        assert status.total_errors == 1
        assert status.triggered is False


class TestKillSwitchCost:
    def test_triggers_on_cost_threshold(self):
        ks = KillSwitch(max_cost_usd=10.0)
        for _ in range(10):
            ks.check_or_raise(cost_usd=1.0)
        with pytest.raises(KillSwitchTriggered, match="Cost threshold"):
            ks.check_or_raise(cost_usd=1.0)

    def test_no_trigger_under_threshold(self):
        ks = KillSwitch(max_cost_usd=10.0)
        for _ in range(9):
            ks.check_or_raise(cost_usd=1.0)
        # Still under: 9.0 <= 10.0

    def test_cost_none_disables(self):
        ks = KillSwitch(max_cost_usd=None)
        for _ in range(100):
            ks.check_or_raise(cost_usd=100.0)
        assert ks.is_triggered is False


class TestKillSwitchErrorRate:
    def test_triggers_on_high_error_rate(self):
        ks = KillSwitch(max_error_rate=0.5, error_window=10)
        # 6 errors out of 10 = 60% > 50% — triggers on the 10th action
        with pytest.raises(KillSwitchTriggered, match="Error rate"):
            for i in range(11):
                ks.check_or_raise(is_error=(i < 6))

    def test_no_trigger_under_error_rate(self):
        ks = KillSwitch(max_error_rate=0.5, error_window=10)
        # 4 errors out of 10 = 40% < 50%
        for i in range(10):
            ks.check_or_raise(is_error=(i < 4))

    def test_error_rate_needs_full_window(self):
        ks = KillSwitch(max_error_rate=0.5, error_window=10)
        # Only 5 actions (all errors) — window not full, no trigger
        for _ in range(5):
            ks.check_or_raise(is_error=True)
        assert ks.is_triggered is False


class TestKillSwitchForbidden:
    def test_triggers_on_forbidden_action(self):
        ks = KillSwitch(forbidden_actions=["delete_database", "rm_rf"])
        ks.check_or_raise(action_type="read_file")  # OK
        with pytest.raises(KillSwitchTriggered, match="Forbidden action"):
            ks.check_or_raise(action_type="delete_database")

    def test_empty_forbidden_list(self):
        ks = KillSwitch(forbidden_actions=[])
        ks.check_or_raise(action_type="delete_database")  # No trigger


class TestKillSwitchRate:
    def test_triggers_on_rate_exceeded(self):
        ks = KillSwitch(max_actions_per_minute=5)
        for _ in range(5):
            ks.check_or_raise()
        with pytest.raises(KillSwitchTriggered, match="Rate exceeded"):
            ks.check_or_raise()

    def test_no_trigger_under_rate(self):
        ks = KillSwitch(max_actions_per_minute=100)
        for _ in range(50):
            ks.check_or_raise()
        assert ks.is_triggered is False


class TestKillSwitchAutoShutdown:
    def test_triggers_after_timeout(self):
        ks = KillSwitch(auto_shutdown_after=0.0)  # Immediately
        with pytest.raises(KillSwitchTriggered, match="Auto-shutdown"):
            ks.check_or_raise()


class TestKillSwitchCallback:
    def test_on_trigger_callback(self):
        captured = {}

        def on_trigger(reason, status):
            captured["reason"] = reason
            captured["status"] = status

        ks = KillSwitch(max_cost_usd=1.0, on_trigger=on_trigger)
        ks.check_or_raise(cost_usd=0.5)
        with pytest.raises(KillSwitchTriggered):
            ks.check_or_raise(cost_usd=1.0)

        assert "reason" in captured
        assert "Cost threshold" in captured["reason"]
        assert captured["status"].triggered is True

    def test_callback_error_doesnt_block_trigger(self):
        def bad_callback(reason, status):
            raise ValueError("callback error")

        ks = KillSwitch(max_cost_usd=1.0, on_trigger=bad_callback)
        with pytest.raises(KillSwitchTriggered):
            ks.check_or_raise(cost_usd=2.0)


class TestKillSwitchMultiTrigger:
    def test_stays_triggered_after_multiple_checks(self):
        ks = KillSwitch()
        ks.trigger("first")
        with pytest.raises(KillSwitchTriggered, match="first"):
            ks.check_or_raise()
        with pytest.raises(KillSwitchTriggered, match="first"):
            ks.check_or_raise()

    def test_combined_triggers(self):
        ks = KillSwitch(
            max_cost_usd=5.0,
            max_actions_per_minute=100,
            forbidden_actions=["nuke"],
        )
        ks.check_or_raise(action_type="read", cost_usd=1.0)
        ks.check_or_raise(action_type="write", cost_usd=2.0)
        assert ks.is_triggered is False
        assert ks.status.total_cost_usd == pytest.approx(3.0)


class TestKillSwitchThreadSafety:
    def test_lock_exists(self):
        """Kill switch uses a threading lock for thread safety."""
        import threading

        ks = KillSwitch()
        assert isinstance(ks._lock, type(threading.Lock()))
