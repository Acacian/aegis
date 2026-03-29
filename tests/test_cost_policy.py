"""Tests for aegis.core.cost_policy — Cost governance as policy dimension."""

from __future__ import annotations

import time

import pytest

from aegis.config import CostConfig
from aegis.core.budget import TokenUsage
from aegis.core.cost_policy import (
    CostAction,
    CostDecision,
    CostPolicyEnforcer,
    _DailyTracker,
    _TokenRateTracker,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cheap_usage(model: str = "gpt-4o-mini", n: int = 100) -> TokenUsage:
    """Small token usage that costs fractions of a cent."""
    return TokenUsage(model=model, input_tokens=n, output_tokens=n)


def _expensive_usage(model: str = "gpt-4o", n: int = 500_000) -> TokenUsage:
    """Large token usage that costs several dollars."""
    return TokenUsage(model=model, input_tokens=n, output_tokens=n)


# ---------------------------------------------------------------------------
# Per-call limit
# ---------------------------------------------------------------------------


class TestPerCallLimit:
    def test_block_expensive_call(self):
        """Per-call limit blocks a single call that exceeds the limit."""
        cfg = CostConfig(per_call_limit_usd=0.01, on_exceed="block")
        enforcer = CostPolicyEnforcer(cfg)
        usage = _expensive_usage()
        decision = enforcer.check_and_record(usage)
        assert decision.blocked
        assert decision.dimension == "per_call"
        assert enforcer.session_spent == 0.0  # not recorded

    def test_allow_cheap_call(self):
        """Per-call limit allows a cheap call."""
        cfg = CostConfig(per_call_limit_usd=10.0, on_exceed="block")
        enforcer = CostPolicyEnforcer(cfg)
        usage = _cheap_usage()
        decision = enforcer.check_and_record(usage)
        assert decision.allowed
        assert enforcer.session_spent > 0.0

    def test_warn_on_exceed(self):
        """When on_exceed=warn, expensive call goes through with warning."""
        cfg = CostConfig(per_call_limit_usd=0.01, on_exceed="warn")
        enforcer = CostPolicyEnforcer(cfg)
        usage = _expensive_usage()
        decision = enforcer.check_and_record(usage)
        assert decision.action == CostAction.WARN
        assert not decision.blocked
        assert decision.dimension == "per_call"


# ---------------------------------------------------------------------------
# Per-session limit
# ---------------------------------------------------------------------------


class TestPerSessionLimit:
    def test_block_when_session_exceeds(self):
        """Session limit blocks when cumulative spend exceeds."""
        cfg = CostConfig(per_session_limit_usd=0.001, on_exceed="block")
        enforcer = CostPolicyEnforcer(cfg)
        usage = TokenUsage(model="gpt-4o", input_tokens=10000, output_tokens=10000)
        # This should push past $0.001
        decision = enforcer.check_and_record(usage)
        assert decision.blocked
        assert decision.dimension == "per_session"

    def test_allow_within_session_limit(self):
        """Session limit allows calls within budget."""
        cfg = CostConfig(per_session_limit_usd=100.0, on_exceed="block")
        enforcer = CostPolicyEnforcer(cfg)
        usage = _cheap_usage()
        decision = enforcer.check_and_record(usage)
        assert decision.allowed


# ---------------------------------------------------------------------------
# Daily budget
# ---------------------------------------------------------------------------


class TestDailyBudget:
    def test_block_when_daily_exceeds(self):
        """Daily budget blocks when daily spend exceeds."""
        cfg = CostConfig(daily_budget_usd=0.001, on_exceed="block")
        enforcer = CostPolicyEnforcer(cfg)
        usage = TokenUsage(model="gpt-4o", input_tokens=10000, output_tokens=10000)
        decision = enforcer.check_and_record(usage)
        assert decision.blocked
        assert decision.dimension == "daily"

    def test_allow_within_daily_budget(self):
        """Daily budget allows calls within limit."""
        cfg = CostConfig(daily_budget_usd=1000.0, on_exceed="block")
        enforcer = CostPolicyEnforcer(cfg)
        usage = _cheap_usage()
        decision = enforcer.check_and_record(usage)
        assert decision.allowed


# ---------------------------------------------------------------------------
# Per-minute token rate
# ---------------------------------------------------------------------------


class TestPerMinuteTokens:
    def test_block_when_rate_exceeds(self):
        """Per-minute token rate blocks when rate is exceeded."""
        cfg = CostConfig(per_minute_tokens=100, on_exceed="block")
        enforcer = CostPolicyEnforcer(cfg)
        # First call adds 200 tokens
        usage = _cheap_usage(n=200)
        # Should block because 200 + 200 = 400 > 100
        decision = enforcer.check_and_record(usage)
        assert decision.blocked
        assert decision.dimension == "per_minute_tokens"

    def test_allow_within_rate(self):
        """Per-minute token rate allows calls within limit."""
        cfg = CostConfig(per_minute_tokens=1_000_000, on_exceed="block")
        enforcer = CostPolicyEnforcer(cfg)
        usage = _cheap_usage()
        decision = enforcer.check_and_record(usage)
        assert decision.allowed


# ---------------------------------------------------------------------------
# Overall budget + alert threshold
# ---------------------------------------------------------------------------


class TestOverallBudget:
    def test_block_over_budget(self):
        """Overall budget blocks when total exceeds."""
        cfg = CostConfig(budget_usd=0.001, on_exceed="block")
        enforcer = CostPolicyEnforcer(cfg)
        usage = TokenUsage(model="gpt-4o", input_tokens=10000, output_tokens=10000)
        decision = enforcer.check_and_record(usage)
        assert decision.blocked
        assert decision.dimension == "budget"

    def test_warn_at_alert_threshold(self):
        """Alert threshold triggers a warn decision."""
        cfg = CostConfig(budget_usd=1.0, alert_threshold=0.01, on_exceed="block")
        enforcer = CostPolicyEnforcer(cfg)
        # Even a small call will be >1% of $1
        usage = TokenUsage(model="gpt-4o", input_tokens=1000, output_tokens=1000)
        decision = enforcer.check_and_record(usage)
        # Should be WARN (alert threshold), not BLOCK
        assert decision.action == CostAction.WARN
        assert decision.dimension == "budget_alert"


# ---------------------------------------------------------------------------
# on_exceed modes
# ---------------------------------------------------------------------------


class TestOnExceedModes:
    def test_block_mode(self):
        """on_exceed=block prevents recording."""
        cfg = CostConfig(per_call_limit_usd=0.0001, on_exceed="block")
        enforcer = CostPolicyEnforcer(cfg)
        decision = enforcer.check_and_record(_expensive_usage())
        assert decision.blocked
        assert enforcer.session_spent == 0.0

    def test_warn_mode(self):
        """on_exceed=warn records but returns warn."""
        cfg = CostConfig(per_call_limit_usd=0.0001, on_exceed="warn")
        enforcer = CostPolicyEnforcer(cfg)
        decision = enforcer.check_and_record(_expensive_usage())
        assert decision.action == CostAction.WARN
        assert not decision.blocked
        # Usage IS recorded in warn mode
        assert enforcer.session_spent > 0.0

    def test_log_mode(self):
        """on_exceed=log behaves like warn (non-blocking)."""
        cfg = CostConfig(per_call_limit_usd=0.0001, on_exceed="log")
        enforcer = CostPolicyEnforcer(cfg)
        decision = enforcer.check_and_record(_expensive_usage())
        assert decision.action == CostAction.WARN
        assert not decision.blocked


# ---------------------------------------------------------------------------
# Pre-check (no recording)
# ---------------------------------------------------------------------------


class TestPreCheck:
    def test_pre_check_does_not_record(self):
        """pre_check evaluates without recording cost."""
        cfg = CostConfig(budget_usd=100.0, on_exceed="block")
        enforcer = CostPolicyEnforcer(cfg)
        decision = enforcer.pre_check(_cheap_usage())
        assert decision.allowed
        assert enforcer.session_spent == 0.0  # nothing recorded


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


class TestReport:
    def test_report_structure(self):
        """get_report returns expected structure."""
        cfg = CostConfig(
            budget_usd=100.0,
            per_session_limit_usd=5.0,
            daily_budget_usd=50.0,
            per_minute_tokens=100_000,
        )
        enforcer = CostPolicyEnforcer(cfg, session_id="test-session")
        enforcer.check_and_record(_cheap_usage())

        report = enforcer.get_report()
        assert report["session_id"] == "test-session"
        assert "limits" in report
        assert report["limits"]["budget_usd"] == 100.0
        assert report["limits"]["per_session_limit_usd"] == 5.0
        assert report["limits"]["daily_budget_usd"] == 50.0
        assert report["limits"]["per_minute_tokens"] == 100_000
        assert "daily_spent" in report
        assert "tokens_last_minute" in report


# ---------------------------------------------------------------------------
# Token rate tracker unit tests
# ---------------------------------------------------------------------------


class TestTokenRateTracker:
    def test_rolling_window(self):
        """Entries outside the window are pruned."""
        tracker = _TokenRateTracker(window_seconds=10.0)
        now = time.time()
        tracker.add(100, now=now - 15)  # outside window
        tracker.add(200, now=now - 5)  # inside window
        tracker.add(300, now=now)  # inside window
        assert tracker.total_in_window(now=now) == 500

    def test_empty_tracker(self):
        tracker = _TokenRateTracker()
        assert tracker.total_in_window() == 0


# ---------------------------------------------------------------------------
# Daily tracker unit tests
# ---------------------------------------------------------------------------


class TestDailyTracker:
    def test_accumulates_same_day(self):
        tracker = _DailyTracker()
        now = time.time()
        tracker.add(1.0, now=now)
        tracker.add(2.0, now=now)
        assert tracker.spent_today == pytest.approx(3.0)


# ---------------------------------------------------------------------------
# CostDecision properties
# ---------------------------------------------------------------------------


class TestCostDecision:
    def test_allowed_property(self):
        assert CostDecision(action=CostAction.ALLOW).allowed is True
        assert CostDecision(action=CostAction.WARN).allowed is True
        assert CostDecision(action=CostAction.BLOCK).allowed is False

    def test_blocked_property(self):
        assert CostDecision(action=CostAction.BLOCK).blocked is True
        assert CostDecision(action=CostAction.ALLOW).blocked is False
        assert CostDecision(action=CostAction.WARN).blocked is False


# ---------------------------------------------------------------------------
# Integration: multiple dimensions active at once
# ---------------------------------------------------------------------------


class TestMultipleDimensions:
    def test_most_restrictive_wins(self):
        """When multiple limits exist, the first violated one triggers."""
        cfg = CostConfig(
            budget_usd=1000.0,
            per_call_limit_usd=0.0001,  # This will trigger first
            per_session_limit_usd=500.0,
            daily_budget_usd=500.0,
            on_exceed="block",
        )
        enforcer = CostPolicyEnforcer(cfg)
        decision = enforcer.check_and_record(_expensive_usage())
        assert decision.blocked
        assert decision.dimension == "per_call"

    def test_all_limits_pass(self):
        """When all limits are generous, calls go through."""
        cfg = CostConfig(
            budget_usd=1000.0,
            per_call_limit_usd=100.0,
            per_session_limit_usd=500.0,
            daily_budget_usd=500.0,
            per_minute_tokens=10_000_000,
            on_exceed="block",
        )
        enforcer = CostPolicyEnforcer(cfg)
        decision = enforcer.check_and_record(_cheap_usage())
        assert decision.allowed
        assert decision.cost_usd > 0


# ---------------------------------------------------------------------------
# Config parsing roundtrip
# ---------------------------------------------------------------------------


class TestConfigParsing:
    def test_yaml_cost_section_roundtrip(self):
        """CostConfig fields survive from_dict parsing."""
        from aegis.config import AegisConfig

        data = {
            "cost": {
                "budget_usd": 100.0,
                "per_session_limit_usd": 5.0,
                "per_call_limit_usd": 1.0,
                "daily_budget_usd": 50.0,
                "per_minute_tokens": 100_000,
                "alert_threshold": 0.8,
                "on_exceed": "warn",
            }
        }
        cfg = AegisConfig.from_dict(data)
        assert cfg.cost is not None
        assert cfg.cost.budget_usd == 100.0
        assert cfg.cost.per_session_limit_usd == 5.0
        assert cfg.cost.per_call_limit_usd == 1.0
        assert cfg.cost.daily_budget_usd == 50.0
        assert cfg.cost.per_minute_tokens == 100_000
        assert cfg.cost.alert_threshold == 0.8
        assert cfg.cost.on_exceed == "warn"


# ---------------------------------------------------------------------------
# Model pricing module
# ---------------------------------------------------------------------------


class TestModelPricingModule:
    def test_get_pricing_singleton(self):
        from aegis.core.model_pricing import get_pricing

        p1 = get_pricing()
        p2 = get_pricing()
        assert p1 is p2

    def test_list_models(self):
        from aegis.core.model_pricing import list_models

        models = list_models()
        assert "gpt-4o" in models
        assert "claude-sonnet-4" in models

    def test_estimate_call_cost(self):
        from aegis.core.model_pricing import estimate_call_cost

        cost = estimate_call_cost("gpt-4o", input_tokens=1000, output_tokens=500)
        assert cost > 0
