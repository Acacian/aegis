"""Tests for aegis.core.budget — Cost circuit breaker."""

from __future__ import annotations

import pytest

from aegis.core.budget import (
    BudgetAction,
    BudgetExhausted,
    CostRecord,
    CostTracker,
    ModelPricing,
    TokenUsage,
)


# ---------------------------------------------------------------------------
# ModelPricing
# ---------------------------------------------------------------------------


class TestModelPricing:
    def test_known_model(self):
        p = ModelPricing()
        usage = TokenUsage(model="gpt-4o", input_tokens=1_000_000, output_tokens=0)
        assert p.cost(usage) == pytest.approx(2.50, rel=1e-3)

    def test_output_cost(self):
        p = ModelPricing()
        usage = TokenUsage(model="gpt-4o", input_tokens=0, output_tokens=1_000_000)
        assert p.cost(usage) == pytest.approx(10.00, rel=1e-3)

    def test_cached_tokens_reduce_cost(self):
        p = ModelPricing()
        full = TokenUsage(model="gpt-4o", input_tokens=1000, output_tokens=0)
        cached = TokenUsage(model="gpt-4o", input_tokens=1000, output_tokens=0, cached_tokens=500)
        assert p.cost(cached) < p.cost(full)

    def test_prefix_matching(self):
        p = ModelPricing()
        usage = TokenUsage(model="gpt-4o-2024-08-06", input_tokens=1_000_000, output_tokens=0)
        assert p.cost(usage) == pytest.approx(2.50, rel=1e-3)

    def test_register_custom_model(self):
        p = ModelPricing()
        p.register("my-model", 1.0, 2.0, 0.5)
        usage = TokenUsage(model="my-model", input_tokens=1_000_000, output_tokens=1_000_000)
        assert p.cost(usage) == pytest.approx(3.0, rel=1e-3)

    def test_unknown_model_falls_back(self):
        p = ModelPricing()
        usage = TokenUsage(model="unknown-xyz", input_tokens=1_000_000, output_tokens=0)
        # Should fall back to gpt-4o pricing
        assert p.cost(usage) == pytest.approx(2.50, rel=1e-3)

    def test_anthropic_pricing(self):
        p = ModelPricing()
        usage = TokenUsage(model="claude-sonnet-4-20250514", input_tokens=1_000_000, output_tokens=0)
        assert p.cost(usage) == pytest.approx(3.00, rel=1e-3)


# ---------------------------------------------------------------------------
# CostTracker basics
# ---------------------------------------------------------------------------


class TestCostTracker:
    def test_initial_state(self):
        t = CostTracker(max_budget=10.0)
        assert t.spent == 0.0
        assert t.remaining == 10.0
        assert t.utilization == 0.0

    def test_unlimited_budget(self):
        t = CostTracker()  # max_budget=0 => unlimited
        assert t.remaining == float("inf")
        assert t.utilization == 0.0

    def test_record_tracks_cost(self):
        t = CostTracker(max_budget=100.0)
        usage = TokenUsage(model="gpt-4o", input_tokens=1000, output_tokens=200)
        record = t.record(usage)
        assert isinstance(record, CostRecord)
        assert record.cost > 0
        assert t.spent > 0
        assert t.spent == record.cumulative

    def test_multiple_records_accumulate(self):
        t = CostTracker(max_budget=100.0)
        usage = TokenUsage(model="gpt-4o", input_tokens=1000, output_tokens=200)
        t.record(usage)
        t.record(usage)
        assert len(t.records) == 2
        assert t.records[1].cumulative > t.records[0].cumulative

    def test_budget_exhausted(self):
        t = CostTracker(max_budget=0.001)  # Very small budget
        usage = TokenUsage(model="gpt-4o", input_tokens=100_000, output_tokens=100_000)
        with pytest.raises(BudgetExhausted) as exc_info:
            t.record(usage)
        assert exc_info.value.budget == 0.001
        assert exc_info.value.spent > 0

    def test_check_budget_without_recording(self):
        t = CostTracker(max_budget=1.0)
        assert t.check_budget(0.5) == BudgetAction.OK
        assert t.check_budget(0.85) == BudgetAction.WARN  # 0.85 > 0.8 warn threshold
        assert t.check_budget(0.95) == BudgetAction.SOFT_LIMIT  # 0.95 > 0.9 soft threshold
        assert t.check_budget(1.5) == BudgetAction.HARD_LIMIT

    def test_warn_threshold(self):
        warnings: list[CostRecord] = []
        t = CostTracker(
            max_budget=1.0,
            warn_threshold=0.5,
            on_warn=lambda r: warnings.append(r),
        )
        # gpt-4o-mini output @ $0.60/M => 1M tokens = $0.60 = 60% utilization
        # Above warn (50%) but below soft (90%)
        usage = TokenUsage(model="gpt-4o-mini", input_tokens=0, output_tokens=1_000_000)
        t.record(usage)
        assert len(warnings) == 1

    def test_estimate_cost(self):
        t = CostTracker()
        cost = t.estimate_cost("gpt-4o", 1000, 500)
        assert cost > 0

    def test_get_report(self):
        t = CostTracker(max_budget=10.0, session_id="test-session")
        t.record(TokenUsage(model="gpt-4o", input_tokens=1000, output_tokens=200))
        t.record(TokenUsage(model="claude-sonnet-4", input_tokens=500, output_tokens=100))
        report = t.get_report()
        assert report["session_id"] == "test-session"
        assert report["max_budget"] == 10.0
        assert report["spent"] > 0
        assert report["call_count"] == 2
        assert "gpt-4o" in report["by_model"]
        assert "claude-sonnet-4" in report["by_model"]

    def test_agent_tracking(self):
        t = CostTracker(max_budget=10.0)
        t.record(
            TokenUsage(model="gpt-4o", input_tokens=1000, output_tokens=200),
            agent_id="agent-1",
        )
        t.record(
            TokenUsage(model="gpt-4o", input_tokens=500, output_tokens=100),
            agent_id="agent-2",
        )
        report = t.get_report()
        assert "agent-1" in report["by_agent"]
        assert "agent-2" in report["by_agent"]


# ---------------------------------------------------------------------------
# Loop detection
# ---------------------------------------------------------------------------


class TestLoopDetection:
    def test_loop_detected(self):
        t = CostTracker(max_budget=100.0, loop_threshold=3, loop_window=60.0)
        usage = TokenUsage(model="gpt-4o", input_tokens=10, output_tokens=10)
        t.record(usage, agent_id="a1", action_type="test")
        t.record(usage, agent_id="a1", action_type="test")
        with pytest.raises(BudgetExhausted):
            t.record(usage, agent_id="a1", action_type="test")

    def test_different_actions_no_loop(self):
        t = CostTracker(max_budget=100.0, loop_threshold=3, loop_window=60.0)
        usage = TokenUsage(model="gpt-4o", input_tokens=10, output_tokens=10)
        t.record(usage, action_type="action1")
        t.record(usage, action_type="action2")
        t.record(usage, action_type="action3")
        assert len(t.records) == 3


# ---------------------------------------------------------------------------
# Child tracker
# ---------------------------------------------------------------------------


class TestChildTracker:
    def test_child_budget_capped(self):
        parent = CostTracker(max_budget=10.0)
        child = parent.child(20.0)
        # Child budget should be capped to parent's remaining
        assert child.max_budget == 10.0

    def test_child_budget_smaller(self):
        parent = CostTracker(max_budget=10.0)
        child = parent.child(3.0)
        assert child.max_budget == 3.0
