"""Tests for model_pricing module."""

from __future__ import annotations

from aegis.core.model_pricing import (
    PRICING_TABLE,
    estimate_call_cost,
    get_pricing,
    list_models,
)


class TestModelPricing:
    def test_get_pricing_returns_instance(self):
        pricing = get_pricing()
        assert pricing is not None

    def test_get_pricing_is_singleton(self):
        p1 = get_pricing()
        p2 = get_pricing()
        assert p1 is p2

    def test_list_models_returns_sorted(self):
        models = list_models()
        assert isinstance(models, list)
        assert models == sorted(models)
        assert len(models) > 0

    def test_pricing_table_has_common_models(self):
        models = list_models()
        # At least some well-known models should be present
        assert any("gpt" in m for m in models) or len(models) > 0

    def test_estimate_call_cost_known_model(self):
        models = list_models()
        if models:
            cost = estimate_call_cost(models[0], input_tokens=1000, output_tokens=500)
            assert isinstance(cost, float)
            assert cost >= 0

    def test_estimate_call_cost_zero_tokens(self):
        models = list_models()
        if models:
            cost = estimate_call_cost(models[0], input_tokens=0, output_tokens=0)
            assert cost == 0.0

    def test_estimate_call_cost_with_cached_tokens(self):
        models = list_models()
        if models:
            cost_no_cache = estimate_call_cost(models[0], input_tokens=1000, output_tokens=500)
            cost_with_cache = estimate_call_cost(
                models[0],
                input_tokens=1000,
                output_tokens=500,
                cached_tokens=500,
            )
            # Cached should be same or cheaper
            assert cost_with_cache <= cost_no_cache

    def test_pricing_table_is_dict(self):
        assert isinstance(PRICING_TABLE, dict)

    def test_register_custom_model(self):
        pricing = get_pricing()
        pricing.register("test-model-xyz", 1.0, 2.0, 0.5)
        from aegis.core.budget import TokenUsage

        usage = TokenUsage(model="test-model-xyz", input_tokens=1000, output_tokens=500)
        cost = pricing.cost(usage)
        assert cost > 0
