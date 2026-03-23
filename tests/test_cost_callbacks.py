"""Tests for cross-framework cost tracking callbacks."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from aegis.core.budget import CostTracker
from aegis.core.cost_callbacks import (
    AnthropicCostExtractor,
    GoogleCostExtractor,
    LangChainCostCallback,
    OpenAICostExtractor,
)

# ---------------------------------------------------------------------------
# Helpers — mock response objects
# ---------------------------------------------------------------------------


def _openai_response(
    model: str = "gpt-4o",
    prompt_tokens: int = 100,
    completion_tokens: int = 50,
    cache_read_input_tokens: int = 0,
) -> SimpleNamespace:
    """Build a mock OpenAI ChatCompletion response."""
    return SimpleNamespace(
        model=model,
        usage=SimpleNamespace(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cache_read_input_tokens=cache_read_input_tokens,
            completion_tokens_details=None,
        ),
    )


def _anthropic_response(
    model: str = "claude-sonnet-4-20250514",
    input_tokens: int = 100,
    output_tokens: int = 50,
    cache_read: int = 0,
    cache_creation: int = 0,
) -> SimpleNamespace:
    """Build a mock Anthropic Message response."""
    return SimpleNamespace(
        model=model,
        usage=SimpleNamespace(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_input_tokens=cache_read,
            cache_creation_input_tokens=cache_creation,
        ),
    )


def _google_response(
    prompt_tokens: int = 100,
    candidates_tokens: int = 50,
    cached_tokens: int = 0,
) -> SimpleNamespace:
    """Build a mock Google GenerativeAI response."""
    return SimpleNamespace(
        usage_metadata=SimpleNamespace(
            prompt_token_count=prompt_tokens,
            candidates_token_count=candidates_tokens,
            cached_content_token_count=cached_tokens,
        ),
    )


def _langchain_llm_result(
    model_name: str = "gpt-4o",
    prompt_tokens: int = 100,
    completion_tokens: int = 50,
) -> SimpleNamespace:
    """Build a mock LangChain LLMResult."""
    return SimpleNamespace(
        llm_output={
            "model_name": model_name,
            "token_usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
            },
        },
        generations=[],
    )


# ---------------------------------------------------------------------------
# LangChain callback
# ---------------------------------------------------------------------------


class TestLangChainCostCallback:
    def test_records_usage(self) -> None:
        tracker = CostTracker(max_budget=10.0)
        cb = LangChainCostCallback(tracker)
        response = _langchain_llm_result()
        cb.on_llm_end(response)
        assert tracker.spent > 0
        assert cb.total_calls == 1

    def test_no_usage_skipped(self) -> None:
        tracker = CostTracker(max_budget=10.0)
        cb = LangChainCostCallback(tracker)
        response = SimpleNamespace(llm_output={}, generations=[])
        cb.on_llm_end(response)
        assert tracker.spent == 0
        assert cb.total_calls == 0

    def test_custom_agent_id(self) -> None:
        tracker = CostTracker(max_budget=10.0)
        cb = LangChainCostCallback(tracker, agent_id="my-agent")
        cb.on_llm_end(_langchain_llm_result())
        report = tracker.get_report()
        assert "my-agent" in report["by_agent"]

    def test_default_model_fallback(self) -> None:
        tracker = CostTracker(max_budget=10.0)
        cb = LangChainCostCallback(tracker, default_model="claude-sonnet-4")
        response = SimpleNamespace(
            llm_output={
                "token_usage": {"prompt_tokens": 100, "completion_tokens": 50},
            },
            generations=[],
        )
        cb.on_llm_end(response)
        report = tracker.get_report()
        assert "claude-sonnet-4" in report["by_model"]

    def test_generation_info_fallback(self) -> None:
        tracker = CostTracker(max_budget=10.0)
        cb = LangChainCostCallback(tracker)
        gen = SimpleNamespace(
            generation_info={
                "token_usage": {"prompt_tokens": 200, "completion_tokens": 100},
            },
        )
        response = SimpleNamespace(
            llm_output={},
            generations=[[gen]],
        )
        cb.on_llm_end(response)
        assert tracker.spent > 0
        assert cb.total_calls == 1

    def test_noop_protocol_methods(self) -> None:
        tracker = CostTracker()
        cb = LangChainCostCallback(tracker)
        # These should not raise
        cb.on_llm_start()
        cb.on_llm_error()
        cb.on_chain_start()
        cb.on_chain_end()
        cb.on_chain_error()
        cb.on_tool_start()
        cb.on_tool_end()
        cb.on_tool_error()
        cb.on_text()

    def test_multiple_calls_accumulate(self) -> None:
        tracker = CostTracker(max_budget=100.0, loop_threshold=20)
        cb = LangChainCostCallback(tracker)
        for _ in range(5):
            cb.on_llm_end(_langchain_llm_result())
        assert cb.total_calls == 5
        assert len(tracker.records) == 5


# ---------------------------------------------------------------------------
# OpenAI extractor
# ---------------------------------------------------------------------------


class TestOpenAICostExtractor:
    def test_records_usage(self) -> None:
        tracker = CostTracker(max_budget=10.0)
        ext = OpenAICostExtractor(tracker)
        response = _openai_response()
        usage = ext.record(response)
        assert usage is not None
        assert usage.model == "gpt-4o"
        assert usage.input_tokens == 100
        assert usage.output_tokens == 50
        assert tracker.spent > 0
        assert ext.total_calls == 1

    def test_no_usage_returns_none(self) -> None:
        tracker = CostTracker(max_budget=10.0)
        ext = OpenAICostExtractor(tracker)
        response = SimpleNamespace(model="gpt-4o")  # no usage attr
        assert ext.record(response) is None
        assert tracker.spent == 0

    def test_cached_tokens(self) -> None:
        tracker = CostTracker(max_budget=10.0)
        ext = OpenAICostExtractor(tracker)
        response = _openai_response(cache_read_input_tokens=50)
        usage = ext.record(response)
        assert usage is not None
        assert usage.cached_tokens == 50

    def test_reasoning_tokens(self) -> None:
        tracker = CostTracker(max_budget=10.0)
        ext = OpenAICostExtractor(tracker)
        response = SimpleNamespace(
            model="o3",
            usage=SimpleNamespace(
                prompt_tokens=100,
                completion_tokens=200,
                cache_read_input_tokens=0,
                completion_tokens_details=SimpleNamespace(reasoning_tokens=150),
            ),
        )
        usage = ext.record(response)
        assert usage is not None
        assert usage.reasoning_tokens == 150

    def test_record_streaming(self) -> None:
        tracker = CostTracker(max_budget=10.0)
        ext = OpenAICostExtractor(tracker)
        # Empty chunk list
        assert ext.record_streaming([]) is None
        # Last chunk has usage
        chunks = [
            SimpleNamespace(model="gpt-4o"),  # no usage
            _openai_response(),  # has usage
        ]
        usage = ext.record_streaming(chunks)
        assert usage is not None

    def test_agent_id_attribution(self) -> None:
        tracker = CostTracker(max_budget=10.0)
        ext = OpenAICostExtractor(tracker, agent_id="openai-agent")
        ext.record(_openai_response())
        report = tracker.get_report()
        assert "openai-agent" in report["by_agent"]


# ---------------------------------------------------------------------------
# Anthropic extractor
# ---------------------------------------------------------------------------


class TestAnthropicCostExtractor:
    def test_records_usage(self) -> None:
        tracker = CostTracker(max_budget=10.0)
        ext = AnthropicCostExtractor(tracker)
        response = _anthropic_response()
        usage = ext.record(response)
        assert usage is not None
        assert usage.model == "claude-sonnet-4-20250514"
        assert usage.input_tokens == 100
        assert usage.output_tokens == 50
        assert tracker.spent > 0
        assert ext.total_calls == 1

    def test_no_usage_returns_none(self) -> None:
        tracker = CostTracker(max_budget=10.0)
        ext = AnthropicCostExtractor(tracker)
        response = SimpleNamespace(model="claude-sonnet-4")
        assert ext.record(response) is None

    def test_cached_tokens(self) -> None:
        tracker = CostTracker(max_budget=10.0)
        ext = AnthropicCostExtractor(tracker)
        response = _anthropic_response(cache_read=30, cache_creation=20)
        usage = ext.record(response)
        assert usage is not None
        assert usage.cached_tokens == 50  # 30 + 20

    def test_record_streaming(self) -> None:
        tracker = CostTracker(max_budget=10.0)
        ext = AnthropicCostExtractor(tracker)
        final_msg = _anthropic_response()
        usage = ext.record_streaming(final_msg)
        assert usage is not None
        assert tracker.spent > 0

    def test_agent_id_attribution(self) -> None:
        tracker = CostTracker(max_budget=10.0)
        ext = AnthropicCostExtractor(tracker, agent_id="claude-agent")
        ext.record(_anthropic_response())
        report = tracker.get_report()
        assert "claude-agent" in report["by_agent"]


# ---------------------------------------------------------------------------
# Google extractor
# ---------------------------------------------------------------------------


class TestGoogleCostExtractor:
    def test_records_usage(self) -> None:
        tracker = CostTracker(max_budget=10.0)
        ext = GoogleCostExtractor(tracker)
        response = _google_response()
        usage = ext.record(response)
        assert usage is not None
        assert usage.input_tokens == 100
        assert usage.output_tokens == 50
        assert tracker.spent > 0
        assert ext.total_calls == 1

    def test_no_usage_returns_none(self) -> None:
        tracker = CostTracker(max_budget=10.0)
        ext = GoogleCostExtractor(tracker)
        response = SimpleNamespace()
        assert ext.record(response) is None

    def test_model_override(self) -> None:
        tracker = CostTracker(max_budget=10.0)
        ext = GoogleCostExtractor(tracker)
        ext.record(_google_response(), model="gemini-2.5-pro")
        report = tracker.get_report()
        assert "gemini-2.5-pro" in report["by_model"]

    def test_cached_tokens(self) -> None:
        tracker = CostTracker(max_budget=10.0)
        ext = GoogleCostExtractor(tracker)
        response = _google_response(cached_tokens=40)
        usage = ext.record(response)
        assert usage is not None
        assert usage.cached_tokens == 40

    def test_default_model(self) -> None:
        tracker = CostTracker(max_budget=10.0)
        ext = GoogleCostExtractor(tracker, default_model="gemini-2.5-flash")
        ext.record(_google_response())
        report = tracker.get_report()
        assert "gemini-2.5-flash" in report["by_model"]

    def test_agent_id_attribution(self) -> None:
        tracker = CostTracker(max_budget=10.0)
        ext = GoogleCostExtractor(tracker, agent_id="gemini-agent")
        ext.record(_google_response())
        report = tracker.get_report()
        assert "gemini-agent" in report["by_agent"]


# ---------------------------------------------------------------------------
# Integration: shared tracker across frameworks
# ---------------------------------------------------------------------------


class TestCrossFrameworkIntegration:
    def test_shared_tracker(self) -> None:
        """All extractors feed the same CostTracker."""
        tracker = CostTracker(max_budget=100.0)

        lc = LangChainCostCallback(tracker, agent_id="lc")
        oai = OpenAICostExtractor(tracker, agent_id="oai")
        ant = AnthropicCostExtractor(tracker, agent_id="ant")
        goog = GoogleCostExtractor(tracker, agent_id="goog")

        lc.on_llm_end(_langchain_llm_result())
        oai.record(_openai_response())
        ant.record(_anthropic_response())
        goog.record(_google_response())

        assert len(tracker.records) == 4
        report = tracker.get_report()
        assert report["call_count"] == 4
        assert len(report["by_agent"]) == 4
        assert all(agent in report["by_agent"] for agent in ["lc", "oai", "ant", "goog"])

    def test_budget_enforcement_across_frameworks(self) -> None:
        """Budget exhaustion works across mixed framework calls."""
        from aegis.core.budget import BudgetExhausted

        tracker = CostTracker(max_budget=0.001)  # tiny budget

        oai = OpenAICostExtractor(tracker)
        # Large call should exhaust budget
        with pytest.raises(BudgetExhausted):
            oai.record(_openai_response(prompt_tokens=100_000, completion_tokens=100_000))
