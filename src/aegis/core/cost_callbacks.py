"""Cross-framework cost tracking callbacks.

Provides callback/hook classes for popular AI frameworks that
automatically record token usage into an Aegis :class:`CostTracker`.
Each class uses conditional imports so the framework dependency is
optional.

Supported frameworks:

- **LangChain** — ``LangChainCostCallback`` implements
  ``BaseCallbackHandler`` and captures token usage from LLM responses.
- **OpenAI** — ``OpenAICostExtractor`` extracts usage from
  ``ChatCompletion`` response objects (works with both ``openai`` and
  OpenAI Agents SDK).
- **Anthropic** — ``AnthropicCostExtractor`` extracts usage from
  ``anthropic.types.Message`` response objects.
- **Google Generative AI** — ``GoogleCostExtractor`` extracts usage
  from ``google.generativeai`` / Google ADK response objects.

Usage::

    from aegis.core.budget import CostTracker
    from aegis.core.cost_callbacks import LangChainCostCallback

    tracker = CostTracker(max_budget=5.00)
    callback = LangChainCostCallback(tracker)

    # Pass to LangChain as a callback handler:
    llm = ChatOpenAI(callbacks=[callback])
"""

from __future__ import annotations

import logging
from typing import Any

from aegis.core.budget import CostTracker, TokenUsage

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# LangChain callback handler
# ---------------------------------------------------------------------------


class LangChainCostCallback:
    """LangChain callback handler that records token usage into a CostTracker.

    Implements the LangChain ``BaseCallbackHandler`` protocol for
    ``on_llm_end``. When the LLM response includes token usage metadata,
    it is recorded in the attached tracker.

    Args:
        tracker: The :class:`CostTracker` to record costs into.
        agent_id: Optional agent identifier for cost attribution.
        default_model: Fallback model name when the response does not
            include model information.
    """

    def __init__(
        self,
        tracker: CostTracker,
        *,
        agent_id: str = "",
        default_model: str = "gpt-4o",
    ) -> None:
        self.tracker = tracker
        self.agent_id = agent_id
        self.default_model = default_model
        self._total_calls = 0

    @property
    def total_calls(self) -> int:
        """Number of LLM calls recorded."""
        return self._total_calls

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Called by LangChain when an LLM call completes.

        Extracts token usage from the response's ``llm_output`` dict.
        Expected keys: ``token_usage`` with ``prompt_tokens``,
        ``completion_tokens``, and optionally ``model_name``.
        """
        llm_output = getattr(response, "llm_output", None) or {}
        token_usage = llm_output.get("token_usage", {})
        if not token_usage:
            # Some LangChain models put usage in generations
            generations = getattr(response, "generations", None)
            if generations:
                for gen_list in generations:
                    for gen in gen_list:
                        info = getattr(gen, "generation_info", None) or {}
                        if "token_usage" in info:
                            token_usage = info["token_usage"]
                            break
                    if token_usage:
                        break
            if not token_usage:
                return

        model = llm_output.get("model_name") or self.default_model
        input_tokens = token_usage.get("prompt_tokens", 0)
        output_tokens = token_usage.get("completion_tokens", 0)

        if input_tokens or output_tokens:
            usage = TokenUsage(
                model=model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            )
            self.tracker.record(usage, agent_id=self.agent_id, action_type="llm_call")
            self._total_calls += 1

    # LangChain callback protocol stubs (required for compatibility)
    def on_llm_start(self, *args: Any, **kwargs: Any) -> None:
        """No-op: LangChain callback protocol."""

    def on_llm_error(self, *args: Any, **kwargs: Any) -> None:
        """No-op: LangChain callback protocol."""

    def on_chain_start(self, *args: Any, **kwargs: Any) -> None:
        """No-op: LangChain callback protocol."""

    def on_chain_end(self, *args: Any, **kwargs: Any) -> None:
        """No-op: LangChain callback protocol."""

    def on_chain_error(self, *args: Any, **kwargs: Any) -> None:
        """No-op: LangChain callback protocol."""

    def on_tool_start(self, *args: Any, **kwargs: Any) -> None:
        """No-op: LangChain callback protocol."""

    def on_tool_end(self, *args: Any, **kwargs: Any) -> None:
        """No-op: LangChain callback protocol."""

    def on_tool_error(self, *args: Any, **kwargs: Any) -> None:
        """No-op: LangChain callback protocol."""

    def on_text(self, *args: Any, **kwargs: Any) -> None:
        """No-op: LangChain callback protocol."""


# ---------------------------------------------------------------------------
# OpenAI cost extractor
# ---------------------------------------------------------------------------


class OpenAICostExtractor:
    """Extracts token usage from OpenAI ``ChatCompletion`` response objects.

    Works with both the ``openai`` library and OpenAI Agents SDK.
    Call :meth:`record` with a response to extract and record usage.

    Args:
        tracker: The :class:`CostTracker` to record costs into.
        agent_id: Optional agent identifier for cost attribution.
    """

    def __init__(
        self,
        tracker: CostTracker,
        *,
        agent_id: str = "",
    ) -> None:
        self.tracker = tracker
        self.agent_id = agent_id
        self._total_calls = 0

    @property
    def total_calls(self) -> int:
        """Number of calls recorded."""
        return self._total_calls

    def record(self, response: Any) -> TokenUsage | None:
        """Extract token usage from an OpenAI response and record it.

        Supports:
        - ``response.usage.prompt_tokens`` / ``completion_tokens``
        - ``response.usage.cache_read_input_tokens`` (cached tokens)
        - ``response.model`` for model identification

        Returns the :class:`TokenUsage` if usage was found, else ``None``.
        """
        usage = getattr(response, "usage", None)
        if usage is None:
            return None

        model = getattr(response, "model", "gpt-4o")
        input_tokens = getattr(usage, "prompt_tokens", 0) or 0
        output_tokens = getattr(usage, "completion_tokens", 0) or 0
        cached_tokens = getattr(usage, "cache_read_input_tokens", 0) or 0

        # OpenAI reasoning models report reasoning_tokens
        completion_details = getattr(usage, "completion_tokens_details", None)
        reasoning_tokens = 0
        if completion_details:
            reasoning_tokens = getattr(completion_details, "reasoning_tokens", 0) or 0

        if input_tokens or output_tokens:
            token_usage = TokenUsage(
                model=model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cached_tokens=cached_tokens,
                reasoning_tokens=reasoning_tokens,
            )
            self.tracker.record(
                token_usage,
                agent_id=self.agent_id,
                action_type="llm_call",
            )
            self._total_calls += 1
            return token_usage
        return None

    def record_streaming(self, chunks: list[Any]) -> TokenUsage | None:
        """Extract usage from the final chunk of a streaming response.

        OpenAI streaming responses include usage in the last chunk
        when ``stream_options={"include_usage": True}`` is set.

        Args:
            chunks: List of streaming chunks.

        Returns the :class:`TokenUsage` if usage was found in the last chunk.
        """
        if not chunks:
            return None
        # Usage is in the last chunk
        return self.record(chunks[-1])


# ---------------------------------------------------------------------------
# Anthropic cost extractor
# ---------------------------------------------------------------------------


class AnthropicCostExtractor:
    """Extracts token usage from Anthropic ``Message`` response objects.

    Args:
        tracker: The :class:`CostTracker` to record costs into.
        agent_id: Optional agent identifier for cost attribution.
    """

    def __init__(
        self,
        tracker: CostTracker,
        *,
        agent_id: str = "",
    ) -> None:
        self.tracker = tracker
        self.agent_id = agent_id
        self._total_calls = 0

    @property
    def total_calls(self) -> int:
        """Number of calls recorded."""
        return self._total_calls

    def record(self, response: Any) -> TokenUsage | None:
        """Extract token usage from an Anthropic Message and record it.

        Supports:
        - ``response.usage.input_tokens`` / ``output_tokens``
        - ``response.usage.cache_creation_input_tokens`` (cached tokens)
        - ``response.usage.cache_read_input_tokens`` (cached tokens)
        - ``response.model`` for model identification

        Returns the :class:`TokenUsage` if usage was found, else ``None``.
        """
        usage = getattr(response, "usage", None)
        if usage is None:
            return None

        model = getattr(response, "model", "claude-sonnet-4")
        input_tokens = getattr(usage, "input_tokens", 0) or 0
        output_tokens = getattr(usage, "output_tokens", 0) or 0
        # Anthropic reports both cache creation and cache read tokens
        cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0
        cache_creation = getattr(usage, "cache_creation_input_tokens", 0) or 0
        cached_tokens = cache_read + cache_creation

        if input_tokens or output_tokens:
            token_usage = TokenUsage(
                model=model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cached_tokens=cached_tokens,
            )
            self.tracker.record(
                token_usage,
                agent_id=self.agent_id,
                action_type="llm_call",
            )
            self._total_calls += 1
            return token_usage
        return None

    def record_streaming(self, final_message: Any) -> TokenUsage | None:
        """Record usage from a streaming ``MessageStream`` final message.

        Anthropic streaming returns the final ``Message`` with usage
        after ``stream.get_final_message()`` or the ``message_stop`` event.

        Args:
            final_message: The final message from the stream.

        Returns the :class:`TokenUsage` if usage was found.
        """
        return self.record(final_message)


# ---------------------------------------------------------------------------
# Google Generative AI cost extractor
# ---------------------------------------------------------------------------


class GoogleCostExtractor:
    """Extracts token usage from Google Generative AI / ADK responses.

    Supports both ``google.generativeai`` and Google ADK response objects.

    Args:
        tracker: The :class:`CostTracker` to record costs into.
        agent_id: Optional agent identifier for cost attribution.
        default_model: Fallback model name.
    """

    def __init__(
        self,
        tracker: CostTracker,
        *,
        agent_id: str = "",
        default_model: str = "gemini-2.0-flash",
    ) -> None:
        self.tracker = tracker
        self.agent_id = agent_id
        self.default_model = default_model
        self._total_calls = 0

    @property
    def total_calls(self) -> int:
        """Number of calls recorded."""
        return self._total_calls

    def record(self, response: Any, *, model: str = "") -> TokenUsage | None:
        """Extract token usage from a Google AI response and record it.

        Supports:
        - ``response.usage_metadata.prompt_token_count``
        - ``response.usage_metadata.candidates_token_count``
        - ``response.usage_metadata.cached_content_token_count``

        Args:
            response: A Google GenerativeAI response object.
            model: Override model name.

        Returns the :class:`TokenUsage` if usage was found, else ``None``.
        """
        usage_metadata = getattr(response, "usage_metadata", None)
        if usage_metadata is None:
            return None

        model_name = model or self.default_model
        input_tokens = getattr(usage_metadata, "prompt_token_count", 0) or 0
        output_tokens = getattr(usage_metadata, "candidates_token_count", 0) or 0
        cached_tokens = getattr(usage_metadata, "cached_content_token_count", 0) or 0

        if input_tokens or output_tokens:
            token_usage = TokenUsage(
                model=model_name,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cached_tokens=cached_tokens,
            )
            self.tracker.record(
                token_usage,
                agent_id=self.agent_id,
                action_type="llm_call",
            )
            self._total_calls += 1
            return token_usage
        return None
