"""Model pricing table and utilities.

This module provides a convenient entry point for the pricing data
already embedded in :mod:`aegis.core.budget`.  The canonical pricing
table lives in ``budget._PRICING`` to avoid circular imports; this
module re-exports :class:`ModelPricing` and adds helper utilities.

Usage::

    from aegis.core.model_pricing import get_pricing, estimate_call_cost

    pricing = get_pricing()
    pricing.register("my-model", 1.0, 2.0, 0.5)

    cost = estimate_call_cost("gpt-4o", input_tokens=1000, output_tokens=500)
"""

from __future__ import annotations

from aegis.core.budget import _PRICING as PRICING_TABLE
from aegis.core.budget import ModelPricing, TokenUsage

__all__ = [
    "PRICING_TABLE",
    "ModelPricing",
    "estimate_call_cost",
    "get_pricing",
    "list_models",
]

# Module-level singleton
_default_pricing: ModelPricing | None = None


def get_pricing() -> ModelPricing:
    """Return a shared :class:`ModelPricing` instance.

    The instance is created on first call and reused thereafter.
    Custom models registered on this instance are visible to all
    callers that use :func:`get_pricing`.
    """
    global _default_pricing  # noqa: PLW0603
    if _default_pricing is None:
        _default_pricing = ModelPricing()
    return _default_pricing


def list_models() -> list[str]:
    """Return sorted list of all models with known pricing."""
    return sorted(PRICING_TABLE.keys())


def estimate_call_cost(
    model: str,
    *,
    input_tokens: int = 0,
    output_tokens: int = 0,
    cached_tokens: int = 0,
) -> float:
    """Estimate cost of an LLM call in dollars.

    Args:
        model: Model name (e.g. ``"gpt-4o"``).
        input_tokens: Number of input/prompt tokens.
        output_tokens: Number of output/completion tokens.
        cached_tokens: Number of cached input tokens.

    Returns:
        Estimated cost in USD.
    """
    pricing = get_pricing()
    usage = TokenUsage(
        model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cached_tokens=cached_tokens,
    )
    return pricing.cost(usage)
