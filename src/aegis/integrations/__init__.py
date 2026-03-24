"""Zero-code integration layer for Aegis governance.

Provides decorators and monkey-patches that add governance to existing
code with minimal changes.

Usage::

    from aegis.integrations import guard, patch_openai, patch_anthropic

    # Decorator-based governance
    @guard
    def call_api(endpoint, data):
        ...

    # Monkey-patch OpenAI
    patch_openai()

    # Monkey-patch Anthropic
    patch_anthropic()
"""

from __future__ import annotations

from aegis.integrations.decorators import guard
from aegis.integrations.errors import AegisBlockedError, AegisGuardrailError
from aegis.integrations.patch_anthropic import patch_anthropic, unpatch_anthropic
from aegis.integrations.patch_openai import patch_openai, unpatch_openai

__all__ = [
    "AegisBlockedError",
    "AegisGuardrailError",
    "guard",
    "patch_anthropic",
    "patch_openai",
    "unpatch_anthropic",
    "unpatch_openai",
]
