"""LLM-backed policy generators for autopolicy.

Reference implementations of :class:`~aegis.core.autopolicy.PolicyGenerator`
for OpenAI and Anthropic.  Dependencies are lazy-loaded — you only need
``openai`` or ``anthropic`` installed if you actually use the corresponding
generator.

Usage::

    from aegis.core.autopolicy_llm import OpenAIPolicyGenerator

    gen = OpenAIPolicyGenerator(api_key="sk-...")
    policy = generate_policy(
        "Block all deletes, require approval for writes over $10K",
        generator=gen,
    )

Or with Anthropic::

    from aegis.core.autopolicy_llm import AnthropicPolicyGenerator

    gen = AnthropicPolicyGenerator(api_key="sk-ant-...")
    policy = generate_policy(
        "Healthcare agents must not access patient records without consent",
        generator=gen,
    )
"""

from __future__ import annotations

import json
import logging
from typing import Any

import yaml

from aegis.core.autopolicy import POLICY_GENERATION_PROMPT

logger = logging.getLogger(__name__)

# JSON Schema for structured output — ensures LLM returns valid policy
_POLICY_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["version", "defaults", "rules"],
    "additionalProperties": False,
    "properties": {
        "version": {"type": "string", "enum": ["1"]},
        "defaults": {
            "type": "object",
            "required": ["risk_level", "approval"],
            "additionalProperties": False,
            "properties": {
                "risk_level": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                },
                "approval": {
                    "type": "string",
                    "enum": ["auto", "approve", "block"],
                },
            },
        },
        "rules": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name", "match"],
                "additionalProperties": False,
                "properties": {
                    "name": {"type": "string"},
                    "match": {
                        "type": "object",
                        "required": ["type"],
                        "additionalProperties": False,
                        "properties": {
                            "type": {"type": "string"},
                            "target": {"type": "string"},
                        },
                    },
                    "risk_level": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"],
                    },
                    "approval": {
                        "type": "string",
                        "enum": ["auto", "approve", "block"],
                    },
                    "conditions": {
                        "type": "object",
                        "additionalProperties": True,
                    },
                },
            },
        },
    },
}

# Modified prompt for JSON output (LLM structured output mode)
_JSON_PROMPT_TEMPLATE = (
    "You are a policy generator for Aegis, an AI agent governance framework.\n"
    "Convert the following natural language description into a policy JSON object.\n\n"
    "The output must match this structure:\n"
    '  {{"version": "1",\n'
    '   "defaults": {{"risk_level": "medium", "approval": "approve"}},\n'
    '   "rules": [{{"name": "rule_name", "match": {{"type": "glob*", "target": "glob*"}},\n'
    '              "risk_level": "low", "approval": "auto", "conditions": {{}}}}]}}\n\n'
    "Risk levels: low (safe reads), medium (writes), "
    "high (bulk/sensitive), critical (destructive).\n"
    "Approval: auto (no human), approve (human required), block (never allowed).\n"
    'Match type uses glob patterns: "read*", "write*", "delete*", "send*", "deploy*", "*".\n'
    "Conditions are optional: param_gt, time_after, time_before, weekdays.\n\n"
    "Generate appropriate rules based on the description. Be precise and complete.\n\n"
    "Description:\n{description}"
)


def _validate_policy_dict(data: Any) -> dict[str, Any]:
    """Basic validation of generated policy dict."""
    if not isinstance(data, dict):
        raise ValueError(f"Expected dict, got {type(data).__name__}")

    if "version" not in data:
        data["version"] = "1"
    if "defaults" not in data:
        data["defaults"] = {"risk_level": "medium", "approval": "approve"}
    if "rules" not in data:
        data["rules"] = []

    # Validate rules have required fields
    for i, rule in enumerate(data.get("rules", [])):
        if not isinstance(rule, dict):
            raise ValueError(f"Rule {i} is not a dict")
        if "name" not in rule:
            rule["name"] = f"rule_{i + 1}"
        if "match" not in rule:
            raise ValueError(f"Rule {i} ({rule.get('name', '?')}) missing 'match'")
        if "type" not in rule["match"]:
            raise ValueError(f"Rule {i} ({rule['name']}) match missing 'type'")

    return data


class OpenAIPolicyGenerator:
    """OpenAI-backed policy generator using structured outputs.

    Requires ``openai`` package (``pip install openai``).

    Args:
        api_key: OpenAI API key. Falls back to ``OPENAI_API_KEY`` env var.
        model: Model to use. Default: ``gpt-4o-mini``.
        temperature: Sampling temperature. Default: ``0.1`` (deterministic).
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str = "gpt-4o-mini",
        temperature: float = 0.1,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._temperature = temperature
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                from openai import OpenAI
            except ImportError as exc:
                raise ImportError(
                    "OpenAI package required for OpenAIPolicyGenerator. "
                    "Install with: pip install openai"
                ) from exc
            kwargs: dict[str, Any] = {}
            if self._api_key:
                kwargs["api_key"] = self._api_key
            self._client = OpenAI(**kwargs)
        return self._client

    def generate(self, description: str) -> dict[str, Any]:
        """Generate a policy dict from a natural language description.

        Uses OpenAI's structured output (response_format) to ensure
        valid JSON output matching the policy schema.
        """
        client = self._get_client()

        prompt = _JSON_PROMPT_TEMPLATE.format(description=description)

        response = client.chat.completions.create(
            model=self._model,
            temperature=self._temperature,
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": description},
            ],
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "aegis_policy",
                    "strict": True,
                    "schema": _POLICY_JSON_SCHEMA,
                },
            },
        )

        content = response.choices[0].message.content
        if not content:
            raise ValueError("Empty response from OpenAI")

        data = json.loads(content)
        return _validate_policy_dict(data)


class AnthropicPolicyGenerator:
    """Anthropic-backed policy generator using tool use for structured output.

    Requires ``anthropic`` package (``pip install anthropic``).

    Args:
        api_key: Anthropic API key. Falls back to ``ANTHROPIC_API_KEY`` env var.
        model: Model to use. Default: ``claude-sonnet-4-20250514``.
        max_tokens: Maximum tokens for response. Default: ``2048``.
        temperature: Sampling temperature. Default: ``0.1``.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str = "claude-sonnet-4-20250514",
        max_tokens: int = 2048,
        temperature: float = 0.1,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                from anthropic import Anthropic
            except ImportError as exc:
                raise ImportError(
                    "Anthropic package required for AnthropicPolicyGenerator. "
                    "Install with: pip install anthropic"
                ) from exc
            kwargs: dict[str, Any] = {}
            if self._api_key:
                kwargs["api_key"] = self._api_key
            self._client = Anthropic(**kwargs)
        return self._client

    def generate(self, description: str) -> dict[str, Any]:
        """Generate a policy dict from a natural language description.

        Uses Anthropic's tool use to get structured JSON output matching
        the policy schema.
        """
        client = self._get_client()

        prompt = _JSON_PROMPT_TEMPLATE.format(description=description)

        tool_def = {
            "name": "generate_aegis_policy",
            "description": "Generate an Aegis governance policy from the description.",
            "input_schema": _POLICY_JSON_SCHEMA,
        }

        response = client.messages.create(  # aegis: ignore
            model=self._model,
            max_tokens=self._max_tokens,
            temperature=self._temperature,
            system=prompt,
            messages=[{"role": "user", "content": description}],
            tools=[tool_def],
            tool_choice={"type": "tool", "name": "generate_aegis_policy"},
        )

        # Extract tool use result
        for block in response.content:
            if block.type == "tool_use" and block.name == "generate_aegis_policy":
                return _validate_policy_dict(block.input)

        # Fallback: parse text content as YAML
        for block in response.content:
            if block.type == "text" and block.text.strip():
                data = yaml.safe_load(block.text)
                return _validate_policy_dict(data)

        raise ValueError("No valid policy in Anthropic response")


class YAMLFallbackGenerator:
    """Fallback generator that works with any OpenAI-compatible API.

    Uses plain YAML output (no structured output mode required).
    Works with vLLM, Ollama, LiteLLM, or any OpenAI-compatible endpoint.

    Args:
        base_url: API base URL. E.g. ``http://localhost:11434/v1``.
        api_key: API key (use ``"ollama"`` for Ollama).
        model: Model name. E.g. ``llama3``, ``mistral``.
        temperature: Sampling temperature.
    """

    def __init__(
        self,
        *,
        base_url: str = "http://localhost:11434/v1",
        api_key: str = "ollama",
        model: str = "llama3",
        temperature: float = 0.1,
    ) -> None:
        self._base_url = base_url
        self._api_key = api_key
        self._model = model
        self._temperature = temperature
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                from openai import OpenAI
            except ImportError as exc:
                raise ImportError(
                    "OpenAI package required for YAMLFallbackGenerator. "
                    "Install with: pip install openai"
                ) from exc
            self._client = OpenAI(
                base_url=self._base_url,
                api_key=self._api_key,
            )
        return self._client

    def generate(self, description: str) -> dict[str, Any]:
        """Generate a policy dict via YAML output parsing."""
        client = self._get_client()

        prompt = POLICY_GENERATION_PROMPT.replace("{description}", description)

        response = client.chat.completions.create(
            model=self._model,
            temperature=self._temperature,
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": description},
            ],
        )

        content = response.choices[0].message.content
        if not content:
            raise ValueError("Empty response from LLM")

        # Strip markdown fences if present
        text = content.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            lines = lines[1:]  # Remove opening fence
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines)

        data = yaml.safe_load(text)
        return _validate_policy_dict(data)
