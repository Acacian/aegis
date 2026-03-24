"""Tests for LLM-backed policy generators.

All LLM calls are mocked — no real API keys needed.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
import yaml

from aegis.core.autopolicy_llm import (
    AnthropicPolicyGenerator,
    OpenAIPolicyGenerator,
    YAMLFallbackGenerator,
    _validate_policy_dict,
)


# -- Validation ----------------------------------------------------------------


class TestValidatePolicyDict:
    def test_valid_minimal(self):
        data = {
            "version": "1",
            "defaults": {"risk_level": "medium", "approval": "approve"},
            "rules": [],
        }
        result = _validate_policy_dict(data)
        assert result["version"] == "1"

    def test_adds_defaults(self):
        data = {"rules": [{"name": "r1", "match": {"type": "read*"}}]}
        result = _validate_policy_dict(data)
        assert result["version"] == "1"
        assert result["defaults"]["risk_level"] == "medium"

    def test_auto_names_rules(self):
        data = {
            "version": "1",
            "defaults": {"risk_level": "low", "approval": "auto"},
            "rules": [{"match": {"type": "read*"}}],
        }
        result = _validate_policy_dict(data)
        assert result["rules"][0]["name"] == "rule_1"

    def test_rejects_non_dict(self):
        with pytest.raises(ValueError, match="Expected dict"):
            _validate_policy_dict("not a dict")

    def test_rejects_rule_without_match(self):
        data = {"rules": [{"name": "bad"}]}
        with pytest.raises(ValueError, match="missing 'match'"):
            _validate_policy_dict(data)

    def test_rejects_match_without_type(self):
        data = {"rules": [{"name": "bad", "match": {}}]}
        with pytest.raises(ValueError, match="match missing 'type'"):
            _validate_policy_dict(data)

    def test_rejects_non_dict_rule(self):
        data = {"rules": ["not a dict"]}
        with pytest.raises(ValueError, match="not a dict"):
            _validate_policy_dict(data)


# -- Fixtures for mocking -----------------------------------------------------

_VALID_POLICY = {
    "version": "1",
    "defaults": {"risk_level": "medium", "approval": "approve"},
    "rules": [
        {
            "name": "block_deletes",
            "match": {"type": "delete*", "target": "*"},
            "risk_level": "critical",
            "approval": "block",
        },
        {
            "name": "allow_reads",
            "match": {"type": "read*", "target": "*"},
            "risk_level": "low",
            "approval": "auto",
        },
    ],
}


def _mock_openai_response(content: str) -> MagicMock:
    """Create a mock OpenAI ChatCompletion response."""
    choice = MagicMock()
    choice.message.content = content
    response = MagicMock()
    response.choices = [choice]
    return response


def _mock_anthropic_tool_response(data: dict) -> MagicMock:
    """Create a mock Anthropic response with tool_use block."""
    tool_block = MagicMock()
    tool_block.type = "tool_use"
    tool_block.name = "generate_aegis_policy"
    tool_block.input = data
    response = MagicMock()
    response.content = [tool_block]
    return response


def _mock_anthropic_text_response(text: str) -> MagicMock:
    """Create a mock Anthropic response with text block."""
    text_block = MagicMock()
    text_block.type = "text"
    text_block.text = text
    response = MagicMock()
    response.content = [text_block]
    return response


# -- OpenAI generator ---------------------------------------------------------


class TestOpenAIPolicyGenerator:
    @patch("aegis.core.autopolicy_llm.OpenAIPolicyGenerator._get_client")
    def test_generates_policy(self, mock_get_client):
        client = MagicMock()
        client.chat.completions.create.return_value = _mock_openai_response(
            json.dumps(_VALID_POLICY)
        )
        mock_get_client.return_value = client

        gen = OpenAIPolicyGenerator(api_key="sk-test")
        result = gen.generate("block all deletes, allow reads")

        assert result["version"] == "1"
        assert len(result["rules"]) == 2
        assert result["rules"][0]["name"] == "block_deletes"
        assert result["rules"][0]["approval"] == "block"

    @patch("aegis.core.autopolicy_llm.OpenAIPolicyGenerator._get_client")
    def test_uses_structured_output(self, mock_get_client):
        client = MagicMock()
        client.chat.completions.create.return_value = _mock_openai_response(
            json.dumps(_VALID_POLICY)
        )
        mock_get_client.return_value = client

        gen = OpenAIPolicyGenerator(model="gpt-4o")
        gen.generate("test")

        call_kwargs = client.chat.completions.create.call_args[1]
        assert call_kwargs["response_format"]["type"] == "json_schema"
        assert call_kwargs["response_format"]["json_schema"]["name"] == "aegis_policy"

    @patch("aegis.core.autopolicy_llm.OpenAIPolicyGenerator._get_client")
    def test_empty_response_raises(self, mock_get_client):
        client = MagicMock()
        client.chat.completions.create.return_value = _mock_openai_response("")
        mock_get_client.return_value = client

        gen = OpenAIPolicyGenerator(api_key="sk-test")
        with pytest.raises(ValueError, match="Empty response"):
            gen.generate("test")

    @patch("aegis.core.autopolicy_llm.OpenAIPolicyGenerator._get_client")
    def test_invalid_json_raises(self, mock_get_client):
        client = MagicMock()
        client.chat.completions.create.return_value = _mock_openai_response(
            "not json"
        )
        mock_get_client.return_value = client

        gen = OpenAIPolicyGenerator(api_key="sk-test")
        with pytest.raises(json.JSONDecodeError):
            gen.generate("test")

    @patch("aegis.core.autopolicy_llm.OpenAIPolicyGenerator._get_client")
    def test_custom_temperature(self, mock_get_client):
        client = MagicMock()
        client.chat.completions.create.return_value = _mock_openai_response(
            json.dumps(_VALID_POLICY)
        )
        mock_get_client.return_value = client

        gen = OpenAIPolicyGenerator(temperature=0.7)
        gen.generate("test")

        call_kwargs = client.chat.completions.create.call_args[1]
        assert call_kwargs["temperature"] == 0.7

    def test_import_error_without_openai(self):
        gen = OpenAIPolicyGenerator(api_key="sk-test")
        gen._client = None  # Force re-import
        with patch.dict("sys.modules", {"openai": None}):
            with pytest.raises(ImportError, match="openai"):
                gen._get_client()


# -- Anthropic generator -------------------------------------------------------


class TestAnthropicPolicyGenerator:
    @patch("aegis.core.autopolicy_llm.AnthropicPolicyGenerator._get_client")
    def test_generates_policy_via_tool(self, mock_get_client):
        client = MagicMock()
        client.messages.create.return_value = _mock_anthropic_tool_response(
            _VALID_POLICY
        )
        mock_get_client.return_value = client

        gen = AnthropicPolicyGenerator(api_key="sk-ant-test")
        result = gen.generate("block deletes, allow reads")

        assert result["version"] == "1"
        assert len(result["rules"]) == 2

    @patch("aegis.core.autopolicy_llm.AnthropicPolicyGenerator._get_client")
    def test_uses_tool_choice(self, mock_get_client):
        client = MagicMock()
        client.messages.create.return_value = _mock_anthropic_tool_response(
            _VALID_POLICY
        )
        mock_get_client.return_value = client

        gen = AnthropicPolicyGenerator()
        gen.generate("test")

        call_kwargs = client.messages.create.call_args[1]
        assert call_kwargs["tool_choice"]["type"] == "tool"
        assert call_kwargs["tool_choice"]["name"] == "generate_aegis_policy"
        assert len(call_kwargs["tools"]) == 1

    @patch("aegis.core.autopolicy_llm.AnthropicPolicyGenerator._get_client")
    def test_fallback_to_text_yaml(self, mock_get_client):
        client = MagicMock()
        yaml_text = yaml.dump(_VALID_POLICY, default_flow_style=False)
        client.messages.create.return_value = _mock_anthropic_text_response(yaml_text)
        mock_get_client.return_value = client

        gen = AnthropicPolicyGenerator(api_key="sk-ant-test")
        result = gen.generate("test")

        assert result["version"] == "1"
        assert len(result["rules"]) == 2

    @patch("aegis.core.autopolicy_llm.AnthropicPolicyGenerator._get_client")
    def test_empty_response_raises(self, mock_get_client):
        client = MagicMock()
        response = MagicMock()
        response.content = []
        client.messages.create.return_value = response
        mock_get_client.return_value = client

        gen = AnthropicPolicyGenerator(api_key="sk-ant-test")
        with pytest.raises(ValueError, match="No valid policy"):
            gen.generate("test")

    def test_import_error_without_anthropic(self):
        gen = AnthropicPolicyGenerator(api_key="sk-ant-test")
        gen._client = None
        with patch.dict("sys.modules", {"anthropic": None}):
            with pytest.raises(ImportError, match="anthropic"):
                gen._get_client()


# -- YAML fallback generator ---------------------------------------------------


class TestYAMLFallbackGenerator:
    @patch("aegis.core.autopolicy_llm.YAMLFallbackGenerator._get_client")
    def test_generates_from_yaml(self, mock_get_client):
        client = MagicMock()
        yaml_text = yaml.dump(_VALID_POLICY, default_flow_style=False)
        client.chat.completions.create.return_value = _mock_openai_response(yaml_text)
        mock_get_client.return_value = client

        gen = YAMLFallbackGenerator(model="llama3")
        result = gen.generate("block deletes")

        assert result["version"] == "1"
        assert len(result["rules"]) == 2

    @patch("aegis.core.autopolicy_llm.YAMLFallbackGenerator._get_client")
    def test_strips_markdown_fences(self, mock_get_client):
        client = MagicMock()
        yaml_text = yaml.dump(_VALID_POLICY, default_flow_style=False)
        fenced = f"```yaml\n{yaml_text}\n```"
        client.chat.completions.create.return_value = _mock_openai_response(fenced)
        mock_get_client.return_value = client

        gen = YAMLFallbackGenerator()
        result = gen.generate("test")

        assert result["version"] == "1"

    @patch("aegis.core.autopolicy_llm.YAMLFallbackGenerator._get_client")
    def test_empty_response_raises(self, mock_get_client):
        client = MagicMock()
        client.chat.completions.create.return_value = _mock_openai_response("")
        mock_get_client.return_value = client

        gen = YAMLFallbackGenerator()
        with pytest.raises(ValueError, match="Empty response"):
            gen.generate("test")

    @patch("aegis.core.autopolicy_llm.YAMLFallbackGenerator._get_client")
    def test_custom_base_url(self, mock_get_client):
        """Ensures custom base_url is used (for vLLM, Ollama, etc.)."""
        gen = YAMLFallbackGenerator(
            base_url="http://my-vllm:8000/v1",
            api_key="test-key",
            model="mistral",
        )
        assert gen._base_url == "http://my-vllm:8000/v1"
        assert gen._model == "mistral"


# -- Integration with autopolicy -----------------------------------------------


class TestAutopolicyIntegration:
    @patch("aegis.core.autopolicy_llm.OpenAIPolicyGenerator._get_client")
    def test_openai_with_generate_policy(self, mock_get_client):
        """Test that OpenAI generator works with generate_policy()."""
        from aegis.core.autopolicy import generate_policy

        client = MagicMock()
        client.chat.completions.create.return_value = _mock_openai_response(
            json.dumps(_VALID_POLICY)
        )
        mock_get_client.return_value = client

        gen = OpenAIPolicyGenerator(api_key="sk-test")
        policy = generate_policy("block deletes, allow reads", generator=gen)

        # Should return a valid Policy object
        assert policy is not None

    @patch("aegis.core.autopolicy_llm.AnthropicPolicyGenerator._get_client")
    def test_anthropic_with_generate_policy_yaml(self, mock_get_client):
        """Test that Anthropic generator works with generate_policy_yaml()."""
        from aegis.core.autopolicy import generate_policy_yaml

        client = MagicMock()
        client.messages.create.return_value = _mock_anthropic_tool_response(
            _VALID_POLICY
        )
        mock_get_client.return_value = client

        gen = AnthropicPolicyGenerator(api_key="sk-ant-test")
        yaml_str = generate_policy_yaml("block deletes", generator=gen)

        assert isinstance(yaml_str, str)
        parsed = yaml.safe_load(yaml_str)
        assert parsed["version"] == "1"


# -- Protocol compliance -------------------------------------------------------


class TestProtocolCompliance:
    def test_openai_is_policy_generator(self):
        from aegis.core.autopolicy import PolicyGenerator

        gen = OpenAIPolicyGenerator(api_key="test")
        assert isinstance(gen, PolicyGenerator)

    def test_anthropic_is_policy_generator(self):
        from aegis.core.autopolicy import PolicyGenerator

        gen = AnthropicPolicyGenerator(api_key="test")
        assert isinstance(gen, PolicyGenerator)

    def test_fallback_is_policy_generator(self):
        from aegis.core.autopolicy import PolicyGenerator

        gen = YAMLFallbackGenerator()
        assert isinstance(gen, PolicyGenerator)
