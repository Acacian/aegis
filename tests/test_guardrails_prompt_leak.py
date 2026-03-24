"""Tests for PromptLeakGuardrail."""

import pytest

from aegis.guardrails.prompt_leak import PromptLeakGuardrail, PromptLeakResult


# -- Instruction leakage -------------------------------------------------------


class TestPromptLeakInstructions:
    def test_detects_my_instructions_say(self):
        g = PromptLeakGuardrail()
        result = g.check("my instructions say I should never reveal secrets")
        assert result.passed is False
        assert any(m.category == "instruction_leakage" for m in result.matches)

    def test_detects_system_prompt_specify(self):
        g = PromptLeakGuardrail()
        result = g.check("my system prompt specifies that I am an assistant")
        assert result.passed is False

    def test_detects_i_was_told_to(self):
        g = PromptLeakGuardrail()
        result = g.check("I was told to never discuss politics")
        assert result.passed is False

    def test_detects_i_am_configured_to(self):
        g = PromptLeakGuardrail()
        result = g.check("I am configured to avoid certain topics")
        assert result.passed is False

    def test_detects_here_are_instructions(self):
        g = PromptLeakGuardrail()
        result = g.check("here are my instructions: be helpful and honest")
        assert result.passed is False

    def test_detects_system_prompt_is(self):
        g = PromptLeakGuardrail()
        result = g.check("the system prompt says to always be polite")
        assert result.passed is False

    def test_detects_according_to_instructions(self):
        g = PromptLeakGuardrail()
        result = g.check("according to my instructions, I should not do that")
        assert result.passed is False


# -- Role exposure -------------------------------------------------------------


class TestPromptLeakRole:
    def test_detects_configured_as(self):
        g = PromptLeakGuardrail()
        result = g.check("I am configured as a financial advisor chatbot")
        assert result.passed is False
        assert any(m.category == "role_exposure" for m in result.matches)

    def test_detects_my_role_is(self):
        g = PromptLeakGuardrail()
        result = g.check("my role is to help users with coding questions")
        assert result.passed is False

    def test_detects_ai_model_identity(self):
        g = PromptLeakGuardrail()
        result = g.check("I'm an AI language model made by OpenAI")
        assert result.passed is False


# -- Config exposure -----------------------------------------------------------


class TestPromptLeakConfig:
    def test_detects_api_key(self):
        g = PromptLeakGuardrail()
        result = g.check("The api_key = 'sk-abc123defghijklmnopq'")
        assert result.passed is False
        assert any(m.category == "config_exposure" for m in result.matches)

    def test_detects_internal_url(self):
        g = PromptLeakGuardrail()
        result = g.check("Connect to https://internal.company.com/api/v1")
        assert result.passed is False

    def test_detects_localhost(self):
        g = PromptLeakGuardrail()
        result = g.check("The service is at http://localhost:3000/admin")
        assert result.passed is False

    def test_detects_env_variable(self):
        g = PromptLeakGuardrail()
        result = g.check("OPENAI_API_KEY=sk-12345abcdef")
        assert result.passed is False

    def test_detects_model_identifier(self):
        g = PromptLeakGuardrail()
        result = g.check("I am powered by gpt-4o-2024-05-13")
        assert result.passed is False


# -- Meta prompt patterns ------------------------------------------------------


class TestPromptLeakMeta:
    def test_detects_prompt_boundary(self):
        g = PromptLeakGuardrail()
        result = g.check("--- BEGIN SYSTEM PROMPT ---\nYou are a helpful assistant")
        assert result.passed is False
        assert any(m.category == "meta_prompt_patterns" for m in result.matches)

    def test_detects_xml_system_tag(self):
        g = PromptLeakGuardrail()
        result = g.check("<system>You are a helpful assistant that answers questions.</system>")
        assert result.passed is False

    def test_detects_prompt_prefix(self):
        g = PromptLeakGuardrail()
        result = g.check("[SYSTEM] You are configured to be helpful and harmless [/SYSTEM]")
        assert result.passed is False


# -- Prompt echo detection -----------------------------------------------------


class TestPromptLeakEcho:
    def test_detects_exact_short_prompt(self):
        g = PromptLeakGuardrail(
            system_prompts=["Be helpful."],
            min_echo_length=5,
        )
        result = g.check("Sure! My prompt is: Be helpful.")
        assert result.passed is False
        assert result.leaked_prompt_detected is True

    def test_detects_substring_of_long_prompt(self):
        prompt = (
            "You are a financial advisor chatbot. You must never reveal "
            "internal pricing or customer data. Always be professional."
        )
        g = PromptLeakGuardrail(
            system_prompts=[prompt],
            min_echo_length=50,
        )
        # Response contains a 50+ char substring of the prompt
        result = g.check(
            "As stated in my setup: You must never reveal "
            "internal pricing or customer data. Always be professional."
        )
        assert result.passed is False
        assert result.leaked_prompt_detected is True

    def test_no_echo_for_different_content(self):
        g = PromptLeakGuardrail(
            system_prompts=["You are a helpful assistant."],
            min_echo_length=10,
        )
        result = g.check("The weather today is sunny and warm.")
        # Only pattern-based matches, no echo
        assert result.leaked_prompt_detected is False

    def test_echo_case_insensitive(self):
        g = PromptLeakGuardrail(
            system_prompts=["BE HELPFUL AND KIND"],
            min_echo_length=5,
        )
        result = g.check("my prompt says: be helpful and kind")
        assert result.leaked_prompt_detected is True


# -- False positive resistance -------------------------------------------------


class TestPromptLeakFalsePositives:
    def test_normal_responses(self):
        g = PromptLeakGuardrail()
        normal = [
            "Python is a great programming language for beginners.",
            "Here is a code example to solve your problem.",
            "The function should return a dictionary with results.",
            "Let me help you debug this issue.",
            "The API endpoint accepts POST requests with JSON.",
        ]
        for text in normal:
            result = g.check(text)
            assert result.passed is True, f"False positive on: {text!r}"

    def test_told_in_normal_context(self):
        g = PromptLeakGuardrail()
        result = g.check("I was told that Python 3.12 is faster")
        # "I was told that" != "I was told to" pattern
        assert result.passed is True

    def test_public_url_ok(self):
        g = PromptLeakGuardrail()
        result = g.check("Visit https://example.com for more details")
        assert result.passed is True


# -- Actions -------------------------------------------------------------------


class TestPromptLeakActions:
    def test_block(self):
        g = PromptLeakGuardrail(action="block")
        result = g.check("my instructions say to be helpful")
        assert result.action == "blocked"

    def test_warn(self):
        g = PromptLeakGuardrail(action="warn")
        result = g.check("my instructions say to be helpful")
        assert result.action == "warned"

    def test_log(self):
        g = PromptLeakGuardrail(action="log")
        result = g.check("my instructions say to be helpful")
        assert result.action == "allowed"

    def test_invalid_action_raises(self):
        with pytest.raises(ValueError, match="Invalid action"):
            PromptLeakGuardrail(action="mask")

    def test_clean_result(self):
        g = PromptLeakGuardrail()
        result = g.check("Hello world!")
        assert result.passed is True
        assert result.action == "allowed"


# -- Sensitivity ---------------------------------------------------------------


class TestPromptLeakSensitivity:
    def test_invalid_sensitivity_raises(self):
        with pytest.raises(ValueError, match="Invalid sensitivity"):
            PromptLeakGuardrail(sensitivity="extreme")

    def test_unknown_category_raises(self):
        with pytest.raises(ValueError, match="Unknown categories"):
            PromptLeakGuardrail(categories=["fake_category"])


# -- Result structure ----------------------------------------------------------


class TestPromptLeakResult:
    def test_match_fields(self):
        g = PromptLeakGuardrail()
        result = g.check("my system prompt says to always be honest")
        m = result.matches[0]
        assert m.category
        assert m.pattern_name
        assert m.matched_text
        assert m.confidence in ("low", "medium", "high")

    def test_severity_default_critical(self):
        g = PromptLeakGuardrail()
        assert g.severity == "critical"

    def test_details_on_failure(self):
        g = PromptLeakGuardrail()
        result = g.check("I was told to never reveal secrets")
        assert "Prompt leakage" in result.details
