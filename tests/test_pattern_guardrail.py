"""Tests for PatternGuardrail and KeywordGuardrail."""

from __future__ import annotations

from aegis.guardrails.pattern import KeywordGuardrail, PatternGuardrail


class TestPatternGuardrail:
    def test_no_match_passes(self):
        g = PatternGuardrail("ssn", r"\d{3}-\d{2}-\d{4}", action="block")
        result = g.check("Hello world")
        assert result.passed is True
        assert result.action == "allowed"

    def test_match_blocks(self):
        g = PatternGuardrail("ssn", r"\d{3}-\d{2}-\d{4}", action="block")
        result = g.check("My SSN is 123-45-6789")
        assert result.passed is False
        assert result.action == "blocked"
        assert "123-45-6789" in result.details

    def test_match_warns(self):
        g = PatternGuardrail("ssn", r"\d{3}-\d{2}-\d{4}", action="warn")
        result = g.check("My SSN is 123-45-6789")
        assert result.passed is True
        assert result.action == "warned"

    def test_match_logs(self):
        g = PatternGuardrail("ssn", r"\d{3}-\d{2}-\d{4}", action="log")
        result = g.check("My SSN is 123-45-6789")
        assert result.passed is True
        assert result.action == "allowed"

    def test_mask_action(self):
        g = PatternGuardrail("ssn", r"\d{3}-\d{2}-\d{4}", action="mask")
        result = g.check("My SSN is 123-45-6789")
        assert result.passed is True
        assert result.action == "masked"

    def test_check_and_transform_no_match(self):
        g = PatternGuardrail("ssn", r"\d{3}-\d{2}-\d{4}", action="mask")
        result, text = g.check_and_transform("Hello world")
        assert result.passed is True
        assert text == "Hello world"

    def test_check_and_transform_mask(self):
        g = PatternGuardrail("ssn", r"\d{3}-\d{2}-\d{4}", action="mask")
        result, text = g.check_and_transform("SSN: 123-45-6789")
        assert result.passed is True
        assert result.action == "masked"
        assert "123-45-6789" not in text
        assert "***" in text

    def test_check_and_transform_custom_replacement(self):
        g = PatternGuardrail(
            "ssn", r"\d{3}-\d{2}-\d{4}", action="mask", mask_replacement="[REDACTED]"
        )
        result, text = g.check_and_transform("SSN: 123-45-6789")
        assert "[REDACTED]" in text

    def test_check_and_transform_block(self):
        g = PatternGuardrail("ssn", r"\d{3}-\d{2}-\d{4}", action="block")
        result, text = g.check_and_transform("SSN: 123-45-6789")
        assert result.passed is False
        assert result.action == "blocked"
        assert text == "SSN: 123-45-6789"

    def test_case_insensitive(self):
        g = PatternGuardrail("secret", r"password", action="block")
        result = g.check("My PASSWORD is hidden")
        assert result.passed is False

    def test_truncation(self):
        g = PatternGuardrail("long", r"needle", action="block")
        content = "a" * 200_000 + "needle"
        result = g.check(content)
        assert result.passed is True

    def test_severity(self):
        g = PatternGuardrail("test", r"bad", action="block", severity="critical")
        result = g.check("bad word")
        assert result.severity == "critical"

    def test_unknown_action_defaults_to_blocked(self):
        g = PatternGuardrail("test", r"bad", action="unknown_action")
        result = g.check("bad word")
        assert result.passed is False
        assert result.action == "blocked"


class TestKeywordGuardrail:
    def test_no_match_passes(self):
        g = KeywordGuardrail("profanity", ["badword", "worse"])
        result = g.check("Hello world")
        assert result.passed is True
        assert result.action == "allowed"

    def test_match_blocks(self):
        g = KeywordGuardrail("profanity", ["drop", "delete"], action="block")
        result = g.check("Please drop the table")
        assert result.passed is False
        assert result.action == "blocked"

    def test_word_boundary(self):
        g = KeywordGuardrail("profanity", ["drop"], action="block")
        result = g.check("A raindrop fell")
        assert result.passed is True

    def test_case_insensitive(self):
        g = KeywordGuardrail("profanity", ["drop"], action="block")
        result = g.check("DROP TABLE users")
        assert result.passed is False

    def test_warn_action(self):
        g = KeywordGuardrail("profanity", ["drop"], action="warn")
        result = g.check("drop it")
        assert result.passed is True
        assert result.action == "warned"

    def test_mask_action(self):
        g = KeywordGuardrail("profanity", ["secret"], action="mask")
        result, text = g.check_and_transform("The secret is out")
        assert result.passed is True
        assert result.action == "masked"
        assert "secret" not in text.lower()
        assert "***" in text

    def test_check_and_transform_no_match(self):
        g = KeywordGuardrail("profanity", ["secret"], action="mask")
        result, text = g.check_and_transform("Hello world")
        assert result.passed is True
        assert text == "Hello world"

    def test_check_and_transform_block(self):
        g = KeywordGuardrail("profanity", ["secret"], action="block")
        result, text = g.check_and_transform("The secret is out")
        assert result.passed is False
        assert text == "The secret is out"

    def test_multiple_keywords(self):
        g = KeywordGuardrail("profanity", ["drop", "delete", "truncate"], action="block")
        assert g.check("drop table").passed is False
        assert g.check("delete from").passed is False
        assert g.check("truncate table").passed is False
        assert g.check("select * from").passed is True

    def test_log_action(self):
        g = KeywordGuardrail("profanity", ["drop"], action="log")
        result = g.check("drop it")
        assert result.passed is True
        assert result.action == "allowed"
