"""Tests for base guardrail classes: GuardrailResult, PatternGuardrail, KeywordGuardrail."""

import pytest

from aegis.guardrails.base import GuardrailResult
from aegis.guardrails.pattern import KeywordGuardrail, PatternGuardrail

# -- GuardrailResult --------------------------------------------------------


class TestGuardrailResult:
    def test_result_fields(self):
        r = GuardrailResult(
            passed=True,
            guardrail_name="test",
            action="allowed",
        )
        assert r.passed is True
        assert r.guardrail_name == "test"
        assert r.action == "allowed"
        assert r.details is None
        assert r.masked_content is None
        assert r.original_content is None
        assert r.severity == "medium"

    def test_result_is_frozen(self):
        r = GuardrailResult(passed=True, guardrail_name="x", action="allowed")
        with pytest.raises(AttributeError):
            r.passed = False  # type: ignore[misc]


# -- PatternGuardrail -------------------------------------------------------


class TestPatternGuardrail:
    def test_blocks_on_match(self):
        g = PatternGuardrail(name="ssn", pattern=r"\d{3}-\d{2}-\d{4}", action="block")
        result = g.check("my ssn is 123-45-6789")
        assert result.passed is False
        assert result.action == "blocked"
        assert "123-45-6789" in (result.details or "")

    def test_blocks_on_match_transform(self):
        g = PatternGuardrail(name="ssn", pattern=r"\d{3}-\d{2}-\d{4}", action="block")
        result, content = g.check_and_transform("my ssn is 123-45-6789")
        assert result.passed is False
        assert result.action == "blocked"
        # Blocked action does not modify content
        assert content == "my ssn is 123-45-6789"

    def test_masks_matched_content(self):
        g = PatternGuardrail(
            name="email",
            pattern=r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            action="mask",
        )
        result, content = g.check_and_transform("email: user@example.com")
        assert result.passed is True
        assert result.action == "masked"
        assert "user@example.com" not in content
        assert "***" in content
        assert result.masked_content == content
        assert result.original_content == "email: user@example.com"

    def test_masks_check_only(self):
        """check() reports masked but does not transform."""
        g = PatternGuardrail(name="em", pattern=r"\w+@\w+\.\w+", action="mask")
        result = g.check("email: a@b.com")
        assert result.passed is True
        assert result.action == "masked"

    def test_warns_but_passes(self):
        g = PatternGuardrail(name="w", pattern=r"badword", action="warn")
        result = g.check("contains badword here")
        assert result.passed is True
        assert result.action == "warned"

    def test_warns_transform_does_not_modify(self):
        g = PatternGuardrail(name="w", pattern=r"badword", action="warn")
        result, content = g.check_and_transform("contains badword here")
        assert result.passed is True
        assert result.action == "warned"
        assert content == "contains badword here"

    def test_logs_but_passes(self):
        g = PatternGuardrail(name="l", pattern=r"secret", action="log")
        result = g.check("has secret info")
        assert result.passed is True
        assert result.action == "allowed"

    def test_logs_transform_does_not_modify(self):
        g = PatternGuardrail(name="l", pattern=r"secret", action="log")
        result, content = g.check_and_transform("has secret info")
        assert result.passed is True
        assert result.action == "allowed"
        assert content == "has secret info"

    def test_no_match_returns_passed(self):
        g = PatternGuardrail(name="num", pattern=r"\d{10}", action="block")
        result = g.check("no numbers here")
        assert result.passed is True
        assert result.action == "allowed"

    def test_no_match_transform_returns_original(self):
        g = PatternGuardrail(name="num", pattern=r"\d{10}", action="block")
        result, content = g.check_and_transform("no numbers here")
        assert result.passed is True
        assert content == "no numbers here"

    def test_case_insensitive(self):
        g = PatternGuardrail(name="ci", pattern=r"secret", action="block")
        result = g.check("contains SECRET word")
        assert result.passed is False

    def test_custom_mask_replacement(self):
        g = PatternGuardrail(
            name="m",
            pattern=r"\d+",
            action="mask",
            mask_replacement="[REDACTED]",
        )
        result, content = g.check_and_transform("number 42 here")
        assert "[REDACTED]" in content
        assert "42" not in content

    def test_severity_propagates(self):
        g = PatternGuardrail(name="s", pattern=r"x", action="block", severity="critical")
        result = g.check("x")
        assert result.severity == "critical"

    def test_repr(self):
        g = PatternGuardrail(name="test", pattern=r"x")
        assert "PatternGuardrail" in repr(g)


# -- KeywordGuardrail -------------------------------------------------------


class TestKeywordGuardrail:
    def test_detects_keywords(self):
        g = KeywordGuardrail(name="bad", keywords=["DROP TABLE", "DELETE"], action="block")
        result = g.check("please DROP TABLE users")
        assert result.passed is False
        assert result.action == "blocked"

    def test_masks_keywords(self):
        g = KeywordGuardrail(name="bad", keywords=["password", "secret"], action="mask")
        result, content = g.check_and_transform("my password is abc and secret is xyz")
        assert result.passed is True
        assert result.action == "masked"
        assert "password" not in content.lower()
        assert "secret" not in content.lower()
        assert content.count("***") == 2

    def test_no_match_returns_passed(self):
        g = KeywordGuardrail(name="k", keywords=["hack", "exploit"], action="block")
        result = g.check("this is a normal sentence")
        assert result.passed is True
        assert result.action == "allowed"

    def test_no_match_transform_returns_original(self):
        g = KeywordGuardrail(name="k", keywords=["hack"], action="block")
        result, content = g.check_and_transform("normal text")
        assert result.passed is True
        assert content == "normal text"

    def test_word_boundary_no_partial(self):
        """Keywords use word boundaries so 'drop' should not match 'raindrop'."""
        g = KeywordGuardrail(name="b", keywords=["drop"], action="block")
        result = g.check("raindrop on the window")
        assert result.passed is True

    def test_case_insensitive(self):
        g = KeywordGuardrail(name="ci", keywords=["admin"], action="block")
        result = g.check("I am ADMIN here")
        assert result.passed is False

    def test_warn_action(self):
        g = KeywordGuardrail(name="w", keywords=["sensitive"], action="warn")
        result = g.check("this is sensitive data")
        assert result.passed is True
        assert result.action == "warned"

    def test_log_action(self):
        g = KeywordGuardrail(name="l", keywords=["internal"], action="log")
        result = g.check("internal docs")
        assert result.passed is True
        assert result.action == "allowed"

    def test_multiple_keywords(self):
        g = KeywordGuardrail(name="multi", keywords=["alpha", "beta", "gamma"], action="block")
        assert g.check("alpha test").passed is False
        assert g.check("beta test").passed is False
        assert g.check("gamma test").passed is False
        assert g.check("delta test").passed is True

    def test_repr(self):
        g = KeywordGuardrail(name="test", keywords=["a"])
        assert "KeywordGuardrail" in repr(g)
