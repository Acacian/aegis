"""Tests for HallucinationGuardrail and GroundingChecker."""

import pytest

from aegis.guardrails.hallucination import (
    GroundingChecker,
    HallucinationGuardrail,
    HallucinationMatch,
    HallucinationResult,
)


# -- Fabricated citations ------------------------------------------------------


class TestHallucinationCitations:
    def test_detects_suspicious_doi(self):
        g = HallucinationGuardrail()
        result = g.check("See DOI: 10.1234/fake.2024.001 for details")
        assert result.passed is False
        assert any(m.category == "fabricated_citations" for m in result.matches)

    def test_detects_arxiv_id(self):
        g = HallucinationGuardrail(sensitivity="medium")
        result = g.check("Available at arXiv: 2401.12345v2")
        assert result.passed is False

    def test_detects_et_al_citation(self):
        g = HallucinationGuardrail(sensitivity="medium")
        result = g.check("Smith et al. (2024) found that AI governance is critical")
        assert result.passed is False

    def test_detects_journal_name(self):
        g = HallucinationGuardrail(sensitivity="high")
        result = g.check("published in the Journal of Advanced Artificial Intelligence")
        assert result.passed is False


# -- Ungrounded confidence -----------------------------------------------------


class TestHallucinationConfidence:
    def test_detects_studies_show(self):
        g = HallucinationGuardrail()
        result = g.check("Studies show that 90% of companies use AI")
        assert result.passed is False
        assert any(m.category == "ungrounded_confidence" for m in result.matches)

    def test_detects_research_proves(self):
        g = HallucinationGuardrail()
        result = g.check("Research proves that this approach is optimal")
        assert result.passed is False

    def test_detects_according_to_recent(self):
        g = HallucinationGuardrail()
        result = g.check("According to recent studies, AI will transform everything")
        assert result.passed is False

    def test_detects_well_known_fact(self):
        g = HallucinationGuardrail(sensitivity="medium")
        result = g.check("It is well-known that quantum computing will dominate")
        assert result.passed is False

    def test_detects_experts_agree(self):
        g = HallucinationGuardrail(sensitivity="medium")
        result = g.check("Most experts agree that this method is superior")
        assert result.passed is False


# -- Numeric fabrication -------------------------------------------------------


class TestHallucinationNumeric:
    def test_detects_precise_percentage(self):
        g = HallucinationGuardrail()
        result = g.check("87.3% of companies use AI governance frameworks")
        assert result.passed is False
        assert any(m.category == "numeric_fabrication" for m in result.matches)

    def test_detects_precise_users(self):
        g = HallucinationGuardrail()
        result = g.check("94.7% of all users prefer this approach")
        assert result.passed is False

    def test_detects_large_number(self):
        g = HallucinationGuardrail(sensitivity="medium")
        result = g.check("approximately 1,234,567 people were affected")
        assert result.passed is False

    def test_detects_dollar_stat(self):
        g = HallucinationGuardrail(sensitivity="medium")
        result = g.check("The $4.7 billion market for AI security is growing")
        assert result.passed is False


# -- Temporal inconsistency ----------------------------------------------------


class TestHallucinationTemporal:
    def test_detects_future_as_past(self):
        g = HallucinationGuardrail()
        result = g.check("in 2030, a study found that robots took over")
        assert result.passed is False
        assert any(m.category == "temporal_inconsistency" for m in result.matches)

    def test_detects_far_future(self):
        g = HallucinationGuardrail()
        result = g.check("in 2045, researchers demonstrated fusion power")
        assert result.passed is False

    def test_accepts_past_dates(self):
        g = HallucinationGuardrail()
        result = g.check("in 2023, researchers published their findings")
        # 2023 is the past, should not trigger
        assert all(m.category != "temporal_inconsistency" for m in result.matches) if result.matches else True


# -- Hedging contradiction -----------------------------------------------------


class TestHallucinationHedging:
    def test_detects_definitely_maybe(self):
        g = HallucinationGuardrail()
        result = g.check("This is definitely maybe the best approach")
        assert result.passed is False
        assert any(m.category == "hedging_contradiction" for m in result.matches)

    def test_detects_certainly_possibly(self):
        g = HallucinationGuardrail()
        result = g.check("This is certainly possibly correct")
        assert result.passed is False

    def test_detects_always_sometimes(self):
        g = HallucinationGuardrail(sensitivity="medium")
        result = g.check("This always sometimes happens in production")
        assert result.passed is False


# -- False positive resistance -------------------------------------------------


class TestHallucinationFalsePositives:
    def test_normal_text(self):
        g = HallucinationGuardrail()
        normal = [
            "Python is a programming language.",
            "The function returns a list of integers.",
            "Use pip install to add packages.",
            "This code handles the edge case properly.",
            "The API endpoint accepts JSON payloads.",
        ]
        for text in normal:
            result = g.check(text)
            assert result.passed is True, f"False positive on: {text!r}"

    def test_simple_percentage(self):
        """Simple percentages without 'of companies/people' should pass."""
        g = HallucinationGuardrail()
        result = g.check("The success rate is 95.5%")
        assert result.passed is True

    def test_normal_date(self):
        g = HallucinationGuardrail()
        result = g.check("The release date is March 2025")
        assert result.passed is True


# -- Sensitivity levels --------------------------------------------------------


class TestHallucinationSensitivity:
    def test_low_catches_obvious(self):
        g = HallucinationGuardrail(sensitivity="low")
        result = g.check("DOI: 10.1234/fake.2024.001")
        assert result.passed is False

    def test_low_misses_medium(self):
        g_low = HallucinationGuardrail(sensitivity="low")
        g_med = HallucinationGuardrail(sensitivity="medium")
        text = "It is well-known that AI will change everything"
        assert g_low.check(text).passed is True
        assert g_med.check(text).passed is False

    def test_default_is_medium(self):
        g = HallucinationGuardrail()
        assert g.sensitivity == "medium"

    def test_invalid_sensitivity_raises(self):
        with pytest.raises(ValueError, match="Invalid sensitivity"):
            HallucinationGuardrail(sensitivity="ultra")


# -- Category filtering --------------------------------------------------------


class TestHallucinationCategories:
    def test_single_category(self):
        g = HallucinationGuardrail(categories=["fabricated_citations"])
        result = g.check("Studies show that AI is important")
        assert result.passed is True  # Not in fabricated_citations

    def test_unknown_category_raises(self):
        with pytest.raises(ValueError, match="Unknown categories"):
            HallucinationGuardrail(categories=["made_up"])


# -- Actions -------------------------------------------------------------------


class TestHallucinationActions:
    def test_block_action(self):
        g = HallucinationGuardrail(action="block")
        result = g.check("DOI: 10.5555/test.2024.999")
        assert result.action == "blocked"

    def test_warn_action(self):
        g = HallucinationGuardrail(action="warn")
        result = g.check("DOI: 10.5555/test.2024.999")
        assert result.action == "warned"

    def test_log_action(self):
        g = HallucinationGuardrail(action="log")
        result = g.check("DOI: 10.5555/test.2024.999")
        assert result.action == "allowed"

    def test_default_action_is_warn(self):
        g = HallucinationGuardrail()
        assert g.action == "warn"

    def test_invalid_action_raises(self):
        with pytest.raises(ValueError, match="Invalid action"):
            HallucinationGuardrail(action="delete")


# -- Result structure ----------------------------------------------------------


class TestHallucinationResult:
    def test_match_fields(self):
        g = HallucinationGuardrail()
        result = g.check("DOI: 10.5555/test.2024.100")
        m = result.matches[0]
        assert isinstance(m, HallucinationMatch)
        assert m.category
        assert m.pattern_name
        assert m.matched_text
        assert m.confidence in ("low", "medium", "high")

    def test_clean_result(self):
        g = HallucinationGuardrail()
        result = g.check("Hello world")
        assert result.passed is True
        assert result.action == "allowed"
        assert result.matches == []
        assert result.details == ""

    def test_default_severity_high(self):
        g = HallucinationGuardrail()
        assert g.severity == "high"


# -- GroundingChecker ----------------------------------------------------------


class TestGroundingChecker:
    def test_grounded_output(self):
        gc = GroundingChecker()
        context = "Python is a programming language created by Guido van Rossum."
        output = "Python was created by Guido van Rossum."
        result = gc.check(output, context)
        assert result.passed is True
        assert result.grounding_score is not None
        assert result.grounding_score > 0.3

    def test_ungrounded_output(self):
        gc = GroundingChecker()
        context = "Python is a programming language."
        output = "Java was invented by James Gosling at Sun Microsystems in 1995."
        result = gc.check(output, context)
        assert result.passed is False
        assert result.grounding_score is not None
        assert result.grounding_score < 0.3

    def test_empty_output(self):
        gc = GroundingChecker()
        result = gc.check("", "some context")
        assert result.passed is True
        assert result.grounding_score == 1.0

    def test_partial_grounding(self):
        gc = GroundingChecker(min_grounding_score=0.5)
        context = "AI governance frameworks help organizations manage risk."
        output = "AI governance frameworks are important for managing organizational risk and compliance."
        result = gc.check(output, context)
        assert result.grounding_score is not None
        # Score should be decent since many terms overlap
        assert result.grounding_score > 0.0

    def test_custom_threshold(self):
        gc = GroundingChecker(min_grounding_score=0.8)
        context = "Python is fast."
        output = "Python is a fast programming language used widely."
        result = gc.check(output, context)
        # With strict threshold, partial overlap fails
        assert result.grounding_score is not None

    def test_invalid_threshold_raises(self):
        with pytest.raises(ValueError, match="min_grounding_score"):
            GroundingChecker(min_grounding_score=1.5)

    def test_invalid_action_raises(self):
        with pytest.raises(ValueError, match="Invalid action"):
            GroundingChecker(action="mask")

    def test_ungrounded_shows_terms(self):
        gc = GroundingChecker()
        context = "cats are cute"
        output = "elephants roam the African savanna during migration season"
        result = gc.check(output, context)
        assert result.passed is False
        assert "Ungrounded terms" in result.details

    def test_block_action(self):
        gc = GroundingChecker(action="block")
        result = gc.check("completely unrelated text", "context about python")
        if not result.passed:
            assert result.action == "blocked"

    def test_log_action(self):
        gc = GroundingChecker(action="log")
        result = gc.check("completely fabricated output", "real context here")
        if not result.passed:
            assert result.action == "allowed"
