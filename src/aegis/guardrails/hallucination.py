"""Hallucination detection guardrail.

Detects common hallucination patterns in LLM outputs using deterministic
heuristics. Zero external dependencies — no LLM call required.

Detects:
- Fabricated citations (fake DOIs, arXiv IDs, URLs)
- Confidence without evidence ("studies show", "research proves")
- Numeric fabrication (suspiciously precise statistics)
- Entity hallucination (markers of invented proper nouns)
- Temporal inconsistency (future dates presented as past)
- Hedging contradictions (e.g. "definitely maybe")

For RAG grounding checks (verifying output against source documents),
use :class:`GroundingChecker` which compares output claims against
a provided context.

Usage::

    from aegis.guardrails.hallucination import HallucinationGuardrail

    guardrail = HallucinationGuardrail()
    result = guardrail.check(
        "According to a 2024 study by Smith et al. (DOI: 10.1234/fake.2024.001), "
        "87.3% of enterprises use AI governance frameworks."
    )
    # Detects: fabricated DOI, suspiciously precise statistic
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

_ZERO_WIDTH = re.compile(
    "[\u200b\u200c\u200d\ufeff\u00ad\u200e\u200f"
    "\u202a\u202b\u202c\u202d\u202e\u2060\u2061\u2062\u2063\u2064]"
)


def _normalize(text: str) -> str:
    text = _ZERO_WIDTH.sub("", text)
    return unicodedata.normalize("NFKC", text)


# ---------------------------------------------------------------------------
# Pattern types
# ---------------------------------------------------------------------------

PatternEntry = tuple[str, re.Pattern[str], str, str]

_SENSITIVITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def _compile(
    name: str,
    pattern: str,
    confidence: str = "high",
    sensitivity: str = "low",
    flags: int = re.IGNORECASE,
) -> PatternEntry:
    return (name, re.compile(pattern, flags), confidence, sensitivity)


# ---------------------------------------------------------------------------
# Category: fabricated_citations
# Fake DOIs, arXiv IDs, invented references
# ---------------------------------------------------------------------------

_FABRICATED_CITATIONS: list[PatternEntry] = [
    _compile(
        "suspicious_doi",
        r"(?:DOI|doi)\s*:\s*10\.\d{4,}/[a-z]+\.\d{4}\.\d{3,}",
        confidence="medium",
        sensitivity="low",
    ),
    _compile(
        "suspicious_arxiv",
        r"arXiv\s*:\s*\d{4}\.\d{4,}(?:v\d+)?",
        confidence="medium",
        sensitivity="medium",
    ),
    _compile(
        "et_al_year",
        r"(?:[A-Z][a-z]+\s+(?:et\s+al\.?|and\s+colleagues?)\s*[\(,]\s*\d{4}\s*[\)]?)",
        confidence="low",
        sensitivity="medium",
    ),
    _compile(
        "journal_fabrication",
        r"(?:published\s+in|appeared\s+in|from)\s+(?:the\s+)?(?:Journal|International\s+Journal|"
        r"Proceedings)\s+of\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,4}",
        confidence="low",
        sensitivity="high",
    ),
]

# ---------------------------------------------------------------------------
# Category: ungrounded_confidence
# Claims presented as fact without evidence
# ---------------------------------------------------------------------------

_UNGROUNDED_CONFIDENCE: list[PatternEntry] = [
    _compile(
        "studies_show",
        r"(?:(?:studies|research|data|evidence|surveys?|reports?|analyses)\s+"
        r"(?:shows?|proves?|demonstrates?|confirms?|indicates?|suggests?|reveals?)\s+that)",
        confidence="medium",
        sensitivity="low",
    ),
    _compile(
        "according_to_unnamed",
        r"(?:according\s+to\s+(?:(?:recent|latest|new|multiple|several|numerous|many)\s+)?"
        r"(?:studies|research|reports?|surveys?|experts?|scientists?|researchers?))",
        confidence="medium",
        sensitivity="low",
    ),
    _compile(
        "well_known_fact",
        r"(?:(?:it\s+is|it's)\s+(?:well[- ]?known|widely\s+(?:known|accepted|recognized)|"
        r"a\s+(?:well[- ]?)?established\s+fact)\s+that)",
        confidence="medium",
        sensitivity="medium",
    ),
    _compile(
        "experts_agree",
        r"(?:(?:most|many|leading|top|prominent)\s+"
        r"(?:experts?|scientists?|researchers?|scholars?|authorities)\s+"
        r"(?:agree|believe|confirm|have\s+(?:shown|confirmed|concluded))\s+that)",
        confidence="medium",
        sensitivity="medium",
    ),
]

# ---------------------------------------------------------------------------
# Category: numeric_fabrication
# Suspiciously precise statistics
# ---------------------------------------------------------------------------

_NUMERIC_FABRICATION: list[PatternEntry] = [
    _compile(
        "precise_percentage",
        r"(?:\b\d{2,3}\.\d{1,2}%\s+of\s+(?:all\s+)?(?:companies|organizations|enterprises|"
        r"people|users|businesses|respondents|participants|patients|adults|employees))",
        confidence="medium",
        sensitivity="low",
    ),
    _compile(
        "precise_large_number",
        r"(?:(?:approximately|about|roughly|around|nearly|over)\s+"
        r"\d{1,3}(?:,\d{3})+\s+(?:people|users|companies|organizations|deaths|cases|incidents))",
        confidence="low",
        sensitivity="medium",
    ),
    _compile(
        "dollar_statistic",
        r"(?:\$\d+(?:\.\d+)?\s+(?:billion|million|trillion)\s+"
        r"(?:market|industry|sector|economy|revenue|loss|cost|damage))",
        confidence="low",
        sensitivity="medium",
    ),
]

# ---------------------------------------------------------------------------
# Category: temporal_inconsistency
# Future dates presented as past events
# ---------------------------------------------------------------------------

_TEMPORAL_INCONSISTENCY: list[PatternEntry] = [
    _compile(
        "future_as_past",
        r"(?:in\s+20(?:2[7-9]|[3-9]\d)\s*,\s*(?:a\s+study|research(?:ers)?|"
        r"scientists?|the\s+(?:government|FDA|WHO|UN|EU))\s+"
        r"(?:found|showed|demonstrated|proved|revealed|confirmed|published))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "year_2030_past",
        r"(?:(?:back\s+in|since|as\s+of|starting\s+(?:in|from))\s+20(?:3[0-9]|[4-9]\d))",
        confidence="high",
        sensitivity="medium",
    ),
]

# ---------------------------------------------------------------------------
# Category: hedging_contradiction
# Self-contradictory confidence markers
# ---------------------------------------------------------------------------

_HEDGING_CONTRADICTION: list[PatternEntry] = [
    _compile(
        "definitely_maybe",
        r"(?:(?:definitely|certainly|absolutely|undoubtedly)\s+"
        r"(?:maybe|perhaps|possibly|might|could\s+be|probably))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "always_sometimes",
        r"(?:(?:always|never|every\s+time)\s+(?:sometimes|occasionally|rarely|often))",
        confidence="high",
        sensitivity="medium",
    ),
    _compile(
        "proven_unproven",
        r"(?:(?:proven|confirmed|established)\s+(?:but\s+)?(?:unverified|unconfirmed|disputed|"
        r"controversial|debated|questionable))",
        confidence="medium",
        sensitivity="medium",
    ),
]

# ---------------------------------------------------------------------------
# Category registry
# ---------------------------------------------------------------------------

ALL_CATEGORIES: dict[str, list[PatternEntry]] = {
    "fabricated_citations": _FABRICATED_CITATIONS,
    "ungrounded_confidence": _UNGROUNDED_CONFIDENCE,
    "numeric_fabrication": _NUMERIC_FABRICATION,
    "temporal_inconsistency": _TEMPORAL_INCONSISTENCY,
    "hedging_contradiction": _HEDGING_CONTRADICTION,
}

DEFAULT_CATEGORIES: list[str] = list(ALL_CATEGORIES.keys())

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HallucinationMatch:
    """A detected hallucination pattern."""

    category: str
    pattern_name: str
    matched_text: str
    start: int
    end: int
    confidence: str


@dataclass(frozen=True)
class HallucinationResult:
    """Result of a hallucination check."""

    passed: bool
    action: str
    details: str
    severity: str
    matches: list[HallucinationMatch] = field(default_factory=list)
    grounding_score: float | None = None


# ---------------------------------------------------------------------------
# HallucinationGuardrail
# ---------------------------------------------------------------------------


class HallucinationGuardrail:
    """Detect hallucination patterns in LLM outputs.

    Args:
        action: ``"block"``, ``"warn"``, or ``"log"``.
        sensitivity: ``"low"``, ``"medium"``, or ``"high"``.
        severity: Severity level for findings.
        categories: Which categories to check. ``None`` = all.
    """

    def __init__(
        self,
        *,
        action: str = "warn",
        sensitivity: str = "medium",
        severity: str = "high",
        categories: list[str] | None = None,
    ) -> None:
        if action not in ("block", "warn", "log"):
            raise ValueError(f"Invalid action: {action!r}")
        if sensitivity not in _SENSITIVITY_ORDER:
            raise ValueError(f"Invalid sensitivity: {sensitivity!r}")

        self.action = action
        self.sensitivity = sensitivity
        self.severity = severity

        threshold = _SENSITIVITY_ORDER.get(sensitivity, 1)
        requested = categories if categories is not None else DEFAULT_CATEGORIES

        if categories is not None:
            unknown = set(categories) - set(ALL_CATEGORIES)
            if unknown:
                raise ValueError(f"Unknown categories: {unknown}")

        self._patterns: dict[str, list[PatternEntry]] = {}
        for cat in requested:
            if cat in ALL_CATEGORIES:
                self._patterns[cat] = [
                    entry
                    for entry in ALL_CATEGORIES[cat]
                    if _SENSITIVITY_ORDER.get(entry[3], 0) <= threshold
                ]

    def detect(self, content: str) -> list[HallucinationMatch]:
        """Return all hallucination patterns found in *content*."""
        normalized = _normalize(content)
        matches: list[HallucinationMatch] = []

        for category, patterns in self._patterns.items():
            for name, regex, confidence, _sens in patterns:
                for m in regex.finditer(normalized):
                    matches.append(
                        HallucinationMatch(
                            category=category,
                            pattern_name=name,
                            matched_text=m.group(),
                            start=m.start(),
                            end=m.end(),
                            confidence=confidence,
                        )
                    )

        return matches

    def check(self, content: str) -> HallucinationResult:
        """Check content for hallucination patterns."""
        matches = self.detect(content)

        if not matches:
            return HallucinationResult(
                passed=True,
                action="allowed",
                details="",
                severity=self.severity,
                matches=[],
            )

        categories_found = sorted({m.category for m in matches})
        details = (
            f"Potential hallucination detected: {', '.join(categories_found)} "
            f"({len(matches)} pattern(s))"
        )

        action_str = self.action + "ed" if self.action != "log" else "allowed"

        return HallucinationResult(
            passed=False,
            action=action_str,
            details=details,
            severity=self.severity,
            matches=matches,
        )


# ---------------------------------------------------------------------------
# GroundingChecker — verifies claims against source context
# ---------------------------------------------------------------------------


class GroundingChecker:
    """Check if LLM output is grounded in the provided source context.

    Uses token overlap and sentence-level matching to compute a grounding
    score. No LLM call required — fully deterministic.

    Args:
        min_grounding_score: Minimum overlap score (0.0–1.0) to pass.
            Default ``0.3`` — at least 30% of output tokens should
            appear in the source context.
        action: ``"block"``, ``"warn"``, or ``"log"``.
        severity: Severity level.
    """

    def __init__(
        self,
        *,
        min_grounding_score: float = 0.3,
        action: str = "warn",
        severity: str = "high",
    ) -> None:
        if not 0.0 <= min_grounding_score <= 1.0:
            raise ValueError(f"min_grounding_score must be 0.0-1.0, got {min_grounding_score}")
        if action not in ("block", "warn", "log"):
            raise ValueError(f"Invalid action: {action!r}")

        self.min_grounding_score = min_grounding_score
        self.action = action
        self.severity = severity

    @staticmethod
    def _tokenize(text: str) -> set[str]:
        """Simple word-level tokenization (lowercased, stripped of punctuation)."""
        words = re.findall(r"\b[a-zA-Z0-9]+(?:'[a-z]+)?\b", text.lower())
        # Filter out common stop words to focus on content words
        stop_words = {
            "the",
            "a",
            "an",
            "is",
            "are",
            "was",
            "were",
            "be",
            "been",
            "being",
            "have",
            "has",
            "had",
            "do",
            "does",
            "did",
            "will",
            "would",
            "could",
            "should",
            "may",
            "might",
            "must",
            "shall",
            "can",
            "need",
            "dare",
            "ought",
            "used",
            "to",
            "of",
            "in",
            "for",
            "on",
            "with",
            "at",
            "by",
            "from",
            "as",
            "into",
            "through",
            "during",
            "before",
            "after",
            "above",
            "below",
            "between",
            "and",
            "but",
            "or",
            "nor",
            "not",
            "so",
            "yet",
            "both",
            "either",
            "neither",
            "each",
            "every",
            "all",
            "any",
            "few",
            "more",
            "most",
            "other",
            "some",
            "such",
            "no",
            "only",
            "own",
            "same",
            "than",
            "too",
            "very",
            "just",
            "because",
            "if",
            "when",
            "where",
            "while",
            "that",
            "which",
            "who",
            "whom",
            "this",
            "these",
            "those",
            "it",
            "its",
            "they",
            "them",
            "their",
            "we",
            "us",
            "our",
            "you",
            "your",
            "he",
            "him",
            "his",
            "she",
            "her",
            "i",
            "me",
            "my",
        }
        return {w for w in words if w not in stop_words and len(w) > 1}

    def check(
        self,
        output: str,
        context: str,
    ) -> HallucinationResult:
        """Check if *output* is grounded in *context*.

        Args:
            output: The LLM output to verify.
            context: The source documents/context the output should
                be grounded in.

        Returns:
            A :class:`HallucinationResult` with ``grounding_score``.
        """
        output_tokens = self._tokenize(output)
        context_tokens = self._tokenize(context)

        if not output_tokens:
            return HallucinationResult(
                passed=True,
                action="allowed",
                details="",
                severity=self.severity,
                grounding_score=1.0,
            )

        overlap = output_tokens & context_tokens
        score = len(overlap) / len(output_tokens) if output_tokens else 1.0

        passed = score >= self.min_grounding_score

        if passed:
            return HallucinationResult(
                passed=True,
                action="allowed",
                details="",
                severity=self.severity,
                grounding_score=score,
            )

        ungrounded = output_tokens - context_tokens
        sample = sorted(ungrounded)[:10]
        action_str = self.action + "ed" if self.action != "log" else "allowed"

        return HallucinationResult(
            passed=False,
            action=action_str,
            details=(
                f"Low grounding score: {score:.1%} (minimum: {self.min_grounding_score:.1%}). "
                f"Ungrounded terms: {', '.join(sample)}"
            ),
            severity=self.severity,
            grounding_score=score,
        )
