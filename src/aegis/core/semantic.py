"""Semantic condition evaluator for policy rules.

Provides two tiers of semantic matching:

**Tier 1 (Lite — built-in, no dependencies):**
Keyword/category-based matcher. Tokenizes the semantic condition string
into keywords and checks action fields for matches. Also supports
predefined semantic categories like "destructive", "data_exposure", etc.

**Tier 2 (Full — pluggable):**
Users can supply a custom ``SemanticEvaluator`` (e.g. LLM-backed) via
the Protocol interface. When no evaluator is provided, the built-in
keyword matcher is used.

Example YAML::

    rules:
      - name: no_data_exposure
        match: { type: "*" }
        conditions:
          semantic: "data exposure or PII leak"
        approval: block
"""

from __future__ import annotations

import logging
import re
from typing import Protocol, runtime_checkable

from aegis.core.action import Action

logger = logging.getLogger(__name__)

# -- Predefined semantic categories ------------------------------------------

SEMANTIC_CATEGORIES: dict[str, frozenset[str]] = {
    "destructive": frozenset(
        {"delete", "drop", "remove", "destroy", "kill", "terminate", "truncate", "purge"}
    ),
    "data_exposure": frozenset(
        {"export", "download", "share", "send", "email", "upload", "transfer", "leak", "expose"}
    ),
    "privileged": frozenset(
        {"admin", "root", "sudo", "superuser", "escalate", "override", "bypass"}
    ),
    "financial": frozenset(
        {"payment", "transfer", "refund", "charge", "invoice", "billing", "withdraw"}
    ),
    "pii": frozenset(
        {"name", "email", "phone", "address", "ssn", "passport", "credit_card", "dob"}
    ),
}

# Stop-words stripped when tokenizing free-form semantic conditions.
_STOP_WORDS = frozenset({"or", "and", "the", "a", "an", "of", "in", "to", "for", "is", "with"})

# Regex for splitting a semantic string into word tokens.
_TOKEN_RE = re.compile(r"[a-z0-9_]+")


# -- Protocol (Tier 2) -------------------------------------------------------


@runtime_checkable
class SemanticEvaluator(Protocol):
    """Pluggable evaluator for semantic conditions.

    Implement this protocol (e.g. with an LLM call) and pass it to
    :func:`evaluate_semantic_condition` to replace the built-in keyword
    matcher.
    """

    def evaluate(self, condition: str, action: Action) -> bool:
        """Return True if *action* semantically matches *condition*."""
        ...  # pragma: no cover


# -- Tier 1: keyword matcher -------------------------------------------------


class KeywordSemanticEvaluator:
    """Built-in keyword/category semantic matcher (no external deps).

    Matching logic:

    1. If the condition string exactly matches a predefined category key
       (e.g. ``"destructive"``), the category's keyword set is used.
    2. Otherwise the condition is tokenized into individual keywords
       (lowercased, stop-words removed).
    3. The action's ``type``, ``target``, ``description``, and the keys
       and string values of ``params`` are searched for any keyword match.
    """

    def evaluate(self, condition: str, action: Action) -> bool:
        """Return True if any keyword from *condition* appears in *action* fields."""
        keywords = self._resolve_keywords(condition)
        if not keywords:
            return False
        return self._match_action(keywords, action)

    # -- internals ---

    @staticmethod
    def _resolve_keywords(condition: str) -> frozenset[str]:
        """Expand categories and tokenize the condition string."""
        lowered = condition.strip().lower()

        # Check if the entire condition is a single category name.
        if lowered in SEMANTIC_CATEGORIES:
            return SEMANTIC_CATEGORIES[lowered]

        # Tokenize and expand any embedded category references.
        raw_tokens = _TOKEN_RE.findall(lowered)
        expanded: set[str] = set()
        for token in raw_tokens:
            if token in SEMANTIC_CATEGORIES:
                expanded.update(SEMANTIC_CATEGORIES[token])
            elif token not in _STOP_WORDS:
                expanded.add(token)
        return frozenset(expanded)

    @staticmethod
    def _match_action(keywords: frozenset[str], action: Action) -> bool:
        """Check whether any keyword appears in action fields."""
        # Build a single searchable corpus from action fields.
        corpus_parts: list[str] = [
            action.type.lower(),
            action.target.lower(),
            action.description.lower(),
        ]
        # Add param keys and string values.
        for key, value in action.params.items():
            corpus_parts.append(key.lower())
            if isinstance(value, str):
                corpus_parts.append(value.lower())

        corpus = " ".join(corpus_parts)

        # Tokenize the corpus for word-level matching.
        # Underscored tokens (e.g. "deploy_target") are kept whole AND
        # split into sub-parts so that both "deploy_target" and "deploy"
        # can match.
        raw_tokens = _TOKEN_RE.findall(corpus)
        corpus_tokens: set[str] = set()
        for token in raw_tokens:
            corpus_tokens.add(token)
            if "_" in token:
                corpus_tokens.update(token.split("_"))

        return bool(keywords & corpus_tokens)


# Singleton instance used as default evaluator.
_DEFAULT_EVALUATOR = KeywordSemanticEvaluator()


# -- Public API ---------------------------------------------------------------


def evaluate_semantic_condition(
    condition: str,
    action: Action,
    evaluator: SemanticEvaluator | None = None,
) -> bool:
    """Evaluate a semantic condition against an action.

    Args:
        condition: The semantic condition string from the YAML policy.
        action: The action to evaluate.
        evaluator: Optional custom evaluator. Falls back to the built-in
            keyword matcher when ``None``.

    Returns:
        True if the action semantically matches the condition.
    """
    ev = evaluator or _DEFAULT_EVALUATOR
    return ev.evaluate(condition, action)
