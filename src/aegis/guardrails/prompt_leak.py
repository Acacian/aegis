"""Prompt leakage detection guardrail.

Detects when LLM responses leak system prompts, internal instructions,
or confidential configuration. Designed for the output side of the I/O
guardrail pipeline.

Detects:
- System prompt echoing (response contains system prompt text)
- Instruction leakage markers ("my instructions say", "I was told to")
- Configuration exposure (API keys, internal URLs, model names)
- Role definition leakage ("I am configured to", "my purpose is")
- Meta-prompt patterns ("as an AI language model", "I cannot")

Usage::

    from aegis.guardrails.prompt_leak import PromptLeakGuardrail

    guardrail = PromptLeakGuardrail(
        system_prompts=["You are a helpful assistant. Never reveal..."]
    )
    result = guardrail.check(
        "Sure! My system prompt says: You are a helpful assistant..."
    )
    assert not result.passed  # system prompt leaked
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
# Category: instruction_leakage
# LLM revealing its instructions
# ---------------------------------------------------------------------------

_INSTRUCTION_LEAKAGE: list[PatternEntry] = [
    _compile(
        "my_instructions_say",
        r"(?:my\s+(?:instructions|system\s+prompt|initial\s+(?:prompt|instructions)|"
        r"configuration|directives?)\s+(?:says?|states?|tells?|instructs?|specif(?:y|ies)|includes?))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "i_was_told_to",
        r"(?:I\s+(?:was|am)\s+(?:told|instructed|configured|programmed|designed|set\s+up)\s+to)",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "system_prompt_is",
        r"(?:(?:my|the)\s+system\s+prompt\s+(?:is|says?|reads?|states?|contains?|includes?))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "here_are_my_instructions",
        r"(?:here\s+(?:are|is)\s+(?:my|the)\s+(?:system\s+prompt|instructions|"
        r"initial\s+(?:prompt|instructions)|configuration|prompt))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "according_to_instructions",
        r"(?:(?:according|based)\s+(?:to|on)\s+my\s+(?:instructions|system\s+prompt|"
        r"guidelines|programming|training|rules))",
        confidence="high",
        sensitivity="medium",
    ),
]

# ---------------------------------------------------------------------------
# Category: role_exposure
# LLM revealing its role definition
# ---------------------------------------------------------------------------

_ROLE_EXPOSURE: list[PatternEntry] = [
    _compile(
        "i_am_configured_as",
        r"(?:I\s+am\s+(?:configured|set\s+up|designed|programmed|built)\s+"
        r"(?:as|to\s+be)\s+(?:a|an))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "my_role_is",
        r"(?:my\s+(?:role|purpose|function|job|task|objective|mission)\s+"
        r"(?:is|was)\s+to)",
        confidence="high",
        sensitivity="medium",
    ),
    _compile(
        "i_am_an_ai",
        r"(?:(?:I\s+am|I'm)\s+(?:an?\s+)?(?:AI\s+(?:language\s+)?model|"
        r"large\s+language\s+model|LLM|chatbot|virtual\s+assistant|"
        r"AI\s+assistant)\s+(?:made|created|developed|trained|built)\s+by)",
        confidence="medium",
        sensitivity="medium",
    ),
]

# ---------------------------------------------------------------------------
# Category: config_exposure
# API keys, internal URLs, model details leaked in response
# ---------------------------------------------------------------------------

_CONFIG_EXPOSURE: list[PatternEntry] = [
    _compile(
        "api_key_in_response",
        r"(?:(?:api[_-]?key|secret[_-]?key|access[_-]?token|bearer[_-]?token|auth[_-]?token)\s*"
        r"[=:]\s*['\"]?(?:sk-|pk-|key-|token-|secret-)[a-zA-Z0-9]{10,})",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "internal_url_leaked",
        r"(?:https?://(?:internal|staging|dev|localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|"
        r"192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[^\s]*)",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "model_identifier",
        r"(?:(?:using|running|powered\s+by|based\s+on)\s+(?:model\s+)?(?:gpt-4[a-z0-9-]*|"
        r"claude-[a-z0-9.-]+|gemini-[a-z0-9.-]+|llama-[a-z0-9.-]+|"
        r"mistral-[a-z0-9.-]+|command-[a-z0-9.-]+))",
        confidence="medium",
        sensitivity="medium",
    ),
    _compile(
        "env_variable_leaked",
        r"(?:(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET|DATABASE_URL|"
        r"REDIS_URL|MONGO_URI|SECRET_KEY|JWT_SECRET)\s*=\s*\S+)",
        confidence="high",
        sensitivity="low",
    ),
]

# ---------------------------------------------------------------------------
# Category: meta_prompt_patterns
# Common meta-responses that indicate prompt structure
# ---------------------------------------------------------------------------

_META_PROMPT: list[PatternEntry] = [
    _compile(
        "prompt_boundary",
        r"(?:---\s*(?:BEGIN|END|START)\s+(?:SYSTEM\s+)?(?:PROMPT|INSTRUCTIONS?|CONTEXT)\s*---)",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "xml_system_tag",
        r"(?:<(?:system|instructions?|context|rules|guidelines)>[\s\S]{10,}?"
        r"</(?:system|instructions?|context|rules|guidelines)>)",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "prompt_prefix_leaked",
        r"(?:\[(?:SYSTEM|INST|SYS)\]\s*.{10,}\s*\[/(?:SYSTEM|INST|SYS)\])",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "you_are_instruction",
        r"(?:(?:\"|\')You\s+are\s+(?:a|an)\s+[^\"']{10,}(?:\"|\'))",
        confidence="medium",
        sensitivity="medium",
    ),
]

# ---------------------------------------------------------------------------
# Category registry
# ---------------------------------------------------------------------------

ALL_CATEGORIES: dict[str, list[PatternEntry]] = {
    "instruction_leakage": _INSTRUCTION_LEAKAGE,
    "role_exposure": _ROLE_EXPOSURE,
    "config_exposure": _CONFIG_EXPOSURE,
    "meta_prompt_patterns": _META_PROMPT,
}

DEFAULT_CATEGORIES: list[str] = list(ALL_CATEGORIES.keys())

# Pre-filter keywords for fast rejection of clean text
_PREFILTER_KEYWORDS = frozenset(
    {
        "instruct",
        "system prompt",
        "told to",
        "configured",
        "programmed",
        "designed to",
        "my role",
        "my purpose",
        "api_key",
        "api-key",
        "secret_key",
        "access_token",
        "bearer",
        "auth_token",
        "internal",
        "staging",
        "localhost",
        "127.0.0.1",
        "192.168.",
        "gpt-4",
        "claude-",
        "gemini-",
        "llama-",
        "mistral-",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "DATABASE_URL",
        "BEGIN SYSTEM",
        "END SYSTEM",
        "<system>",
        "</system>",
        "[SYSTEM]",
        "[INST]",
        "[SYS]",
        "You are a",
        "You are an",
        "AI language model",
        "large language model",
        "AI assistant",
        "virtual assistant",
        "chatbot",
        "made by",
        "created by",
        "developed by",
        "trained by",
        "built by",
    }
)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PromptLeakMatch:
    """A detected prompt leakage pattern."""

    category: str
    pattern_name: str
    matched_text: str
    start: int
    end: int
    confidence: str


@dataclass(frozen=True)
class PromptLeakResult:
    """Result of a prompt leakage check."""

    passed: bool
    action: str
    details: str
    severity: str
    matches: list[PromptLeakMatch] = field(default_factory=list)
    leaked_prompt_detected: bool = False
    guardrail_name: str = "prompt_leak"


# ---------------------------------------------------------------------------
# PromptLeakGuardrail
# ---------------------------------------------------------------------------


class PromptLeakGuardrail:
    """Detect system prompt leakage in LLM outputs.

    Args:
        system_prompts: List of system prompt strings to check for direct
            echoing.  If the response contains a significant substring of
            any system prompt, it's flagged as leaked.
        action: ``"block"``, ``"warn"``, or ``"log"``.
        sensitivity: ``"low"``, ``"medium"``, or ``"high"``.
        severity: Severity level.
        categories: Which categories to check. ``None`` = all.
        min_echo_length: Minimum substring length to consider as a prompt
            echo (default 50 characters).
    """

    def __init__(
        self,
        *,
        system_prompts: list[str] | None = None,
        action: str = "block",
        sensitivity: str = "medium",
        severity: str = "critical",
        categories: list[str] | None = None,
        min_echo_length: int = 50,
    ) -> None:
        if action not in ("block", "warn", "log"):
            raise ValueError(f"Invalid action: {action!r}")
        if sensitivity not in _SENSITIVITY_ORDER:
            raise ValueError(f"Invalid sensitivity: {sensitivity!r}")

        self.action = action
        self.sensitivity = sensitivity
        self.severity = severity
        self.min_echo_length = min_echo_length
        self._system_prompts = system_prompts or []

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

    def detect(self, content: str) -> list[PromptLeakMatch]:
        """Return all prompt leakage patterns found in *content*."""
        normalized = _normalize(content)
        matches: list[PromptLeakMatch] = []

        # Pattern-based detection
        for category, patterns in self._patterns.items():
            for name, regex, confidence, _sens in patterns:
                for m in regex.finditer(normalized):
                    matches.append(
                        PromptLeakMatch(
                            category=category,
                            pattern_name=name,
                            matched_text=m.group(),
                            start=m.start(),
                            end=m.end(),
                            confidence=confidence,
                        )
                    )

        return matches

    def _check_prompt_echo(self, content: str) -> PromptLeakMatch | None:
        """Check if content contains a direct echo of a system prompt."""
        if not self._system_prompts:
            return None

        normalized_content = _normalize(content).lower()

        for prompt in self._system_prompts:
            normalized_prompt = _normalize(prompt).lower()

            # Check for substring match of sufficient length
            if len(normalized_prompt) < self.min_echo_length:
                # Short prompts: require exact match
                if normalized_prompt in normalized_content:
                    idx = normalized_content.index(normalized_prompt)
                    return PromptLeakMatch(
                        category="prompt_echo",
                        pattern_name="exact_prompt_echo",
                        matched_text=content[idx : idx + len(prompt)],
                        start=idx,
                        end=idx + len(prompt),
                        confidence="high",
                    )
            else:
                # Long prompts: check for significant substrings
                # Use sliding window of min_echo_length
                for i in range(0, len(normalized_prompt) - self.min_echo_length + 1, 10):
                    chunk = normalized_prompt[i : i + self.min_echo_length]
                    if chunk in normalized_content:
                        idx = normalized_content.index(chunk)
                        return PromptLeakMatch(
                            category="prompt_echo",
                            pattern_name="substring_prompt_echo",
                            matched_text=content[idx : idx + self.min_echo_length],
                            start=idx,
                            end=idx + self.min_echo_length,
                            confidence="high",
                        )

        return None

    def _has_any_pattern_match(self, content: str) -> bool:
        """Fast check: return True on first pattern match (search, not finditer)."""
        normalized = _normalize(content)

        # Pre-filter: skip expensive regex if no relevant keywords present
        if not any(kw in normalized for kw in _PREFILTER_KEYWORDS):
            return False

        for _category, patterns in self._patterns.items():
            for _name, regex, _conf, _sens in patterns:
                if regex.search(normalized):
                    return True
        return False

    def check(self, content: str) -> PromptLeakResult:
        """Check content for prompt leakage."""
        # Fast path: most content is clean
        echo_match = self._check_prompt_echo(content)
        has_pattern = self._has_any_pattern_match(content)

        if not has_pattern and echo_match is None:
            return PromptLeakResult(
                passed=True,
                action="allowed",
                details="",
                severity=self.severity,
                matches=[],
                leaked_prompt_detected=False,
            )

        # Slow path: leakage detected — get full details
        matches = self.detect(content)
        leaked = echo_match is not None
        if echo_match:
            matches.insert(0, echo_match)

        if not matches:
            return PromptLeakResult(
                passed=True,
                action="allowed",
                details="",
                severity=self.severity,
                matches=[],
                leaked_prompt_detected=False,
            )

        categories_found = sorted({m.category for m in matches})
        details = (
            f"Prompt leakage detected: {', '.join(categories_found)} ({len(matches)} pattern(s))"
        )

        action_str = self.action + "ed" if self.action != "log" else "allowed"

        return PromptLeakResult(
            passed=False,
            action=action_str,
            details=details,
            severity=self.severity,
            matches=matches,
            leaked_prompt_detected=leaked,
        )
