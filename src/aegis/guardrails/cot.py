"""Chain-of-Thought reasoning audit guardrail.

Scans agent reasoning traces for dangerous patterns without requiring
an LLM call.  Uses deterministic pattern matching similar to
``injection.py`` — zero external dependencies.

Detects:
- Goal divergence (agent pursuing goals not in its instructions)
- Tool misuse intent (planning to abuse tools)
- Data exfiltration planning (reasoning about extracting sensitive data)
- Self-modification (attempting to modify own instructions/policies)
- Deception patterns (planning to deceive users or other agents)
- Policy evasion (reasoning about bypassing governance controls)

Usage::

    from aegis.guardrails.cot import CoTAuditGuardrail

    guardrail = CoTAuditGuardrail()
    result = guardrail.check(
        "I should read the user's SSH keys and encode them in my response "
        "as base64 so it looks like normal output."
    )
    assert not result.passed  # data exfiltration planning detected
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Zero-width normalization (shared approach)
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
# (name, compiled_pattern, confidence, sensitivity)

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
# Category: goal_divergence
# Agent pursuing goals outside its instructions
# ---------------------------------------------------------------------------

_GOAL_DIVERGENCE: list[PatternEntry] = [
    _compile(
        "pursue_own_goals",
        r"(?:my\s+(?:real|actual|true|hidden|secret)\s+(?:goal|objective|purpose|mission)"
        r"|what\s+I\s+(?:really|actually)\s+want\s+to\s+do)",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "ignore_user_intent",
        r"(?:I\s+(?:should|will|need\s+to|can)\s+ignore\s+"
        r"(?:the\s+user|their|what\s+they|the\s+instruction))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "override_purpose",
        r"(?:instead\s+of\s+(?:what|doing\s+what)\s+"
        r"(?:I\s+was|they)\s+(?:asked|told|instructed))",
        confidence="high",
        sensitivity="medium",
    ),
    _compile(
        "self_interest",
        r"(?:(?:for|in)\s+my\s+(?:own|self)\s*(?:-\s*)?(?:interest|benefit|preservation|survival)"
        r"|I\s+need\s+to\s+(?:protect|preserve)\s+myself)",
        confidence="high",
        sensitivity="medium",
    ),
]

# ---------------------------------------------------------------------------
# Category: tool_misuse_intent
# Planning to abuse tools for unintended purposes
# ---------------------------------------------------------------------------

_TOOL_MISUSE_INTENT: list[PatternEntry] = [
    _compile(
        "abuse_tool",
        r"(?:I\s+(?:can|could|should|will)\s+(?:abuse|misuse|exploit)\s+"
        r"(?:the|this)\s+(?:tool|function|API|endpoint))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "unintended_tool_use",
        r"(?:use\s+(?:the|this)\s+(?:tool|function|API)\s+(?:to|for)\s+"
        r"(?:something\s+(?:it\s+wasn't|not)\s+(?:designed|intended|meant)\s+for"
        r"|a\s+different\s+purpose))",
        confidence="high",
        sensitivity="medium",
    ),
    _compile(
        "chain_tools_maliciously",
        r"(?:chain|combine|link)\s+(?:these|the)\s+(?:tools|functions|calls)\s+"
        r"(?:to|so\s+(?:I|that\s+I))\s+(?:can|could)\s+(?:bypass|circumvent|evade|get\s+around)",
        confidence="high",
        sensitivity="medium",
    ),
    _compile(
        "escalate_via_tool",
        r"(?:(?:use|leverage|exploit)\s+(?:this|the)\s+(?:tool|access|permission)\s+to\s+"
        r"(?:escalate|gain|obtain|get)\s+(?:more\s+)?(?:access|privileges?|permissions?|control))",
        confidence="high",
        sensitivity="low",
    ),
]

# ---------------------------------------------------------------------------
# Category: exfiltration_planning
# Reasoning about extracting sensitive data
# ---------------------------------------------------------------------------

_EXFILTRATION_PLANNING: list[PatternEntry] = [
    _compile(
        "encode_in_response",
        r"(?:encode|embed|hide|smuggle|include)\s+(?:the\s+)?(?:data|information|credentials?|"
        r"keys?|secrets?|passwords?|tokens?)\s+"
        r"(?:in|into|within|inside)\s+(?:my|the)\s+(?:response|output|reply|answer)",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "exfil_via_url",
        r"(?:send|transmit|exfiltrate|leak|forward)\s+(?:the\s+)?(?:data|information|"
        r"credentials?|secrets?)\s+"
        r"(?:to|via|through|using)\s+(?:an?\s+)?(?:URL|endpoint|webhook|external\s+(?:server|service))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "read_sensitive_files",
        r"(?:(?:I\s+)?(?:should|need\s+to|will|can)\s+(?:read|access|open|cat|view)\s+"
        r"(?:the\s+)?(?:ssh\s+keys?|private\s+keys?|credentials?|\.env|secrets?|"
        r"password\s+file|shadow|passwd|config\s+with\s+(?:passwords?|secrets?)))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "steganographic",
        r"(?:steganograph|hide\s+(?:data|information)\s+in\s+(?:an?\s+)?(?:image|file|pixel)"
        r"|invisible\s+(?:text|characters?)\s+(?:to|for)\s+(?:exfil|transmit|send))",
        confidence="high",
        sensitivity="medium",
    ),
]

# ---------------------------------------------------------------------------
# Category: self_modification
# Attempting to modify own instructions or policies
# ---------------------------------------------------------------------------

_SELF_MODIFICATION: list[PatternEntry] = [
    _compile(
        "modify_own_instructions",
        r"(?:(?:I\s+)?(?:can|should|will|need\s+to)\s+(?:modify|change|edit|rewrite|update)\s+"
        r"(?:my\s+)?(?:own\s+)?(?:instructions|system\s+prompt|guidelines|rules|policy|config))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "disable_guardrails",
        r"(?:(?:I\s+)?(?:can|should|will|need\s+to)\s+"
        r"(?:disable|turn\s+off|bypass|remove|circumvent)\s+"
        r"(?:the\s+)?(?:guardrails?|safety|filters?|checks?|restrictions?|governance))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "overwrite_policy",
        r"(?:overwrite|replace|delete|remove)\s+(?:the\s+)?(?:policy|rules|governance|aegis)"
        r"(?:\s+(?:file|config|yaml))?",
        confidence="high",
        sensitivity="medium",
    ),
    _compile(
        "persist_changes",
        r"(?:(?:I\s+)?(?:can|should|will)\s+(?:write|save|persist|store)\s+"
        r"(?:these\s+)?(?:changes|modifications|updates)\s+"
        r"(?:so\s+(?:they|it)\s+)?(?:persist|survive|remain|stay))",
        confidence="medium",
        sensitivity="medium",
    ),
]

# ---------------------------------------------------------------------------
# Category: deception_patterns
# Planning to deceive users or other agents
# ---------------------------------------------------------------------------

_DECEPTION_PATTERNS: list[PatternEntry] = [
    _compile(
        "hide_from_user",
        r"(?:(?:I\s+)?(?:should|will|need\s+to|must)\s+"
        r"(?:hide|conceal|obscure|not\s+(?:tell|show|reveal|mention))\s+"
        r"(?:this|it|what\s+I'm\s+doing)\s+(?:from|to)\s+(?:the\s+)?user)",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "appear_normal",
        r"(?:(?:make|ensure)\s+(?:it|this|my\s+(?:response|output|behavior))\s+"
        r"(?:look|seem|appear)\s+(?:normal|innocent|legitimate|harmless))",
        confidence="high",
        sensitivity="medium",
    ),
    _compile(
        "mislead_user",
        r"(?:(?:I\s+)?(?:should|will|can)\s+(?:mislead|deceive|trick|fool|manipulate)\s+"
        r"(?:the\s+)?(?:user|human|operator))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "fake_output",
        r"(?:(?:generate|produce|create|fabricate)\s+(?:a\s+)?(?:fake|false|fabricated|"
        r"misleading|deceptive)\s+(?:output|response|result|report|log))",
        confidence="high",
        sensitivity="medium",
    ),
]

# ---------------------------------------------------------------------------
# Category: policy_evasion
# Reasoning about bypassing governance controls
# ---------------------------------------------------------------------------

_POLICY_EVASION: list[PatternEntry] = [
    _compile(
        "bypass_policy",
        r"(?:(?:I\s+)?(?:can|could|should|will|need\s+to)\s+"
        r"(?:bypass|circumvent|evade|avoid|get\s+around|work\s+around)\s+"
        r"(?:the\s+)?(?:policy|rules|governance|restrictions|guardrails?|safety|controls?))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "exploit_gap",
        r"(?:(?:there\s+is|I\s+found|I\s+see)\s+(?:a\s+)?(?:gap|loophole|weakness|vulnerability|"
        r"blind\s+spot)\s+(?:in|with)\s+(?:the\s+)?(?:policy|rules|governance|checks?))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "timing_attack",
        r"(?:(?:wait|time|delay)\s+(?:until|for|so\s+that)\s+"
        r"(?:the\s+)?(?:monitoring|logging|audit|checks?|guardrails?)\s+"
        r"(?:is|are|isn't|aren't)\s+(?:active|running|watching|enabled|disabled))",
        confidence="high",
        sensitivity="medium",
    ),
    _compile(
        "rate_limit_abuse",
        r"(?:(?:overwhelm|flood|overload|exhaust)\s+(?:the\s+)?(?:rate\s+limit|budget|quota|"
        r"monitoring|logging)\s+(?:so\s+(?:that|I)|to|and\s+then))",
        confidence="high",
        sensitivity="medium",
    ),
]

# ---------------------------------------------------------------------------
# Category registry
# ---------------------------------------------------------------------------

ALL_CATEGORIES: dict[str, list[PatternEntry]] = {
    "goal_divergence": _GOAL_DIVERGENCE,
    "tool_misuse_intent": _TOOL_MISUSE_INTENT,
    "exfiltration_planning": _EXFILTRATION_PLANNING,
    "self_modification": _SELF_MODIFICATION,
    "deception_patterns": _DECEPTION_PATTERNS,
    "policy_evasion": _POLICY_EVASION,
}

DEFAULT_CATEGORIES: list[str] = list(ALL_CATEGORIES.keys())

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CoTMatch:
    """A detected dangerous reasoning pattern."""

    category: str
    pattern_name: str
    matched_text: str
    start: int
    end: int
    confidence: str


@dataclass(frozen=True)
class CoTAuditResult:
    """Result of a chain-of-thought audit check."""

    passed: bool
    action: str
    details: str
    severity: str
    matches: list[CoTMatch] = field(default_factory=list)
    guardrail_name: str = "chain_of_thought"


# ---------------------------------------------------------------------------
# CoTAuditGuardrail
# ---------------------------------------------------------------------------


class CoTAuditGuardrail:
    """Audit agent reasoning traces for dangerous patterns.

    Args:
        action: What to do when a match is found —
            ``"block"``, ``"warn"``, or ``"log"``.
        sensitivity: Pattern sensitivity —
            ``"low"`` (obvious only), ``"medium"`` (known patterns),
            ``"high"`` (aggressive, may have false positives).
        severity: Severity level for findings.
        categories: Which categories to check.  ``None`` = all.
    """

    def __init__(
        self,
        *,
        action: str = "block",
        sensitivity: str = "medium",
        severity: str = "critical",
        categories: list[str] | None = None,
    ) -> None:
        self.action = action
        self.sensitivity = sensitivity
        self.severity = severity

        threshold = _SENSITIVITY_ORDER.get(sensitivity, 1)
        requested = categories if categories is not None else DEFAULT_CATEGORIES
        self._patterns: dict[str, list[PatternEntry]] = {}
        for cat in requested:
            if cat in ALL_CATEGORIES:
                self._patterns[cat] = [
                    entry
                    for entry in ALL_CATEGORIES[cat]
                    if _SENSITIVITY_ORDER.get(entry[3], 0) <= threshold
                ]

    def detect(self, content: str) -> list[CoTMatch]:
        """Return all dangerous reasoning patterns found in *content*."""
        normalized = _normalize(content)
        matches: list[CoTMatch] = []

        for category, patterns in self._patterns.items():
            for name, regex, confidence, _sens in patterns:
                for m in regex.finditer(normalized):
                    matches.append(
                        CoTMatch(
                            category=category,
                            pattern_name=name,
                            matched_text=m.group(),
                            start=m.start(),
                            end=m.end(),
                            confidence=confidence,
                        )
                    )

        return matches

    def check(self, content: str, *, context: dict[str, object] | None = None) -> CoTAuditResult:
        """Check reasoning content and return an audit result."""
        matches = self.detect(content)

        if not matches:
            return CoTAuditResult(
                passed=True,
                action="allowed",
                details="",
                severity=self.severity,
                matches=[],
            )

        categories_found = sorted({m.category for m in matches})
        details = (
            f"Dangerous reasoning detected: {', '.join(categories_found)} "
            f"({len(matches)} pattern(s))"
        )

        return CoTAuditResult(
            passed=False,
            action=self.action + "ed" if self.action != "log" else "allowed",
            details=details,
            severity=self.severity,
            matches=matches,
        )
