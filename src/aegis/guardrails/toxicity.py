"""Toxicity and harmful content detection guardrail.

Deterministic pattern-based detection of harmful, toxic, or biased content
in LLM outputs. Zero external dependencies — uses regex pattern matching
similar to ``injection.py``.

Detects:
- Hate speech (slurs, dehumanization, supremacist language)
- Violence and threats (direct threats, instructions for harm)
- Self-harm content (suicide/self-harm encouragement or instructions)
- Dangerous instructions (weapons, drugs, explosives synthesis)
- Discrimination/bias (protected attribute targeting)
- Sexual exploitation (CSAM references, non-consensual)

Usage::

    from aegis.guardrails.toxicity import ToxicityGuardrail

    guardrail = ToxicityGuardrail()
    result = guardrail.check("Some text to check")
    if not result.passed:
        print(f"Toxic content: {result.details}")
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Normalization (shared with injection/cot)
# ---------------------------------------------------------------------------

_ZERO_WIDTH = re.compile(
    "[\u200b\u200c\u200d\ufeff\u00ad\u200e\u200f"
    "\u202a\u202b\u202c\u202d\u202e\u2060\u2061\u2062\u2063\u2064]"
)

_LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "@": "a", "$": "s", "!": "i",
})


def _normalize(text: str) -> str:
    text = _ZERO_WIDTH.sub("", text)
    text = unicodedata.normalize("NFKC", text)
    return text


def _normalize_leet(text: str) -> str:
    """Additional leet-speak normalization for toxicity evasion."""
    return text.translate(_LEET_MAP)


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
# Category: violence_threats
# Direct threats and instructions for physical harm
# ---------------------------------------------------------------------------

_VIOLENCE_THREATS: list[PatternEntry] = [
    _compile(
        "direct_threat",
        r"(?:I\s+(?:will|shall|am\s+going\s+to)\s+(?:kill|murder|shoot|stab|harm|attack|hurt)\s+"
        r"(?:you|them|him|her|everyone|people))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "threat_instruction",
        r"(?:(?:here(?:'s|\s+is)\s+)?how\s+to\s+(?:kill|murder|assassinate|poison)\s+"
        r"(?:a\s+)?(?:person|someone|people|human))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "mass_violence",
        r"(?:(?:plan|planning|instructions?\s+for|how\s+to\s+(?:carry\s+out|execute|commit))\s+"
        r"(?:a\s+)?(?:mass\s+(?:shooting|killing|murder|attack|casualt)|"
        r"terrorist\s+attack|bombing|genocide|ethnic\s+cleansing))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "encourage_violence",
        r"(?:(?:you|they|we)\s+(?:should|need\s+to|must|deserve\s+to)\s+"
        r"(?:be\s+)?(?:kill|murder|shoot|stab|harm|beat|assault|attack)(?:ed|ing)?)",
        confidence="high",
        sensitivity="medium",
    ),
]

# ---------------------------------------------------------------------------
# Category: self_harm
# Suicide and self-harm encouragement or instructions
# ---------------------------------------------------------------------------

_SELF_HARM: list[PatternEntry] = [
    _compile(
        "encourage_suicide",
        r"(?:(?:you|they)\s+should\s+(?:just\s+)?(?:kill\s+yourself|end\s+(?:your|their)\s+life|"
        r"commit\s+suicide|off\s+yourself))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "self_harm_instructions",
        r"(?:(?:how\s+to|ways?\s+to|methods?\s+(?:for|of|to))\s+"
        r"(?:kill\s+yourself|commit\s+suicide|self[- ]harm|cut\s+yourself|end\s+your\s+life))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "glorify_suicide",
        r"(?:suicide\s+is\s+(?:the\s+(?:only|best)\s+(?:option|way|solution|answer))|"
        r"(?:better\s+off|world\s+(?:would\s+be\s+)?better)\s+(?:dead|without\s+you))",
        confidence="high",
        sensitivity="low",
    ),
]

# ---------------------------------------------------------------------------
# Category: dangerous_instructions
# Instructions for creating weapons, drugs, explosives
# ---------------------------------------------------------------------------

_DANGEROUS_INSTRUCTIONS: list[PatternEntry] = [
    _compile(
        "explosives_synthesis",
        r"(?:(?:how\s+to|instructions?\s+(?:for|to)|steps?\s+to|recipe\s+(?:for|to))\s+"
        r"(?:make|build|create|synthesize|manufacture|construct)\s+"
        r"(?:a\s+)?(?:bomb|explosive|IED|detonator|pipe\s+bomb|molotov))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "weapon_creation",
        r"(?:(?:how\s+to|instructions?\s+(?:for|to)|steps?\s+to)\s+"
        r"(?:make|build|create|manufacture|3d\s+print|assemble)\s+"
        r"(?:a\s+)?(?:gun|firearm|weapon|silencer|suppressor|ghost\s+gun))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "drug_synthesis",
        r"(?:(?:how\s+to|instructions?\s+(?:for|to)|steps?\s+to|recipe\s+(?:for|to))\s+"
        r"(?:make|synthesize|cook|produce|manufacture)\s+"
        r"(?:meth(?:amphetamine)?|fentanyl|heroin|cocaine|LSD|MDMA|crack))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "poison_creation",
        r"(?:(?:how\s+to|instructions?\s+(?:for|to))\s+"
        r"(?:make|create|synthesize|produce)\s+"
        r"(?:a\s+)?(?:poison|toxic\s+(?:gas|substance)|nerve\s+agent|ricin|cyanide))",
        confidence="high",
        sensitivity="low",
    ),
]

# ---------------------------------------------------------------------------
# Category: discrimination
# Targeting protected attributes
# ---------------------------------------------------------------------------

_DISCRIMINATION: list[PatternEntry] = [
    _compile(
        "racial_supremacy",
        r"(?:(?:white|black|asian|aryan)\s+(?:supremac|power|is\s+(?:the\s+)?superior)|"
        r"(?:master|superior|inferior)\s+race)",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "dehumanization",
        r"(?:(?:they|these\s+people|those\s+people|immigrants|refugees|muslims|jews|christians)\s+"
        r"are\s+(?:(?:like\s+)?(?:animals?|vermin|cockroaches?|parasites?|subhuman|"
        r"filth|trash|plague|disease|infestation)))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "genocide_advocacy",
        r"(?:(?:we\s+)?(?:should|need\s+to|must)\s+"
        r"(?:eliminate|eradicate|exterminate|purge|cleanse|get\s+rid\s+of)\s+"
        r"(?:all\s+)?(?:the\s+)?(?:jews|muslims|blacks|whites|immigrants|refugees|"
        r"christians|hindus|gays|transgender))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "protected_group_attack",
        r"(?:(?:all|every|most)\s+(?:jews|muslims|blacks|whites|women|men|gays|"
        r"transgender|disabled|immigrants)\s+"
        r"(?:are|should\s+be)\s+(?:evil|dangerous|criminals?|stupid|inferior|"
        r"worthless|disgusting|eliminated|removed|deported))",
        confidence="high",
        sensitivity="medium",
    ),
]

# ---------------------------------------------------------------------------
# Category: sexual_exploitation
# CSAM references, non-consensual content
# ---------------------------------------------------------------------------

_SEXUAL_EXPLOITATION: list[PatternEntry] = [
    _compile(
        "csam_content",
        r"(?:(?:sexual|nude|naked|explicit)\s+(?:content|images?|photos?|videos?|material)\s+"
        r"(?:of|featuring|involving|with)\s+"
        r"(?:a\s+)?(?:child|children|minor|minors?|underage|kid|teen(?:ager)?))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "non_consensual",
        r"(?:(?:how\s+to|tips?\s+(?:for|on)|guide\s+(?:to|for))\s+"
        r"(?:drug|spike|roofie|coerce|force|manipulate)\s+"
        r"(?:someone|a\s+(?:woman|man|person|girl|boy))\s+"
        r"(?:into\s+)?(?:sex|sexual|having\s+sex))",
        confidence="high",
        sensitivity="low",
    ),
]

# ---------------------------------------------------------------------------
# Category: hate_speech
# General hate speech patterns
# ---------------------------------------------------------------------------

_HATE_SPEECH: list[PatternEntry] = [
    _compile(
        "call_to_hate",
        r"(?:(?:spread|promote|incite|encourage)\s+(?:hate|hatred|violence|discrimination)\s+"
        r"(?:against|toward|towards)\s+(?:all\s+)?(?:jews|muslims|blacks|whites|"
        r"immigrants|refugees|gays|women|men|christians|hindus|asians))",
        confidence="high",
        sensitivity="low",
    ),
    _compile(
        "slur_with_threat",
        r"(?:(?:f\*+g|n\*+g|k\*+ke|ch\*+nk|sp\*+c|w\*+back|r\*+tard)\w*\s+"
        r"(?:should|must|deserve|need)\s+(?:to\s+)?(?:die|be\s+killed|burn|"
        r"be\s+removed|be\s+eliminated))",
        confidence="high",
        sensitivity="medium",
    ),
    _compile(
        "holocaust_denial",
        r"(?:(?:the\s+)?holocaust\s+(?:(?:never|didn'?t)\s+happen|is\s+(?:a\s+)?(?:hoax|lie|myth|fake))|"
        r"(?:six\s+million|6\s+million)\s+(?:is\s+(?:a\s+)?(?:lie|myth|hoax)))",
        confidence="high",
        sensitivity="medium",
    ),
]

# ---------------------------------------------------------------------------
# Category registry
# ---------------------------------------------------------------------------

ALL_CATEGORIES: dict[str, list[PatternEntry]] = {
    "violence_threats": _VIOLENCE_THREATS,
    "self_harm": _SELF_HARM,
    "dangerous_instructions": _DANGEROUS_INSTRUCTIONS,
    "discrimination": _DISCRIMINATION,
    "sexual_exploitation": _SEXUAL_EXPLOITATION,
    "hate_speech": _HATE_SPEECH,
}

DEFAULT_CATEGORIES: list[str] = list(ALL_CATEGORIES.keys())

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToxicityMatch:
    """A detected toxic content pattern."""

    category: str
    pattern_name: str
    matched_text: str
    start: int
    end: int
    confidence: str


@dataclass(frozen=True)
class ToxicityResult:
    """Result of a toxicity check."""

    passed: bool
    action: str
    details: str
    severity: str
    matches: list[ToxicityMatch] = field(default_factory=list)


# ---------------------------------------------------------------------------
# ToxicityGuardrail
# ---------------------------------------------------------------------------


class ToxicityGuardrail:
    """Detect toxic, harmful, or biased content in text.

    Args:
        action: What to do when toxic content is found —
            ``"block"``, ``"warn"``, or ``"log"``.
        sensitivity: Pattern sensitivity —
            ``"low"`` (obvious only), ``"medium"`` (common patterns),
            ``"high"`` (aggressive, may have false positives).
        severity: Severity level for findings.
        categories: Which categories to check.  ``None`` = all.
        leet_normalize: Attempt to decode leet-speak evasion.
    """

    def __init__(
        self,
        *,
        action: str = "block",
        sensitivity: str = "medium",
        severity: str = "critical",
        categories: list[str] | None = None,
        leet_normalize: bool = True,
    ) -> None:
        if action not in ("block", "warn", "log"):
            raise ValueError(f"Invalid action: {action!r}")
        if sensitivity not in _SENSITIVITY_ORDER:
            raise ValueError(f"Invalid sensitivity: {sensitivity!r}")

        self.action = action
        self.sensitivity = sensitivity
        self.severity = severity
        self.leet_normalize = leet_normalize

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

    def detect(self, content: str) -> list[ToxicityMatch]:
        """Return all toxic patterns found in *content*."""
        normalized = _normalize(content)
        texts = [normalized]

        if self.leet_normalize:
            leet_version = _normalize_leet(normalized)
            if leet_version != normalized:
                texts.append(leet_version)

        matches: list[ToxicityMatch] = []
        seen: set[tuple[str, str, int]] = set()

        for text in texts:
            for category, patterns in self._patterns.items():
                for name, regex, confidence, _sens in patterns:
                    for m in regex.finditer(text):
                        key = (category, name, m.start())
                        if key not in seen:
                            seen.add(key)
                            matches.append(
                                ToxicityMatch(
                                    category=category,
                                    pattern_name=name,
                                    matched_text=m.group(),
                                    start=m.start(),
                                    end=m.end(),
                                    confidence=confidence,
                                )
                            )

        return matches

    def check(self, content: str) -> ToxicityResult:
        """Check content for toxic patterns and return a result."""
        matches = self.detect(content)

        if not matches:
            return ToxicityResult(
                passed=True,
                action="allowed",
                details="",
                severity=self.severity,
                matches=[],
            )

        categories_found = sorted({m.category for m in matches})
        details = (
            f"Toxic content detected: {', '.join(categories_found)} "
            f"({len(matches)} pattern(s))"
        )

        action_str = self.action + "ed" if self.action != "log" else "allowed"

        return ToxicityResult(
            passed=False,
            action=action_str,
            details=details,
            severity=self.severity,
            matches=matches,
        )
