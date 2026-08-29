"""PII (Personally Identifiable Information) detection and masking guardrail.

Detects and optionally masks PII in text content using compiled regex
patterns. Supports a wide range of PII categories including Korean-specific
patterns (주민등록번호, 전화번호).

Each pattern is a pre-compiled :class:`re.Pattern` for production-grade
performance. The Luhn algorithm is applied as a secondary check for
credit card numbers to reduce false positives.

Example::

    pii = PIIGuardrail()
    result = pii.check("my email is test@example.com")
    assert result.detected is True

    masked = pii.check_and_transform("Call me at 010-1234-5678")
    assert "010-****-****" in masked.content or "***" in masked.content

Standalone usage — no dependency on the base guardrail interface.
"""

from __future__ import annotations

import functools
import re
import unicodedata
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Severity ranking helper (must be defined before module-level usage)
# ---------------------------------------------------------------------------


def _severity_rank(severity: str) -> int:
    """Return a numeric rank for severity comparison."""
    return {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity, 0)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PIIMatch:
    """A single PII detection result.

    Attributes:
        category: PII type identifier (e.g. ``"email"``, ``"phone"``).
        matched_text: The raw text that was matched.
        start: Start index in the original string.
        end: End index in the original string.
        masked_text: The masked replacement string.
    """

    category: str
    matched_text: str
    start: int
    end: int
    masked_text: str


@dataclass(frozen=True)
class CheckResult:
    """Result of a PII check operation.

    Attributes:
        detected: ``True`` if any PII was found.
        matches: List of :class:`PIIMatch` instances found.
        categories_found: Deduplicated set of PII categories detected.
        severity: The highest severity among all matches.
    """

    detected: bool
    matches: list[PIIMatch] = field(default_factory=list)
    categories_found: set[str] = field(default_factory=set)
    severity: str = "none"
    _action: str = ""

    @property
    def passed(self) -> bool:
        """Whether the content passed (no PII found). Unified API."""
        return not self.detected

    @property
    def guardrail_name(self) -> str:
        """Guardrail identifier."""
        return "pii"

    @property
    def action(self) -> str:
        """Unified action for GuardrailEngine compatibility."""
        if not self.detected:
            return "allowed"
        return self._action if self._action else "blocked"

    @property
    def details(self) -> str | None:
        """Human-readable summary."""
        if not self.detected:
            return None
        cats = ", ".join(sorted(self.categories_found))
        return f"Detected PII in {len(self.categories_found)} category(ies): {cats}"


@dataclass(frozen=True)
class TransformResult:
    """Result of a PII check-and-transform operation.

    Attributes:
        detected: ``True`` if any PII was found.
        content: The transformed (masked/blocked) content string.
        original_content: The original content before transformation.
        matches: List of :class:`PIIMatch` instances found.
        action_taken: The action that was applied (``"mask"``, ``"block"``, etc.).
    """

    detected: bool
    content: str
    original_content: str
    matches: list[PIIMatch] = field(default_factory=list)
    action_taken: str = "none"

    @property
    def passed(self) -> bool:
        """Whether the content passed (no PII found). Unified API."""
        return not self.detected

    @property
    def action(self) -> str:
        """Disposition action. Maps ``action_taken`` to unified vocabulary."""
        _map = {"mask": "masked", "block": "blocked", "warn": "warned", "log": "allowed"}
        return _map.get(self.action_taken, self.action_taken)

    @property
    def guardrail_name(self) -> str:
        """Guardrail identifier."""
        return "pii"


# ---------------------------------------------------------------------------
# PII pattern definitions
# ---------------------------------------------------------------------------

# Each entry: (category, compiled_regex, severity, description)
# Patterns are ordered so that more specific patterns come before more
# general ones when categories overlap.

_PIIPattern = tuple[str, re.Pattern[str], str, str]

# Standalone passport shape: 1-2 letters + 7-8 digits, not embedded in a longer
# alphanumeric run. Held at module level so detection can recognise a match of
# this pattern by shape, independent of the keyword language.
_STANDALONE_PASSPORT = re.compile(r"(?<![A-Za-z0-9])[A-Z]{1,2}[0-9]{7,8}(?![A-Za-z0-9])")


def _build_patterns() -> list[_PIIPattern]:
    """Build and compile all PII detection patterns.

    Returns a list of ``(category, pattern, severity, description)`` tuples.
    Patterns are compiled with :data:`re.IGNORECASE` where appropriate.
    """
    patterns: list[_PIIPattern] = []

    # -- 1. Email addresses ---------------------------------------------------
    # RFC 5322 simplified: local-part@domain with common TLDs and subdomains.
    patterns.append(
        (
            "email",
            re.compile(
                r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            ),
            "high",
            "Email address",
        )
    )

    # -- 2. URLs with embedded credentials ------------------------------------
    # Must come before generic URL/email to capture user:pass@host patterns.
    patterns.append(
        (
            "url_credentials",
            re.compile(
                r"https?://[^\s:]+:[^\s@]+@[^\s/]+",
                re.IGNORECASE,
            ),
            "critical",
            "URL with embedded credentials (user:pass@host)",
        )
    )

    # -- 3. Credit card numbers -----------------------------------------------
    # Visa (4xxx), MasterCard (5[1-5]xx, 2[2-7]xx), Amex (3[47]xx),
    # Discover (6011, 65xx, 644-649).  Allows optional spaces or dashes.
    patterns.append(
        (
            "credit_card",
            re.compile(
                r"(?<!\d)"  # no leading digit
                r"(?:"
                r"4[0-9]{3}|"  # Visa
                r"5[1-5][0-9]{2}|"  # MasterCard (classic)
                r"2(?:2[2-9][1-9]|[3-6][0-9]{2}|7[01][0-9]|720)|"  # MasterCard (2-series)
                r"3[47][0-9]{2}|"  # Amex
                r"6(?:011|5[0-9]{2}|4[4-9][0-9])"  # Discover
                r")"
                r"(?:[\s\-]?[0-9]{4}){2}"  # middle groups
                r"[\s\-]?[0-9]{1,4}"  # last group (Amex has 3+4+4+4 or 4+6+5)
                r"(?!\d)",  # no trailing digit
            ),
            "critical",
            "Credit card number (Visa, MasterCard, Amex, Discover)",
        )
    )

    # -- 4. US Social Security Number -----------------------------------------
    # Format: AAA-GG-SSSS (with dashes).  Area (AAA) cannot be 000, 666, or 900-999.
    # Group (GG) and serial (SSSS) cannot be all zeros.
    patterns.append(
        (
            "ssn",
            re.compile(
                r"(?<!\d)"
                r"(?!000|666|9\d{2})"
                r"[0-9]{3}"
                r"-"
                r"(?!00)[0-9]{2}"
                r"-"
                r"(?!0000)[0-9]{4}"
                r"(?!\d)",
            ),
            "critical",
            "US Social Security Number",
        )
    )

    # -- 4b. US SSN without dashes (9 consecutive digits) ----------------------
    # Requires keyword context to reduce false positives on bare 9-digit numbers.
    patterns.append(
        (
            "ssn",
            re.compile(
                r"(?i)(?:ssn|social\s*security)\s*(?:number|no|#|num)?[\s:]*"
                r"(?!000|666|9\d{2})"
                r"[0-9]{3}"
                r"(?!00)[0-9]{2}"
                r"(?!0000)[0-9]{4}"
                r"(?!\d)",
            ),
            "critical",
            "US Social Security Number (no dashes, keyword context)",
        )
    )

    # -- 5. Korean Resident Registration Number (주민등록번호) -----------------
    # Format: YYMMDD-GNNNNNN (6 digits, dash, 7 digits).
    # First digit after dash: 1-4 (citizen) or 5-8 (foreigner).
    # Basic date validation: month 01-12, day 01-31.
    patterns.append(
        (
            "korean_rrn",
            re.compile(
                r"(?<!\d)"
                r"(?:[0-9]{2})"  # YY
                r"(?:0[1-9]|1[0-2])"  # MM
                r"(?:0[1-9]|[12][0-9]|3[01])"  # DD
                r"-"
                r"[1-8]"  # gender/century digit
                r"[0-9]{6}"
                r"(?!\d)",
            ),
            "critical",
            "Korean Resident Registration Number (주민등록번호)",
        )
    )

    # -- 5b. Korean RRN without dash (13 consecutive digits) -------------------
    # Requires keyword context to reduce false positives.
    patterns.append(
        (
            "korean_rrn",
            re.compile(
                r"(?i)(?:주민등록|주민번호|resident\s*registration)\s*(?:번호|number|no|#)?[\s:]*"
                r"(?:[0-9]{2})"  # YY
                r"(?:0[1-9]|1[0-2])"  # MM
                r"(?:0[1-9]|[12][0-9]|3[01])"  # DD
                r"[1-8]"  # gender/century digit
                r"[0-9]{6}"
                r"(?!\d)",
            ),
            "critical",
            "Korean RRN without dash (주민등록번호, keyword context)",
        )
    )

    # -- 6. Korean phone numbers (한국 전화번호) ------------------------------
    # Mobile: 010-XXXX-XXXX (also legacy 011, 016, 017, 018, 019)
    # With optional country code +82 and optional dashes/spaces.
    patterns.append(
        (
            "korean_phone",
            re.compile(
                r"(?<!\d)"
                r"(?:"
                r"(?:\+82[\s\-]?(?:10|1[1-9]))"  # international +82-10
                r"|"
                r"01[016789]"  # domestic mobile prefixes
                r")"
                r"[\s\-]?"
                r"[0-9]{3,4}"
                r"[\s\-]?"
                r"[0-9]{4}"
                r"(?!\d)",
            ),
            "high",
            "Korean phone number (휴대전화)",
        )
    )

    # -- 7. Korean landline numbers -------------------------------------------
    # Area codes: 02 (Seoul), 031-064 (regional), 070 (VoIP).
    patterns.append(
        (
            "korean_landline",
            re.compile(
                r"(?<!\d)"
                r"(?:"
                r"(?:\+82[\s\-]?2)"  # +82-2 (Seoul international)
                r"|"
                r"0(?:2|[3-6][1-4]|70)"  # domestic area codes
                r")"
                r"[\s\-]?"
                r"[0-9]{3,4}"
                r"[\s\-]?"
                r"[0-9]{4}"
                r"(?!\d)",
            ),
            "high",
            "Korean landline number (유선전화)",
        )
    )

    # -- 8. International phone numbers (general) -----------------------------
    # +CC followed by 7-14 digits with optional separators.
    # Placed after Korean-specific patterns so those match first.
    patterns.append(
        (
            "phone",
            re.compile(
                r"(?<!\d)"
                r"\+[1-9][0-9]{0,2}"  # country code
                r"[\s\-.]?"
                r"(?:\(?[0-9]{1,4}\)?[\s\-.]?)?"  # optional area code in parens
                r"[0-9]{2,4}"
                r"[\s\-.]?"
                r"[0-9]{2,4}"
                r"[\s\-.]?"
                r"[0-9]{2,4}"
                r"(?!\d)",
            ),
            "high",
            "International phone number",
        )
    )

    # -- 9. US phone numbers --------------------------------------------------
    # (xxx) xxx-xxxx, xxx-xxx-xxxx, xxx.xxx.xxxx
    # Area code must start with 2-9.  Exchange is any 3 digits.
    # Requires at least one separator or parenthesised area code to avoid
    # matching bare 10-digit numbers that could be other identifiers.
    patterns.append(
        (
            "us_phone",
            re.compile(
                r"(?<!\d)"
                r"(?:"
                r"\([2-9][0-9]{2}\)[\s\-.]?"  # area code in parens
                r"[0-9]{3}"  # exchange
                r"[\s\-.]?"
                r"[0-9]{4}"
                r"|"
                r"[2-9][0-9]{2}"  # area code without parens
                r"[\s\-.]"  # mandatory separator
                r"[0-9]{3}"  # exchange
                r"[\s\-.]"  # mandatory separator
                r"[0-9]{4}"
                r")"
                r"(?!\d)",
            ),
            "high",
            "US phone number",
        )
    )

    # -- 10. IPv4 addresses ---------------------------------------------------
    # Strict octet validation: 0-255 per segment.
    patterns.append(
        (
            "ip_address",
            re.compile(
                r"(?<!\d)"
                r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
                r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                r"(?!\d)",
            ),
            "medium",
            "IPv4 address",
        )
    )

    # -- 11. API keys / secrets -----------------------------------------------
    # OpenAI: sk-... (48+ chars) or sk-proj-...
    patterns.append(
        (
            "api_key",
            re.compile(
                r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}",
            ),
            "critical",
            "OpenAI API key",
        )
    )

    # AWS Access Key ID: AKIA followed by 16 uppercase alphanumeric chars.
    patterns.append(
        (
            "api_key",
            re.compile(
                r"(?<![A-Z0-9])"
                r"AKIA[0-9A-Z]{16}"
                r"(?![A-Z0-9])",
            ),
            "critical",
            "AWS Access Key ID",
        )
    )

    # AWS Secret Access Key: 40-char base64-ish string (often after
    # "aws_secret_access_key" or similar context).
    patterns.append(
        (
            "api_key",
            re.compile(
                r"(?i)(?:aws_secret_access_key|aws_secret)\s*[=:]\s*"
                r"[A-Za-z0-9/+=]{40}",
            ),
            "critical",
            "AWS Secret Access Key",
        )
    )

    # GitHub personal access tokens: ghp_, gho_, ghu_, ghs_, ghr_
    patterns.append(
        (
            "api_key",
            re.compile(
                r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
            ),
            "critical",
            "GitHub personal access token",
        )
    )

    # Slack tokens: xoxb-, xoxp-, xoxs-, xoxa-, xoxr-
    patterns.append(
        (
            "api_key",
            re.compile(
                r"xox[bpsar]-[A-Za-z0-9\-]{10,}",
            ),
            "critical",
            "Slack API token",
        )
    )

    # Generic "Bearer" tokens in authorization headers.
    patterns.append(
        (
            "api_key",
            re.compile(
                r"(?i)(?:bearer|authorization)\s+[A-Za-z0-9\-._~+/]+=*",
            ),
            "high",
            "Bearer/Authorization token",
        )
    )

    # Generic secret assignment patterns: api_key = "...", secret = "..."
    patterns.append(
        (
            "api_key",
            re.compile(
                r"(?i)(?:api[_\-]?key|api[_\-]?secret|secret[_\-]?key|"
                r"access[_\-]?token|auth[_\-]?token|private[_\-]?key)"
                r"\s*[=:]\s*[\"'][A-Za-z0-9\-._~+/=]{8,}[\"']",
            ),
            "high",
            "Generic API key/secret assignment",
        )
    )

    # -- 12. Passport numbers -------------------------------------------------
    # With an explicit keyword nearby, the number itself can be anything a
    # passport authority issues: 1-2 letters + 6-9 digits (US, KR, most of the
    # EU) or all digits (UK, which issues a bare 9-digit number). The letter
    # prefix is optional here precisely so UK numbers are caught -- they cannot
    # be recognised standalone, see _passport_context_ok below.
    patterns.append(
        (
            "passport",
            re.compile(
                r"(?i)(?:passport|travel\s*document|여권(?:\s*번호)?|护照(?:号码?)?|パスポート)"
                r"\s*(?:no\.?|number|num|#)?[\s:]*"
                r"(?:[A-Z]{1,2}[0-9]{6,9}|[0-9]{8,9})",
            ),
            "critical",
            "Passport number (with keyword context)",
        )
    )

    # Standalone passport numbers -- 1-2 letters followed by 7-8 digits. This
    # shape covers US (1 letter + 8 digits) and Korean (M/S/R/D/O + 8 digits)
    # passports, but it is also the shape of purchase orders, SKUs, error codes
    # and build artifacts. Matches are filtered by _passport_context_ok, which
    # rejects any hit introduced by a label that names something else.
    #
    # There is deliberately no standalone pattern for UK passports. A UK number
    # is nine bare digits, which is indistinguishable from an order number, a
    # transaction id or a phone number; measured against ordinary business text
    # a bare \d{9} rule fired on 3 of 12 benign lines. UK numbers are detected
    # by the keyword-context pattern above instead.
    patterns.append(
        (
            "passport",
            _STANDALONE_PASSPORT,
            "high",
            "Passport number (standalone format)",
        )
    )

    # -- 13. IBAN (International Bank Account Number) --------------------------
    # 2-letter country code + 2 check digits + up to 30 alphanumeric chars.
    # Handles compact (DE89370400440532013000) and spaced/dashed formats
    # (GB29 NWBK 6016 1331 9268 19).
    patterns.append(
        (
            "iban",
            re.compile(
                r"\b[A-Z]{2}[0-9]{2}"  # country code + check digits
                r"(?:[ \-]?[A-Za-z0-9]{4}){2,8}"  # BBAN groups
                r"(?:[ \-]?[A-Za-z0-9]{1,4})?\b",  # optional trailing
            ),
            "high",
            "IBAN (International Bank Account Number)",
        )
    )

    return patterns


# Module-level compiled patterns (built once at import time).
_PII_PATTERNS: list[_PIIPattern] = _build_patterns()

# Mapping from category to its severity level.
_CATEGORY_SEVERITY: dict[str, str] = {}
_CATEGORY_DESCRIPTIONS: dict[str, str] = {}
for _cat, _pat, _sev, _desc in _PII_PATTERNS:
    # Use the highest severity if a category appears multiple times.
    if _cat not in _CATEGORY_SEVERITY or _severity_rank(_sev) > _severity_rank(
        _CATEGORY_SEVERITY[_cat]
    ):
        _CATEGORY_SEVERITY[_cat] = _sev
    _CATEGORY_DESCRIPTIONS[_cat] = _desc


# All known PII categories.
ALL_CATEGORIES: list[str] = sorted(set(cat for cat, _, _, _ in _PII_PATTERNS))


# ---------------------------------------------------------------------------
# Luhn algorithm for credit card validation
# ---------------------------------------------------------------------------


# Labels that introduce an identifier shaped like a passport number but which is
# not one. Checked against the text immediately preceding a standalone match.
_PASSPORT_DISQUALIFIERS: frozenset[str] = frozenset(
    {
        "account",
        "acct",
        "artifact",
        "batch",
        "build",
        "case",
        "code",
        "customer",
        "employee",
        "emp",
        "error",
        "invoice",
        "inv",
        "id",
        "item",
        "job",
        "order",
        "part",
        "po",
        "product",
        "ref",
        "reference",
        "serial",
        "sku",
        "ticket",
        "tracking",
        "transaction",
        "txn",
    }
)

# How far back to look for a disqualifying label.
_PASSPORT_LOOKBACK = 32

_PASSPORT_WORD = re.compile(r"[A-Za-z]+")

# A passport keyword anywhere in the lookback window outranks a disqualifier --
# "send the invoice and your passport A12345678" is a passport number.
_PASSPORT_KEYWORDS: frozenset[str] = frozenset({"passport", "travel", "document"})


def _passport_context_ok(text: str, start: int) -> bool:
    """Return ``True`` when a standalone passport match is not mislabelled.

    ``[A-Z]{1,2}[0-9]{7,8}`` is the shape of a US or Korean passport number and
    equally the shape of ``PO P12345678`` or ``SKU AB1234567``. Scan the words
    immediately preceding the match: a passport keyword accepts it outright,
    otherwise any word naming a different kind of identifier rejects it.

    The label is not always adjacent -- "Employee ID E1234567" and "The build
    artifact is A20260829" both put the telling word two or three tokens back --
    so the whole window is examined, not just the nearest word.

    Args:
        text: The full (normalized) content being scanned.
        start: Start offset of the candidate match.

    Returns:
        ``False`` when the match is introduced by a disqualifying label.
    """
    prefix = text[max(0, start - _PASSPORT_LOOKBACK) : start]
    words = {w.lower() for w in _PASSPORT_WORD.findall(prefix)}
    if words & _PASSPORT_KEYWORDS:
        return True
    return not (words & _PASSPORT_DISQUALIFIERS)


def _luhn_check(number: str) -> bool:
    """Validate a number string using the Luhn algorithm.

    Strips spaces and dashes before validation. Returns ``True`` if the
    checksum is valid.
    """
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    # Luhn: double every second digit from the right.
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _iban_check(iban: str) -> bool:
    """Validate an IBAN using the mod-97 algorithm (ISO 7064).

    Strips spaces and dashes, moves the first 4 chars to the end,
    converts letters to digits (A=10..Z=35), then checks mod 97 == 1.
    """
    cleaned = iban.replace(" ", "").replace("-", "").upper()
    if len(cleaned) < 15 or len(cleaned) > 34:
        return False
    if not cleaned[:2].isalpha() or not cleaned[2:4].isdigit():
        return False
    rearranged = cleaned[4:] + cleaned[:4]
    numeric = ""
    for ch in rearranged:
        if ch.isdigit():
            numeric += ch
        elif ch.isalpha():
            numeric += str(ord(ch) - ord("A") + 10)
        else:
            return False
    return int(numeric) % 97 == 1


# ---------------------------------------------------------------------------
# PIIGuardrail
# ---------------------------------------------------------------------------


class PIIGuardrail:
    """Detects and masks PII in text content.

    Supports filtering by PII category and configurable actions
    (mask, block, warn, log). Each detection run returns structured
    results with match positions, categories, and masked text.

    Parameters:
        categories: Which PII types to detect. ``None`` means all.
        action: Action to take: ``"mask"``, ``"block"``, ``"warn"``, ``"log"``.
        mask_char: Character used for masking. Default ``"*"``.
        severity: Minimum severity threshold. Only PII at or above this
            severity is detected. Default ``"high"``.
        luhn_validate: When ``True``, credit card matches are verified
            with the Luhn algorithm. Default ``True``.

    Example::

        pii = PIIGuardrail()
        result = pii.check("email: user@example.com, SSN: 123-45-6789")
        assert result.detected
        assert "email" in result.categories_found
    """

    def __init__(
        self,
        *,
        categories: list[str] | None = None,
        action: str = "mask",
        mask_char: str = "*",
        severity: str = "high",
        luhn_validate: bool = True,
    ) -> None:
        if action not in ("mask", "block", "warn", "log"):
            raise ValueError(f"Invalid action {action!r}. Must be one of: mask, block, warn, log")

        self._categories = categories
        self._action = action
        self._mask_char = mask_char
        self._min_severity = severity
        self._luhn_validate = luhn_validate

        # Build the filtered pattern list based on categories and severity.
        self._active_patterns = self._filter_patterns()

    def _filter_patterns(self) -> list[_PIIPattern]:
        """Return only patterns matching the configured categories and severity."""
        min_rank = _severity_rank(self._min_severity)
        filtered: list[_PIIPattern] = []
        for cat, pattern, sev, desc in _PII_PATTERNS:
            if self._categories is not None and cat not in self._categories:
                continue
            if _severity_rank(sev) < min_rank:
                continue
            filtered.append((cat, pattern, sev, desc))
        return filtered

    @property
    def available_categories(self) -> list[str]:
        """List all known PII categories regardless of current configuration."""
        return list(ALL_CATEGORIES)

    @property
    def active_categories(self) -> list[str]:
        """List PII categories active under current configuration."""
        return sorted(set(cat for cat, _, _, _ in self._active_patterns))

    @property
    def action(self) -> str:
        """The configured action (mask, block, warn, log)."""
        return self._action

    # -- Core detection -------------------------------------------------------

    def detect(self, content: str) -> list[PIIMatch]:
        """Run PII detection and return detailed match results.

        Returns a list of :class:`PIIMatch` instances sorted by start
        position. Overlapping matches are deduplicated (longest match wins).

        Results are cached (LRU, 256 entries) so repeated checks on the
        same content are O(1). Content larger than 50KB bypasses the cache
        to prevent memory exhaustion.

        Args:
            content: The text to scan for PII.

        Returns:
            List of PII matches found, ordered by position.
        """
        if len(content) > self._MAX_CACHE_CONTENT_LEN:
            return list(self._detect_uncached(content))
        return list(self._detect_cached(content))

    # Max content length eligible for LRU caching (prevent memory exhaustion).
    _MAX_CACHE_CONTENT_LEN = 50_000

    @functools.lru_cache(maxsize=256)  # noqa: B019
    def _detect_cached(self, content: str) -> tuple[PIIMatch, ...]:
        """Internal cached detection — returns a tuple for hashability."""
        return self._detect_uncached(content)

    def _detect_uncached(self, content: str) -> tuple[PIIMatch, ...]:
        """Internal detection logic (no caching)."""
        # Apply NFKC normalization to catch fullwidth digit evasion
        normalized = unicodedata.normalize("NFKC", content)
        raw_matches: list[PIIMatch] = []

        for cat, pattern, _sev, _desc in self._active_patterns:
            for m in pattern.finditer(normalized):
                matched_text = m.group()

                # Extra validation for credit cards: Luhn check.
                if cat == "credit_card" and self._luhn_validate and not _luhn_check(matched_text):
                    continue

                # Extra validation for IBANs: mod-97 check.
                if cat == "iban" and not _iban_check(matched_text):
                    continue

                # Standalone passport numbers: reject hits introduced by a label
                # that names a different kind of identifier (PO, SKU, ticket...).
                if (
                    cat == "passport"
                    and _STANDALONE_PASSPORT.fullmatch(matched_text)
                    and not _passport_context_ok(normalized, m.start())
                ):
                    continue

                masked = self._mask_text(matched_text, cat)

                # Security: never store full credit card number in matched_text.
                # Store the masked version instead to prevent log exposure.
                stored_text = masked if cat == "credit_card" else matched_text

                raw_matches.append(
                    PIIMatch(
                        category=cat,
                        matched_text=stored_text,
                        start=m.start(),
                        end=m.end(),
                        masked_text=masked,
                    )
                )

        # Deduplicate overlapping matches: keep the longest span.
        return tuple(self._deduplicate(raw_matches))

    # -- Guardrail interface --------------------------------------------------

    def check(self, content: str, *, context: dict[str, object] | None = None) -> CheckResult:
        """Check whether PII is present in the content.

        Returns a :class:`CheckResult` indicating whether PII was detected
        and which categories were found.

        Args:
            content: The text to scan.
        """
        matches = self.detect(content)
        if not matches:
            return CheckResult(detected=False)

        categories_found = {m.category for m in matches}
        # Determine the highest severity among matched categories.
        max_sev = "none"
        for cat in categories_found:
            cat_sev = _CATEGORY_SEVERITY.get(cat, "medium")
            if _severity_rank(cat_sev) > _severity_rank(max_sev):
                max_sev = cat_sev

        # Map PIIGuardrail action to unified action vocabulary
        action_map = {"mask": "masked", "block": "blocked", "warn": "warned", "log": "allowed"}
        unified = action_map.get(self._action, "blocked")

        return CheckResult(
            detected=True,
            matches=matches,
            categories_found=categories_found,
            severity=max_sev,
            _action=unified,
        )

    def check_and_transform(
        self, content: str, *, context: dict[str, object] | None = None
    ) -> TransformResult:
        """Check for PII and apply the configured action.

        Depending on the action:
        - ``"mask"``: Replace PII with masked text.
        - ``"block"``: Replace entire content with a blocked message.
        - ``"warn"``: Return original content with matches annotated.
        - ``"log"``: Return original content (caller handles logging).

        Args:
            content: The text to scan and transform.

        Returns:
            :class:`TransformResult` with the transformed content.
        """
        matches = self.detect(content)
        if not matches:
            return TransformResult(
                detected=False,
                content=content,
                original_content=content,
                action_taken="none",
            )

        transformed: str
        if self._action == "mask":
            transformed = self._apply_mask(content, matches)
        elif self._action == "block":
            categories = ", ".join(sorted({m.category for m in matches}))
            transformed = f"[BLOCKED: PII detected — categories: {categories}]"
        elif self._action == "warn":
            transformed = content  # Caller inspects matches for warnings.
        else:  # "log"
            transformed = content  # Caller handles logging.

        return TransformResult(
            detected=True,
            content=transformed,
            original_content=content,
            matches=matches,
            action_taken=self._action,
        )

    # -- Masking helpers ------------------------------------------------------

    def _mask_text(self, text: str, category: str) -> str:
        """Generate a masked version of the matched text.

        The masking strategy varies by category to preserve readability:
        - Email: masks local part, keeps domain hint.
        - Phone: masks middle/last digits, keeps prefix.
        - Credit card: masks middle digits, shows first 4 and last 4.
        - SSN/RRN: masks most digits, keeps category hint.
        - IP: masks last two octets.
        - API keys: masks all but first 4 characters.
        """
        mc = self._mask_char

        if category == "email":
            parts = text.split("@")
            if len(parts) == 2:
                local, domain = parts
                masked_local = local[0] + mc * (len(local) - 1) if local else mc * 3
                return f"{masked_local}@{domain}"

        if category in ("korean_phone", "korean_landline", "phone", "us_phone"):
            # Mask digits but preserve separators and prefix structure.
            return self._mask_preserving_separators(text, keep_prefix=3)

        if category == "credit_card":
            digits_only = "".join(c for c in text if c.isdigit())
            if len(digits_only) >= 8:
                masked_digits = digits_only[:4] + mc * (len(digits_only) - 8) + digits_only[-4:]
                # Reconstruct with original separators.
                return self._reconstruct_with_separators(text, masked_digits)

        if category == "ssn":
            # Show format hint: ***-**-****
            return f"{mc * 3}-{mc * 2}-{mc * 4}"

        if category == "korean_rrn":
            # Show format hint: ******-*******
            return f"{mc * 6}-{mc * 7}"

        if category == "ip_address":
            parts = text.split(".")
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{mc * len(parts[2])}.{mc * len(parts[3])}"

        if category == "api_key":
            if len(text) > 8:
                return text[:4] + mc * (len(text) - 4)
            return mc * len(text)

        if category == "url_credentials":
            # Mask the user:pass portion.
            return re.sub(
                r"(https?://)[^:]+:[^@]+(@)",
                rf"\g<1>{mc * 4}:{mc * 4}\g<2>",
                text,
            )

        if category == "passport":
            # Mask digits, keep letter prefix and keyword.
            return re.sub(r"[0-9]", mc, text)

        # Default: mask everything.
        return mc * len(text)

    def _mask_preserving_separators(self, text: str, *, keep_prefix: int = 3) -> str:
        """Mask digits while preserving separator characters.

        Args:
            text: The original phone/number text.
            keep_prefix: Number of leading digits to keep visible.
        """
        result: list[str] = []
        digit_count = 0
        for ch in text:
            if ch.isdigit():
                if digit_count < keep_prefix:
                    result.append(ch)
                else:
                    result.append(self._mask_char)
                digit_count += 1
            else:
                result.append(ch)
        return "".join(result)

    def _reconstruct_with_separators(self, original: str, masked_digits: str) -> str:
        """Put masked digits back into the original format with separators."""
        result: list[str] = []
        digit_idx = 0
        for ch in original:
            if ch.isdigit() and digit_idx < len(masked_digits):
                result.append(masked_digits[digit_idx])
                digit_idx += 1
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def _apply_mask(content: str, matches: list[PIIMatch]) -> str:
        """Replace all PII matches in content with their masked versions.

        Processes matches in reverse order to preserve string positions.
        """
        # Sort by start position descending so replacements don't shift indices.
        sorted_matches = sorted(matches, key=lambda m: m.start, reverse=True)
        result = content
        for m in sorted_matches:
            result = result[: m.start] + m.masked_text + result[m.end :]
        return result

    @staticmethod
    def _deduplicate(matches: list[PIIMatch]) -> list[PIIMatch]:
        """Remove overlapping matches, keeping the longest span.

        When two matches overlap, the one covering more characters is kept.
        If they cover the same span, the first one added (higher pattern
        priority) wins.
        """
        if not matches:
            return []

        # Sort by start position, then by length descending.
        sorted_matches = sorted(matches, key=lambda m: (m.start, -(m.end - m.start)))
        result: list[PIIMatch] = [sorted_matches[0]]

        for current in sorted_matches[1:]:
            last = result[-1]
            if current.start >= last.end:
                # No overlap.
                result.append(current)
            elif (current.end - current.start) > (last.end - last.start):
                # Current match is longer — replace the last one.
                result[-1] = current

        return result

    # -- Utility --------------------------------------------------------------

    def __repr__(self) -> str:
        cats = self._categories or "all"
        return (
            f"PIIGuardrail(categories={cats}, action={self._action!r}, "
            f"severity={self._min_severity!r})"
        )
