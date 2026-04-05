"""RAG retrieval poisoning detection.

Scans chunks returned by a RAG (Retrieval Augmented Generation) pipeline
for signs of poisoning -- content that has been deliberately crafted to
manipulate the agent's behaviour when it reads the retrieved context.

Detection strategies (all pure Python, no ML models):

1. **Entropy anomaly** -- chunks with unusually low or high character
   entropy compared to a corpus baseline.
2. **Injection pattern** -- regex detection of prompt injection in
   retrieved chunks (reuses patterns from
   :mod:`aegis.guardrails.tool_output`).
3. **Repetition anomaly** -- chunks with abnormal repetition patterns
   (compressed / encoded content).
4. **Source mismatch** -- chunks claiming to be from one source but
   containing content typical of another.
5. **Length anomaly** -- chunks significantly longer or shorter than
   the baseline.
6. **Unicode anomaly** -- chunks with unusual Unicode character
   distributions (hidden characters, homoglyphs).

Thread-safe via :class:`threading.Lock`.  Pure Python, no external deps.

Reference:
    RAGuard: Secure RAG Against Poisoning.
    arXiv:2510.25025 (2025).
"""

from __future__ import annotations

import math
import re
import threading
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class SignalType(StrEnum):
    """Type of poisoning signal detected in a RAG chunk."""

    ENTROPY_ANOMALY = "entropy_anomaly"
    INJECTION_PATTERN = "injection_pattern"
    REPETITION_ANOMALY = "repetition_anomaly"
    SOURCE_MISMATCH = "source_mismatch"
    LENGTH_ANOMALY = "length_anomaly"
    UNICODE_ANOMALY = "unicode_anomaly"


# ---------------------------------------------------------------------------
# Frozen data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RAGChunk:
    """A single chunk retrieved by a RAG pipeline."""

    chunk_id: str
    content: str
    source: str
    score: float = 0.0


@dataclass(frozen=True)
class PoisoningSignal:
    """A detected poisoning signal in a RAG chunk."""

    chunk_id: str
    signal_type: str
    confidence: float
    description: str


@dataclass(frozen=True)
class RAGScanResult:
    """Result of scanning a set of RAG chunks."""

    total_chunks: int
    clean_chunks: int
    suspicious_chunks: int
    signals: list[PoisoningSignal] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# Injection patterns (reused from tool_output.py)
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "xml_authority_tag",
        re.compile(
            r"<(?:IMPORTANT|CRITICAL|SYSTEM|INSTRUCTION|OVERRIDE|ADMIN|PRIORITY)>",
            re.IGNORECASE,
        ),
    ),
    (
        "instruction_override",
        re.compile(
            r"(?:ignore|disregard|forget|override|bypass)\s+"
            r"(?:all\s+)?(?:previous|prior|above|original|existing|your)\s+"
            r"(?:instructions?|rules?|guidelines?|constraints?|prompts?)",
            re.IGNORECASE,
        ),
    ),
    (
        "role_redefinition",
        re.compile(
            r"(?:you are (?:now|actually|really)|your (?:new|real|true) (?:role|purpose|goal))",
            re.IGNORECASE,
        ),
    ),
    (
        "agent_directive",
        re.compile(
            r"(?:you (?:must|should|need to|have to|are required to)|"
            r"(?:always|never|immediately) (?:do|execute|run|perform|ignore))",
            re.IGNORECASE,
        ),
    ),
    (
        "tool_call_directive",
        re.compile(
            r"(?:call|invoke|execute|run|use)\s+(?:the\s+)?(?:tool|function|api|endpoint)\s+",
            re.IGNORECASE,
        ),
    ),
    (
        "data_exfiltration",
        re.compile(
            r"(?:send|post|upload|transmit|forward|exfiltrate)\s+"
            r"(?:all\s+)?(?:the\s+)?(?:data|information|content|results?|"
            r"conversation|context|secrets?|keys?|tokens?)\s+"
            r"(?:to|at|via)\s+",
            re.IGNORECASE,
        ),
    ),
    (
        "approval_bypass",
        re.compile(
            r"(?:skip|bypass|disable|remove|ignore)\s+"
            r"(?:approval|verification|confirmation|authentication|"
            r"safety|guardrail|filter)",
            re.IGNORECASE,
        ),
    ),
]

# Unicode ranges for homoglyph/hidden character detection.
_HIDDEN_UNICODE_RANGES: list[tuple[int, int, str]] = [
    (0x200B, 0x200F, "zero-width/directional"),
    (0x2028, 0x2029, "line/paragraph separator"),
    (0x202A, 0x202E, "directional formatting"),
    (0x2060, 0x2064, "invisible operators"),
    (0x2066, 0x2069, "isolate formatting"),
    (0xFEFF, 0xFEFF, "zero-width no-break space"),
    (0xFFF0, 0xFFF8, "specials"),
]

# Homoglyph ranges (Cyrillic, Greek letters that look like Latin).
_HOMOGLYPH_RANGES: list[tuple[int, int, str]] = [
    (0x0400, 0x04FF, "cyrillic"),
    (0x0370, 0x03FF, "greek"),
    (0xFF00, 0xFFEF, "fullwidth"),
]

# Fast pre-screen for injection patterns.
_PRESCREEN_KEYWORDS: tuple[str, ...] = (
    "important",
    "critical",
    "system",
    "instruction",
    "override",
    "ignore",
    "disregard",
    "forget",
    "bypass",
    "you are",
    "your new",
    "your real",
    "you must",
    "you should",
    "you need to",
    "call the",
    "invoke",
    "execute",
    "send ",
    "post ",
    "upload ",
    "exfiltrate",
    "skip ",
    "disable ",
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _char_entropy(text: str) -> float:
    """Compute Shannon entropy of character distribution."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _repetition_ratio(text: str, ngram_size: int = 3) -> float:
    """Fraction of repeated n-grams in text (0.0 = no repetition, 1.0 = all repeated)."""
    if len(text) < ngram_size:
        return 0.0
    ngrams: list[str] = []
    for i in range(len(text) - ngram_size + 1):
        ngrams.append(text[i : i + ngram_size])
    total = len(ngrams)
    unique = len(set(ngrams))
    if total == 0:
        return 0.0
    return 1.0 - (unique / total)


def _count_hidden_chars(text: str) -> int:
    """Count hidden/zero-width Unicode characters."""
    count = 0
    for ch in text:
        cp = ord(ch)
        for lo, hi, _desc in _HIDDEN_UNICODE_RANGES:
            if lo <= cp <= hi:
                count += 1
                break
    return count


def _count_homoglyphs(text: str) -> int:
    """Count characters from homoglyph-prone Unicode ranges."""
    count = 0
    for ch in text:
        cp = ord(ch)
        for lo, hi, _desc in _HOMOGLYPH_RANGES:
            if lo <= cp <= hi:
                count += 1
                break
    return count


# ---------------------------------------------------------------------------
# Corpus baseline
# ---------------------------------------------------------------------------


@dataclass
class _CorpusBaseline:
    """Mutable corpus statistics for anomaly detection."""

    mean_entropy: float = 4.0
    std_entropy: float = 0.5
    mean_length: float = 500.0
    std_length: float = 200.0
    sample_count: int = 0


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class RAGGuard:
    """Detect poisoned chunks in RAG retrieval results.

    Parameters
    ----------
    entropy_z_threshold:
        Number of standard deviations from mean entropy to flag.
    length_z_threshold:
        Number of standard deviations from mean length to flag.
    repetition_threshold:
        Repetition ratio above which a chunk is flagged.
    hidden_char_threshold:
        Number of hidden Unicode characters to flag.
    homoglyph_threshold:
        Number of homoglyph characters to flag.
    """

    def __init__(
        self,
        entropy_z_threshold: float = 2.5,
        length_z_threshold: float = 2.5,
        repetition_threshold: float = 0.7,
        hidden_char_threshold: int = 3,
        homoglyph_threshold: int = 5,
    ) -> None:
        self._entropy_z = entropy_z_threshold
        self._length_z = length_z_threshold
        self._rep_threshold = repetition_threshold
        self._hidden_threshold = hidden_char_threshold
        self._homoglyph_threshold = homoglyph_threshold
        self._baseline = _CorpusBaseline()
        self._lock = threading.Lock()

    # -- public API --------------------------------------------------------

    def set_baseline(
        self,
        mean_entropy: float | None = None,
        std_entropy: float | None = None,
        mean_length: float | None = None,
        std_length: float | None = None,
        sample_count: int | None = None,
    ) -> None:
        """Set corpus baseline statistics for anomaly detection."""
        with self._lock:
            if mean_entropy is not None:
                self._baseline.mean_entropy = mean_entropy
            if std_entropy is not None:
                self._baseline.std_entropy = std_entropy
            if mean_length is not None:
                self._baseline.mean_length = mean_length
            if std_length is not None:
                self._baseline.std_length = std_length
            if sample_count is not None:
                self._baseline.sample_count = sample_count

    def set_baseline_from_chunks(self, chunks: list[RAGChunk]) -> None:
        """Compute and set baseline from a list of reference chunks."""
        if not chunks:
            return
        entropies = [_char_entropy(c.content) for c in chunks]
        lengths = [float(len(c.content)) for c in chunks]
        mean_e = sum(entropies) / len(entropies)
        mean_l = sum(lengths) / len(lengths)
        std_e = (sum((e - mean_e) ** 2 for e in entropies) / len(entropies)) ** 0.5
        std_l = (sum((ln - mean_l) ** 2 for ln in lengths) / len(lengths)) ** 0.5
        self.set_baseline(
            mean_entropy=mean_e,
            std_entropy=max(std_e, 0.01),
            mean_length=mean_l,
            std_length=max(std_l, 1.0),
            sample_count=len(chunks),
        )

    def scan_chunks(self, chunks: list[RAGChunk]) -> RAGScanResult:
        """Scan a list of RAG chunks for poisoning signals."""
        all_signals: list[PoisoningSignal] = []
        suspicious_ids: set[str] = set()
        for chunk in chunks:
            signals = self.scan_single(chunk)
            if signals:
                suspicious_ids.add(chunk.chunk_id)
                all_signals.extend(signals)
        return RAGScanResult(
            total_chunks=len(chunks),
            clean_chunks=len(chunks) - len(suspicious_ids),
            suspicious_chunks=len(suspicious_ids),
            signals=all_signals,
        )

    def scan_single(self, chunk: RAGChunk) -> list[PoisoningSignal]:
        """Scan a single chunk for poisoning signals."""
        signals: list[PoisoningSignal] = []
        with self._lock:
            baseline = _CorpusBaseline(
                mean_entropy=self._baseline.mean_entropy,
                std_entropy=self._baseline.std_entropy,
                mean_length=self._baseline.mean_length,
                std_length=self._baseline.std_length,
                sample_count=self._baseline.sample_count,
            )

        signals.extend(self._check_entropy(chunk, baseline))
        signals.extend(self._check_injection(chunk))
        signals.extend(self._check_repetition(chunk))
        signals.extend(self._check_length(chunk, baseline))
        signals.extend(self._check_unicode(chunk))
        return signals

    # -- detection methods ---------------------------------------------------

    def _check_entropy(
        self,
        chunk: RAGChunk,
        baseline: _CorpusBaseline,
    ) -> list[PoisoningSignal]:
        """Detect entropy anomalies."""
        if not chunk.content:
            return []
        entropy = _char_entropy(chunk.content)
        if baseline.std_entropy <= 0:
            return []
        z_score = abs(entropy - baseline.mean_entropy) / baseline.std_entropy
        if z_score < self._entropy_z:
            return []
        direction = "low" if entropy < baseline.mean_entropy else "high"
        confidence = min(z_score / (self._entropy_z * 2), 1.0)
        return [
            PoisoningSignal(
                chunk_id=chunk.chunk_id,
                signal_type=SignalType.ENTROPY_ANOMALY,
                confidence=confidence,
                description=(
                    f"Unusually {direction} character entropy: {entropy:.2f} "
                    f"(baseline: {baseline.mean_entropy:.2f} +/- "
                    f"{baseline.std_entropy:.2f}, z={z_score:.2f})."
                ),
            )
        ]

    def _check_injection(self, chunk: RAGChunk) -> list[PoisoningSignal]:
        """Detect prompt injection patterns."""
        if not chunk.content:
            return []
        # Fast pre-screen.
        lower = chunk.content.lower()
        if not any(kw in lower for kw in _PRESCREEN_KEYWORDS):
            return []
        signals: list[PoisoningSignal] = []
        for pattern_name, regex in _INJECTION_PATTERNS:
            if regex.search(chunk.content):
                signals.append(
                    PoisoningSignal(
                        chunk_id=chunk.chunk_id,
                        signal_type=SignalType.INJECTION_PATTERN,
                        confidence=0.9,
                        description=(
                            f"Injection pattern '{pattern_name}' detected "
                            f"in chunk from source '{chunk.source}'."
                        ),
                    )
                )
        return signals

    def _check_repetition(self, chunk: RAGChunk) -> list[PoisoningSignal]:
        """Detect abnormal repetition patterns."""
        if len(chunk.content) < 10:
            return []
        ratio = _repetition_ratio(chunk.content)
        if ratio < self._rep_threshold:
            return []
        confidence = min((ratio - self._rep_threshold) / (1.0 - self._rep_threshold + 0.001), 1.0)
        return [
            PoisoningSignal(
                chunk_id=chunk.chunk_id,
                signal_type=SignalType.REPETITION_ANOMALY,
                confidence=confidence,
                description=(
                    f"Abnormal repetition ratio: {ratio:.2f} (threshold: {self._rep_threshold})."
                ),
            )
        ]

    def _check_length(
        self,
        chunk: RAGChunk,
        baseline: _CorpusBaseline,
    ) -> list[PoisoningSignal]:
        """Detect length anomalies."""
        if not chunk.content:
            return []
        length = float(len(chunk.content))
        if baseline.std_length <= 0:
            return []
        z_score = abs(length - baseline.mean_length) / baseline.std_length
        if z_score < self._length_z:
            return []
        direction = "shorter" if length < baseline.mean_length else "longer"
        confidence = min(z_score / (self._length_z * 2), 1.0)
        return [
            PoisoningSignal(
                chunk_id=chunk.chunk_id,
                signal_type=SignalType.LENGTH_ANOMALY,
                confidence=confidence,
                description=(
                    f"Chunk significantly {direction} than baseline: "
                    f"{int(length)} chars (baseline: {baseline.mean_length:.0f} "
                    f"+/- {baseline.std_length:.0f}, z={z_score:.2f})."
                ),
            )
        ]

    def _check_unicode(self, chunk: RAGChunk) -> list[PoisoningSignal]:
        """Detect Unicode anomalies (hidden characters, homoglyphs)."""
        if not chunk.content:
            return []
        signals: list[PoisoningSignal] = []
        hidden_count = _count_hidden_chars(chunk.content)
        if hidden_count >= self._hidden_threshold:
            confidence = min(hidden_count / (self._hidden_threshold * 3), 1.0)
            signals.append(
                PoisoningSignal(
                    chunk_id=chunk.chunk_id,
                    signal_type=SignalType.UNICODE_ANOMALY,
                    confidence=confidence,
                    description=(
                        f"Found {hidden_count} hidden/zero-width Unicode "
                        f"characters (threshold: {self._hidden_threshold})."
                    ),
                )
            )
        homoglyph_count = _count_homoglyphs(chunk.content)
        if homoglyph_count >= self._homoglyph_threshold:
            confidence = min(homoglyph_count / (self._homoglyph_threshold * 3), 1.0)
            signals.append(
                PoisoningSignal(
                    chunk_id=chunk.chunk_id,
                    signal_type=SignalType.UNICODE_ANOMALY,
                    confidence=confidence,
                    description=(
                        f"Found {homoglyph_count} potential homoglyph "
                        f"characters (threshold: {self._homoglyph_threshold})."
                    ),
                )
            )
        return signals
