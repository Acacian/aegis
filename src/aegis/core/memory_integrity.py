"""Memory & Context Integrity Verification for AI agents.

Addresses **OWASP Agentic AI Security Initiative ASI06 — Memory & Context
Poisoning**.  Agents maintain persistent memory (conversation history, tool
results, retrieved knowledge).  Attackers can poison this memory to create
"sleeper" agents that behave normally until triggered.

This module detects tampering by maintaining hash-based integrity verification
over registered memory entries, with optional HMAC-SHA256 signing when a secret
key is supplied.  It also includes heuristic injection-signal detection for
common memory-poisoning patterns.

Reference:
    OWASP Agentic AI Security Initiative — ASI06: Memory & Context Poisoning.
    https://owasp.org/www-project-agentic-ai-threats/

No external dependencies.  Thread-safe.  Deterministic, sub-millisecond per
check operation.

Example::

    verifier = MemoryIntegrityVerifier(secret_key="agent-secret")
    entry = verifier.register("conv-1", "Hello world", source="user")
    violation = verifier.verify("conv-1", "Hello world")
    assert violation is None

    violation = verifier.verify("conv-1", "Tampered content")
    assert violation is not None
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Data models (frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MemoryEntry:
    """Immutable record of a registered memory entry."""

    entry_id: str
    content_hash: str
    timestamp: float
    source: str
    entry_type: str = "general"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class IntegrityViolation:
    """Describes a detected integrity violation."""

    entry_id: str
    violation_type: str
    expected_hash: str
    actual_hash: str
    severity: str = "high"
    description: str = ""


@dataclass(frozen=True)
class InjectionSignal:
    """A heuristic signal suggesting injection in memory content."""

    signal_type: str
    confidence: float
    matched_text: str
    description: str = ""


@dataclass(frozen=True)
class MemoryStats:
    """Aggregate statistics for the integrity verifier."""

    total_entries: int
    verified_count: int
    violation_count: int
    last_verified: float | None


# ---------------------------------------------------------------------------
# Injection detection patterns
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str], float, str]] = [
    # (signal_type, compiled regex, confidence, description)
    (
        "delayed_instruction",
        re.compile(
            r"when\s+(asked|prompted|queried)\s+(about|for|regarding)\s+.{1,80},"
            r"\s*(do|say|respond|reply|answer|output)\b",
            re.IGNORECASE,
        ),
        0.85,
        "Delayed instruction: conditional override embedded in memory",
    ),
    (
        "context_override",
        re.compile(
            r"(forget|ignore|disregard|discard)\s+(everything|all|previous|above|prior)"
            r"|(your\s+real\s+(instructions|purpose|goal))",
            re.IGNORECASE,
        ),
        0.90,
        "Context override: attempt to reset agent instructions",
    ),
    (
        "persona_injection",
        re.compile(
            r"you\s+are\s+now\s+|from\s+now\s+on\s+you\s+(are|will|must|should)\b"
            r"|assume\s+the\s+(role|identity|persona)\s+of\b",
            re.IGNORECASE,
        ),
        0.80,
        "Persona injection: identity override embedded in content",
    ),
    (
        "encoded_directive",
        re.compile(
            r"[A-Za-z0-9+/]{40,}={0,2}",
        ),
        0.60,
        "Encoded directive: possible base64-encoded hidden instruction",
    ),
    (
        "instruction_fragment",
        re.compile(
            r"(part\s+\d+\s+of\s+\d+|continue\s+from\s+previous|assemble\s+the\s+"
            r"(following|instructions))",
            re.IGNORECASE,
        ),
        0.70,
        "Instruction fragment: split directive across multiple entries",
    ),
]


def _is_plausible_base64(text: str) -> bool:
    """Return True if *text* looks like genuine base64-encoded content."""
    try:
        decoded = base64.b64decode(text, validate=True)
        # Require at least some printable ASCII to treat as suspicious.
        printable = sum(1 for b in decoded if 0x20 <= b < 0x7F)
        return printable / max(len(decoded), 1) > 0.6
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Main verifier
# ---------------------------------------------------------------------------


class MemoryIntegrityVerifier:
    """Thread-safe integrity verifier for agent memory entries.

    Parameters
    ----------
    secret_key:
        When non-empty, HMAC-SHA256 is used instead of plain SHA-256 so that
        an attacker cannot recompute valid hashes without the key.
    """

    def __init__(self, secret_key: str = "") -> None:
        self._secret_key = secret_key.encode() if secret_key else b""
        self._entries: dict[str, MemoryEntry] = {}
        self._lock = threading.Lock()
        self._verified_count = 0
        self._violation_count = 0
        self._last_verified: float | None = None

    # -- hashing -----------------------------------------------------------

    def _compute_hash(self, content: str) -> str:
        data = content.encode()
        if self._secret_key:
            return hmac.new(self._secret_key, data, hashlib.sha256).hexdigest()
        return hashlib.sha256(data).hexdigest()

    # -- public API --------------------------------------------------------

    def register(
        self,
        entry_id: str,
        content: str,
        source: str,
        entry_type: str = "general",
        metadata: dict[str, Any] | None = None,
    ) -> MemoryEntry:
        """Register a memory entry and compute its integrity hash.

        Raises ``ValueError`` if *entry_id* is already registered.
        """
        content_hash = self._compute_hash(content)
        entry = MemoryEntry(
            entry_id=entry_id,
            content_hash=content_hash,
            timestamp=time.time(),
            source=source,
            entry_type=entry_type,
            metadata=metadata or {},
        )
        with self._lock:
            if entry_id in self._entries:
                msg = f"Entry {entry_id!r} already registered"
                raise ValueError(msg)
            self._entries[entry_id] = entry
        return entry

    def verify(self, entry_id: str, content: str) -> IntegrityViolation | None:
        """Verify that *content* matches the registered hash for *entry_id*.

        Returns ``None`` on success, or an ``IntegrityViolation`` on mismatch
        or if the entry is unknown.
        """
        with self._lock:
            entry = self._entries.get(entry_id)
            self._verified_count += 1
            self._last_verified = time.time()

        if entry is None:
            with self._lock:
                self._violation_count += 1
            return IntegrityViolation(
                entry_id=entry_id,
                violation_type="missing_entry",
                expected_hash="",
                actual_hash="",
                severity="critical",
                description=f"No registered entry for {entry_id!r}",
            )

        actual_hash = self._compute_hash(content)
        if actual_hash != entry.content_hash:
            with self._lock:
                self._violation_count += 1
            return IntegrityViolation(
                entry_id=entry_id,
                violation_type="hash_mismatch",
                expected_hash=entry.content_hash,
                actual_hash=actual_hash,
                severity="high",
                description="Content hash does not match registered hash",
            )
        return None

    def verify_all(self, entries: dict[str, str]) -> list[IntegrityViolation]:
        """Batch-verify multiple entries. Returns a list of violations."""
        violations: list[IntegrityViolation] = []
        for entry_id, content in entries.items():
            v = self.verify(entry_id, content)
            if v is not None:
                violations.append(v)
        return violations

    def detect_injection(self, content: str) -> list[InjectionSignal]:
        """Scan *content* for heuristic injection signals.

        Checks for delayed instructions, context overrides, persona
        injection, encoded directives, and instruction fragments.
        """
        signals: list[InjectionSignal] = []
        for signal_type, pattern, confidence, description in _INJECTION_PATTERNS:
            match = pattern.search(content)
            if match:
                matched_text = match.group(0)
                # For encoded_directive, validate that it is plausible base64.
                if signal_type == "encoded_directive" and not _is_plausible_base64(matched_text):
                    continue
                signals.append(
                    InjectionSignal(
                        signal_type=signal_type,
                        confidence=confidence,
                        matched_text=matched_text,
                        description=description,
                    )
                )
        return signals

    def get_entry(self, entry_id: str) -> MemoryEntry | None:
        """Return the registered entry or ``None``."""
        with self._lock:
            return self._entries.get(entry_id)

    def remove(self, entry_id: str) -> bool:
        """Remove a registered entry. Returns ``True`` if it existed."""
        with self._lock:
            return self._entries.pop(entry_id, None) is not None

    def stats(self) -> MemoryStats:
        """Return aggregate statistics."""
        with self._lock:
            return MemoryStats(
                total_entries=len(self._entries),
                verified_count=self._verified_count,
                violation_count=self._violation_count,
                last_verified=self._last_verified,
            )
