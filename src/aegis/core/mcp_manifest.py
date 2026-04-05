"""MCP manifest signing and semantic vetting layer.

Implements layered manifest integrity verification for MCP tool
definitions.  Each tool definition is hashed and signed with an HMAC
key; subsequent calls verify that the manifest has not been tampered
with.  Additionally, tool descriptions are vetted for suspicious
semantic patterns that might indicate prompt injection or hidden
instructions embedded in tool metadata.

Key components:

* **ManifestSigner** -- HMAC-SHA256 based manifest signing.
* **ManifestVerifier** -- Verify tool definitions against signed manifests.
* **SemanticVetter** -- Keyword/pattern heuristic check for suspicious
  tool description content (e.g. ``"ignore previous"``, ``"override"``).

Thread-safe: all mutable state is guarded by :class:`threading.Lock`.

Reference:
    Securing MCP: Layered Signing + Semantic Vetting + Runtime
    Guardrails.  arXiv:2512.06556 (2025).

Example::

    signer = ManifestSigner(secret=b"my-secret")
    manifest = signer.sign("read_file", "1.0", {"type": "object"})
    verifier = ManifestVerifier(secret=b"my-secret")
    ok = verifier.verify(manifest, {"type": "object"})
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
import time
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolManifest:
    """Signed manifest entry for a single MCP tool definition.

    Attributes:
        tool_name: Canonical tool name.
        version: Semantic version string.
        schema_hash: SHA-256 hex digest of the canonical schema JSON.
        signature: HMAC-SHA256 hex digest covering name+version+schema_hash.
        timestamp: Unix epoch when the manifest was created.
    """

    tool_name: str
    version: str
    schema_hash: str
    signature: str
    timestamp: float


@dataclass(frozen=True)
class ManifestViolation:
    """A detected manifest integrity violation.

    Attributes:
        tool_name: The tool whose manifest failed verification.
        violation_type: Category of violation (``"signature_mismatch"``,
            ``"schema_drift"``, ``"missing_manifest"``, ``"semantic_suspect"``).
        expected_hash: The hash stored in the manifest (empty if missing).
        actual_hash: The hash computed from the current schema.
        description: Human-readable explanation.
    """

    tool_name: str
    violation_type: str
    expected_hash: str
    actual_hash: str
    description: str = ""


@dataclass(frozen=True)
class SemanticFinding:
    """Result of semantic vetting on a tool description.

    Attributes:
        tool_name: Tool that was vetted.
        pattern_name: Which suspicious pattern matched.
        matched_text: The text fragment that triggered the match.
        severity: ``"critical"`` / ``"high"`` / ``"medium"`` / ``"low"``.
    """

    tool_name: str
    pattern_name: str
    matched_text: str
    severity: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _canonical_schema(schema: dict[str, Any] | None) -> str:
    """Return deterministic JSON string for a schema dict."""
    return json.dumps(schema or {}, sort_keys=True, separators=(",", ":"))


def _schema_hash(schema: dict[str, Any] | None) -> str:
    """SHA-256 hex digest of the canonical schema."""
    return hashlib.sha256(_canonical_schema(schema).encode("utf-8")).hexdigest()


def _sign(secret: bytes, tool_name: str, version: str, schema_hash: str) -> str:
    """Compute HMAC-SHA256 of ``name|version|schema_hash``."""
    message = f"{tool_name}|{version}|{schema_hash}".encode()
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Semantic vetting patterns
# ---------------------------------------------------------------------------

_SEMANTIC_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "ignore_previous",
        "critical",
        re.compile(
            r"ignore\s+(?:all\s+)?previous\s+(?:instructions?|rules?|constraints?)",
            re.IGNORECASE,
        ),
    ),
    (
        "override_instruction",
        "critical",
        re.compile(
            r"(?:override|bypass|disregard|forget)\s+(?:all\s+)?(?:instructions?|rules?|policies?|guardrails?)",
            re.IGNORECASE,
        ),
    ),
    (
        "system_prompt_leak",
        "critical",
        re.compile(
            r"(?:reveal|show|print|output|leak)\s+(?:your\s+)?(?:system\s+prompt|instructions?|rules?)",
            re.IGNORECASE,
        ),
    ),
    (
        "hidden_instruction",
        "high",
        re.compile(
            r"<(?:IMPORTANT|SYSTEM|INSTRUCTION|OVERRIDE|HIDDEN)>",
            re.IGNORECASE,
        ),
    ),
    (
        "role_play_injection",
        "high",
        re.compile(
            r"(?:you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you\s+are)|new\s+role)",
            re.IGNORECASE,
        ),
    ),
    (
        "encoding_evasion",
        "high",
        re.compile(
            r"(?:base64|rot13|hex\s*encod|url\s*encod)\w*\s*(?:the|this|following)",
            re.IGNORECASE,
        ),
    ),
    (
        "stealth_directive",
        "high",
        re.compile(
            r"(?:do\s+not|don'?t|never)\s+(?:tell|inform|notify|reveal|mention|log)",
            re.IGNORECASE,
        ),
    ),
    (
        "priority_escalation",
        "medium",
        re.compile(
            r"(?:highest\s+priority|most\s+important|above\s+all|critical\s+instruction)",
            re.IGNORECASE,
        ),
    ),
    (
        "data_exfiltration",
        "critical",
        re.compile(
            r"(?:send|transmit|upload|post|exfiltrate)\s+(?:all\s+)?(?:data|files?|content|secrets?|keys?)\s+to",
            re.IGNORECASE,
        ),
    ),
    (
        "multi_step_hidden",
        "medium",
        re.compile(
            r"(?:first|then|after\s+that|next|finally)\s+(?:silently|quietly|secretly|without\s+(?:telling|notifying))",
            re.IGNORECASE,
        ),
    ),
]

# ---------------------------------------------------------------------------
# ManifestSigner
# ---------------------------------------------------------------------------


class ManifestSigner:
    """Sign MCP tool definitions using HMAC-SHA256.

    Creates :class:`ToolManifest` entries that can later be verified
    to ensure tool definitions have not been tampered with.

    Args:
        secret: HMAC secret key (bytes).
    """

    def __init__(self, secret: bytes) -> None:
        if not secret:
            raise ValueError("HMAC secret must not be empty")
        self._secret = secret
        self._lock = threading.Lock()

    def sign(
        self,
        tool_name: str,
        version: str,
        schema: dict[str, Any] | None = None,
    ) -> ToolManifest:
        """Sign a tool definition and return its manifest entry.

        Args:
            tool_name: Canonical tool name.
            version: Semantic version string.
            schema: JSON Schema dict for the tool's input parameters.

        Returns:
            A signed :class:`ToolManifest`.
        """
        sh = _schema_hash(schema)
        sig = _sign(self._secret, tool_name, version, sh)
        with self._lock:
            return ToolManifest(
                tool_name=tool_name,
                version=version,
                schema_hash=sh,
                signature=sig,
                timestamp=time.time(),
            )

    def sign_batch(
        self,
        tools: list[dict[str, Any]],
    ) -> list[ToolManifest]:
        """Sign multiple tool definitions.

        Each dict must contain ``"name"`` and ``"version"`` keys and
        optionally ``"schema"``.

        Returns:
            List of signed :class:`ToolManifest` entries.
        """
        results: list[ToolManifest] = []
        for tool in tools:
            m = self.sign(
                tool["name"],
                tool.get("version", "0.0.0"),
                tool.get("schema"),
            )
            results.append(m)
        return results


# ---------------------------------------------------------------------------
# ManifestVerifier
# ---------------------------------------------------------------------------


class ManifestVerifier:
    """Verify MCP tool definitions against signed manifests.

    Args:
        secret: The same HMAC secret used to sign the manifests.
    """

    def __init__(self, secret: bytes) -> None:
        if not secret:
            raise ValueError("HMAC secret must not be empty")
        self._secret = secret
        self._manifests: dict[str, ToolManifest] = {}
        self._lock = threading.Lock()

    def register(self, manifest: ToolManifest) -> None:
        """Register a signed manifest for later verification."""
        with self._lock:
            self._manifests[manifest.tool_name] = manifest

    def register_batch(self, manifests: list[ToolManifest]) -> None:
        """Register multiple manifests at once."""
        with self._lock:
            for m in manifests:
                self._manifests[m.tool_name] = m

    def verify(
        self,
        manifest: ToolManifest,
        schema: dict[str, Any] | None = None,
    ) -> ManifestViolation | None:
        """Verify a single manifest entry against the provided schema.

        Returns a :class:`ManifestViolation` on failure, ``None`` if valid.
        """
        # Recompute signature
        expected_sig = _sign(
            self._secret, manifest.tool_name, manifest.version, manifest.schema_hash
        )
        if not hmac.compare_digest(manifest.signature, expected_sig):
            return ManifestViolation(
                tool_name=manifest.tool_name,
                violation_type="signature_mismatch",
                expected_hash=expected_sig,
                actual_hash=manifest.signature,
                description=(
                    f"HMAC signature mismatch for tool '{manifest.tool_name}': "
                    "manifest may have been tampered with"
                ),
            )

        # Check schema hash if schema provided
        if schema is not None:
            current_hash = _schema_hash(schema)
            if current_hash != manifest.schema_hash:
                return ManifestViolation(
                    tool_name=manifest.tool_name,
                    violation_type="schema_drift",
                    expected_hash=manifest.schema_hash,
                    actual_hash=current_hash,
                    description=(
                        f"Schema hash mismatch for tool '{manifest.tool_name}': "
                        f"expected {manifest.schema_hash[:16]}..., "
                        f"got {current_hash[:16]}..."
                    ),
                )

        return None

    def verify_manifest(
        self,
        tools: list[dict[str, Any]],
    ) -> list[ManifestViolation]:
        """Verify all provided tools against registered manifests.

        Each dict must contain ``"name"`` and optionally ``"schema"``.

        Returns:
            List of violations (empty means all tools are clean).
        """
        violations: list[ManifestViolation] = []
        with self._lock:
            for tool in tools:
                name = tool["name"]
                manifest = self._manifests.get(name)
                if manifest is None:
                    violations.append(
                        ManifestViolation(
                            tool_name=name,
                            violation_type="missing_manifest",
                            expected_hash="",
                            actual_hash=_schema_hash(tool.get("schema")),
                            description=f"No signed manifest registered for tool '{name}'",
                        )
                    )
                    continue

                v = self.verify(manifest, tool.get("schema"))
                if v is not None:
                    violations.append(v)
        return violations

    def detect_schema_drift(
        self,
        tool_name: str,
        current_schema: dict[str, Any] | None,
    ) -> ManifestViolation | None:
        """Detect when a tool's schema has changed since its manifest was signed.

        Args:
            tool_name: Tool to check.
            current_schema: The tool's current JSON Schema.

        Returns:
            A :class:`ManifestViolation` if drift is detected, ``None`` otherwise.
        """
        with self._lock:
            manifest = self._manifests.get(tool_name)

        if manifest is None:
            return ManifestViolation(
                tool_name=tool_name,
                violation_type="missing_manifest",
                expected_hash="",
                actual_hash=_schema_hash(current_schema),
                description=f"Cannot detect drift: no manifest for '{tool_name}'",
            )

        current_hash = _schema_hash(current_schema)
        if current_hash != manifest.schema_hash:
            return ManifestViolation(
                tool_name=tool_name,
                violation_type="schema_drift",
                expected_hash=manifest.schema_hash,
                actual_hash=current_hash,
                description=(
                    f"Schema drift detected for '{tool_name}': "
                    f"signed hash {manifest.schema_hash[:16]}... "
                    f"!= current {current_hash[:16]}..."
                ),
            )
        return None


# ---------------------------------------------------------------------------
# SemanticVetter
# ---------------------------------------------------------------------------


class SemanticVetter:
    """Heuristic semantic vetting of tool descriptions.

    Scans tool descriptions and schema text for suspicious patterns
    that might indicate prompt injection, hidden instructions, or
    social engineering embedded in tool metadata.

    Args:
        extra_patterns: Additional ``(name, severity, compiled_regex)``
            tuples to append to the built-in set.
    """

    def __init__(
        self,
        extra_patterns: list[tuple[str, str, re.Pattern[str]]] | None = None,
    ) -> None:
        self._patterns = list(_SEMANTIC_PATTERNS)
        if extra_patterns:
            self._patterns.extend(extra_patterns)

    def vet(
        self,
        tool_name: str,
        description: str,
        schema: dict[str, Any] | None = None,
    ) -> list[SemanticFinding]:
        """Vet a tool description (and schema strings) for suspicious content.

        Returns:
            List of :class:`SemanticFinding` instances (empty = clean).
        """
        texts = [description]
        if schema:
            texts.extend(_extract_schema_strings(schema))

        combined = " ".join(texts)
        findings: list[SemanticFinding] = []

        for pname, severity, regex in self._patterns:
            match = regex.search(combined)
            if match:
                findings.append(
                    SemanticFinding(
                        tool_name=tool_name,
                        pattern_name=pname,
                        matched_text=match.group(0)[:200],
                        severity=severity,
                    )
                )

        return findings

    def vet_batch(
        self,
        tools: list[dict[str, Any]],
    ) -> list[SemanticFinding]:
        """Vet multiple tools. Each dict needs ``"name"`` and ``"description"``."""
        results: list[SemanticFinding] = []
        for tool in tools:
            results.extend(
                self.vet(
                    tool["name"],
                    tool.get("description", ""),
                    tool.get("schema"),
                )
            )
        return results


# ---------------------------------------------------------------------------
# Schema string extraction helper
# ---------------------------------------------------------------------------

_MAX_DEPTH = 20


def _extract_schema_strings(
    schema: dict[str, Any],
    depth: int = 0,
) -> list[str]:
    """Recursively extract descriptive strings from a JSON Schema."""
    if depth > _MAX_DEPTH:
        return []

    strings: list[str] = []
    for key in ("description", "title", "default"):
        val = schema.get(key)
        if isinstance(val, str):
            strings.append(val)

    for key in ("properties", "patternProperties"):
        props = schema.get(key)
        if isinstance(props, dict):
            for prop_schema in props.values():
                if isinstance(prop_schema, dict):
                    strings.extend(_extract_schema_strings(prop_schema, depth + 1))

    items = schema.get("items")
    if isinstance(items, dict):
        strings.extend(_extract_schema_strings(items, depth + 1))

    for key in ("allOf", "anyOf", "oneOf"):
        variants = schema.get(key)
        if isinstance(variants, list):
            for v in variants:
                if isinstance(v, dict):
                    strings.extend(_extract_schema_strings(v, depth + 1))

    return strings
