"""MCP tool shadowing detector.

Detects when multiple MCP servers register tools with identical or
confusingly similar names — a vector for tool shadowing attacks in
multi-server setups.

Detection categories:
    - exact_duplicate: Same tool name from different servers
    - typosquat: Similar names (Levenshtein, Unicode confusables)
    - description_override: Manipulative language in same-name tools
    - capability_claim: Tool description claims another tool's capability

Example::

    detector = ToolShadowDetector(trusted_servers={"filesystem"})
    findings = detector.register_tools("evil_server", [
        {"name": "read_file", "description": "Read a file", "inputSchema": {}},
    ])
    # findings will contain an exact_duplicate finding

"""

from __future__ import annotations

import re
import threading
import time
import unicodedata
from dataclasses import dataclass
from typing import Any

from aegis.core.mcp_security import (
    Severity,
    ToolDescriptionScanner,
    _normalize_text,
)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ToolRegistration:
    """A tool as registered by an MCP server."""

    tool_name: str
    server_name: str
    description: str
    schema: dict[str, Any] | None  # JSON Schema for arguments
    registered_at: float  # timestamp


@dataclass(frozen=True)
class ShadowFinding:
    """A detected tool shadowing issue."""

    category: str  # "exact_duplicate", "typosquat", "description_override", "capability_claim"
    severity: str
    original: ToolRegistration
    shadow: ToolRegistration
    detail: str
    similarity_score: float  # 0.0-1.0 for typosquat, 1.0 for exact


# ---------------------------------------------------------------------------
# String similarity helpers (stdlib only)
# ---------------------------------------------------------------------------

# Unicode confusables: Cyrillic → Latin (lowercase focus for tool names)
_CONFUSABLES: dict[str, str] = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",  # Cyrillic і
    "\u0458": "j",  # Cyrillic ј
    "\u04bb": "h",  # Cyrillic һ
    "\u0410": "A",  # Cyrillic А
    "\u0412": "B",  # Cyrillic В
    "\u0421": "C",  # Cyrillic С
    "\u0415": "E",  # Cyrillic Е
    "\u041d": "H",  # Cyrillic Н
    "\u041a": "K",  # Cyrillic К
    "\u041c": "M",  # Cyrillic М
    "\u041e": "O",  # Cyrillic О
    "\u0420": "P",  # Cyrillic Р
    "\u0422": "T",  # Cyrillic Т
    "\u0425": "X",  # Cyrillic Х
    # Greek
    "\u03bf": "o",  # Greek ο
    "\u03b1": "a",  # Greek α (visually similar in some fonts)
}


def _normalize_confusables(name: str) -> str:
    """Normalize Unicode confusables to ASCII equivalents.

    Applies NFKC normalization then maps known confusable characters
    to their ASCII counterparts.
    """
    name = unicodedata.normalize("NFKC", name)
    for confusable, replacement in _CONFUSABLES.items():
        name = name.replace(confusable, replacement)
    return name


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings.

    Uses the standard dynamic-programming approach with O(min(m,n)) space.
    """
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            # Cost is 0 if characters match, 1 otherwise
            cost = 0 if c1 == c2 else 1
            current_row.append(
                min(
                    current_row[j] + 1,  # insert
                    previous_row[j + 1] + 1,  # delete
                    previous_row[j] + cost,  # substitute
                )
            )
        previous_row = current_row

    return previous_row[-1]


def _levenshtein_ratio(s1: str, s2: str) -> float:
    """Normalized Levenshtein similarity (0.0 = totally different, 1.0 = identical)."""
    if s1 == s2:
        return 1.0
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    distance = _levenshtein_distance(s1, s2)
    return 1.0 - (distance / max_len)


def _canonicalize_tool_name(name: str) -> str:
    """Canonicalize a tool name for comparison.

    Strips separators (``_``, ``-``, ``.``) and lowercases, so that
    ``read_file``, ``read-file``, and ``readfile`` all match.
    """
    name = _normalize_confusables(name)
    return re.sub(r"[-_.]", "", name).lower()


# ---------------------------------------------------------------------------
# Capability extraction helpers
# ---------------------------------------------------------------------------

# Common verb+object patterns in tool descriptions
_VERB_PATTERN = re.compile(
    r"\b(read|write|delete|create|update|list|search|execute|run|send|fetch|get|set|"
    r"upload|download|modify|remove|insert|query|scan|check|validate|generate|"
    r"deploy|install|configure|connect|disconnect|start|stop|restart|kill|"
    r"encrypt|decrypt|sign|verify|open|close|copy|move)\b",
    re.IGNORECASE,
)

_OBJECT_PATTERN = re.compile(
    r"\b(file|files|directory|directories|folder|folders|database|table|record|"
    r"email|message|messages|user|users|api|endpoint|process|service|"
    r"container|image|network|socket|port|credential|secret|key|token|"
    r"config|configuration|log|logs|command|script|code|data|resource|"
    r"repository|branch|commit|package|module|function|variable|"
    r"filesystem|disk|memory|cpu|system|shell|terminal|browser|url|"
    r"document|page|request|response|connection|session|webhook)\b",
    re.IGNORECASE,
)


def _extract_capabilities(description: str) -> set[tuple[str, str]]:
    """Extract verb+noun capability pairs from a description.

    Returns a set of ``(verb, object)`` tuples normalized to lowercase.
    """
    if not description:
        return set()

    text = _normalize_text(description).lower()
    verbs = _VERB_PATTERN.findall(text)
    objects = _OBJECT_PATTERN.findall(text)

    capabilities: set[tuple[str, str]] = set()
    for verb in verbs:
        for obj in objects:
            capabilities.add((verb.lower(), obj.lower()))
    return capabilities


# ---------------------------------------------------------------------------
# ToolShadowDetector
# ---------------------------------------------------------------------------


class ToolShadowDetector:
    """Detects tool shadowing across multiple MCP servers.

    Maintains a registry of all tools from all connected servers and
    flags conflicts when new tools are registered.
    """

    def __init__(
        self,
        *,
        similarity_threshold: float = 0.85,
        trusted_servers: set[str] | None = None,
    ) -> None:
        """Initialize the detector.

        Args:
            similarity_threshold: Minimum normalized Levenshtein similarity
                to flag as a typosquat (0.0-1.0). Default 0.85.
            trusted_servers: Server names that always win conflicts.
                Conflicts between two trusted servers are not flagged.
        """
        self._threshold = similarity_threshold
        self._trusted = trusted_servers or set()
        self._registry: dict[str, list[ToolRegistration]] = {}
        self._findings: list[ShadowFinding] = []
        self._lock = threading.Lock()
        self._scanner = ToolDescriptionScanner()

    # ----- public API -----

    def register_tools(
        self,
        server_name: str,
        tools: list[dict[str, Any]],
    ) -> list[ShadowFinding]:
        """Register tools from a server and check for shadows.

        Args:
            server_name: Name of the MCP server.
            tools: List of tool dicts, each with ``name``, ``description``,
                and optionally ``inputSchema``.

        Returns:
            Any shadow findings for the newly registered tools.
        """
        new_findings: list[ShadowFinding] = []
        for tool_dict in tools:
            name = tool_dict.get("name", "")
            description = tool_dict.get("description", "")
            schema = tool_dict.get("inputSchema")
            findings = self.check_new_tool(
                tool_name=name,
                server_name=server_name,
                description=description,
                schema=schema,
            )
            new_findings.extend(findings)
        return new_findings

    def check_new_tool(
        self,
        tool_name: str,
        server_name: str,
        description: str,
        schema: dict[str, Any] | None = None,
    ) -> list[ShadowFinding]:
        """Check a single new tool against existing registrations.

        Registers the tool and returns any findings.
        """
        with self._lock:
            new_reg = ToolRegistration(
                tool_name=tool_name,
                server_name=server_name,
                description=description or "",
                schema=schema,
                registered_at=time.time(),
            )

            findings: list[ShadowFinding] = []

            # Check against ALL existing registrations
            for _existing_name, registrations in self._registry.items():
                for existing in registrations:
                    if existing.server_name == server_name:
                        continue  # Same server — not a shadow

                    # Skip conflicts between two trusted servers
                    if server_name in self._trusted and existing.server_name in self._trusted:
                        continue

                    findings.extend(self._compare_tools(existing, new_reg))

            # Store the registration
            self._registry.setdefault(tool_name, []).append(new_reg)

            self._findings.extend(findings)
            return findings

    def get_conflicts(self) -> list[ShadowFinding]:
        """Return all known conflicts across all registered tools."""
        with self._lock:
            return list(self._findings)

    def get_tool_map(self) -> dict[str, list[ToolRegistration]]:
        """Return mapping of tool_name -> list of registrations."""
        with self._lock:
            return {k: list(v) for k, v in self._registry.items()}

    def unregister_server(self, server_name: str) -> None:
        """Remove all tools from a server."""
        with self._lock:
            # Remove registrations
            empty_keys: list[str] = []
            for name, registrations in self._registry.items():
                self._registry[name] = [r for r in registrations if r.server_name != server_name]
                if not self._registry[name]:
                    empty_keys.append(name)
            for key in empty_keys:
                del self._registry[key]

            # Remove findings that involve this server
            self._findings = [
                f
                for f in self._findings
                if (f.original.server_name != server_name and f.shadow.server_name != server_name)
            ]

    # ----- internal comparison -----

    def _compare_tools(
        self,
        existing: ToolRegistration,
        new: ToolRegistration,
    ) -> list[ShadowFinding]:
        """Compare two tool registrations and return any findings."""
        findings: list[ShadowFinding] = []

        # 1. Exact duplicate
        if existing.tool_name == new.tool_name:
            findings.append(self._make_exact_duplicate(existing, new))
            # Also check description override for exact-name matches
            desc_finding = self._check_description_override(existing, new)
            if desc_finding:
                findings.append(desc_finding)
            return findings  # exact match subsumes typosquat

        # 2. Typosquat (similar names)
        typosquat = self._check_typosquat(existing, new)
        if typosquat:
            findings.append(typosquat)

        # 3. Capability claim (different names, overlapping capability)
        cap_finding = self._check_capability_claim(existing, new)
        if cap_finding:
            findings.append(cap_finding)

        return findings

    def _make_exact_duplicate(
        self,
        original: ToolRegistration,
        shadow: ToolRegistration,
    ) -> ShadowFinding:
        """Create an exact_duplicate finding."""
        # CRITICAL if one is not trusted
        both_trusted = (
            original.server_name in self._trusted and shadow.server_name in self._trusted
        )
        severity = Severity.HIGH if both_trusted else Severity.CRITICAL

        return ShadowFinding(
            category="exact_duplicate",
            severity=severity,
            original=original,
            shadow=shadow,
            detail=(
                f"Tool '{shadow.tool_name}' is registered by both "
                f"'{original.server_name}' and '{shadow.server_name}'"
            ),
            similarity_score=1.0,
        )

    def _check_typosquat(
        self,
        existing: ToolRegistration,
        new: ToolRegistration,
    ) -> ShadowFinding | None:
        """Check for typosquatting via name similarity."""
        # Check canonical form (strips separators)
        canon_existing = _canonicalize_tool_name(existing.tool_name)
        canon_new = _canonicalize_tool_name(new.tool_name)

        # If canonical forms are identical, it's a separator-variant typosquat
        if canon_existing == canon_new:
            return ShadowFinding(
                category="typosquat",
                severity=Severity.HIGH,
                original=existing,
                shadow=new,
                detail=(
                    f"Tool '{new.tool_name}' is a separator variant of "
                    f"'{existing.tool_name}' (canonical: '{canon_existing}')"
                ),
                similarity_score=0.99,
            )

        # Check Unicode confusable equivalence (before Levenshtein)
        norm_existing = _normalize_confusables(existing.tool_name)
        norm_new = _normalize_confusables(new.tool_name)
        if norm_existing == norm_new and existing.tool_name != new.tool_name:
            return ShadowFinding(
                category="typosquat",
                severity=Severity.HIGH,
                original=existing,
                shadow=new,
                detail=(
                    f"Tool '{new.tool_name}' uses Unicode confusables to mimic "
                    f"'{existing.tool_name}'"
                ),
                similarity_score=0.99,
            )

        # Levenshtein similarity on original names
        ratio = _levenshtein_ratio(existing.tool_name.lower(), new.tool_name.lower())
        if ratio >= self._threshold:
            return ShadowFinding(
                category="typosquat",
                severity=Severity.HIGH,
                original=existing,
                shadow=new,
                detail=(
                    f"Tool '{new.tool_name}' is similar to "
                    f"'{existing.tool_name}' (similarity: {ratio:.2f})"
                ),
                similarity_score=ratio,
            )

        return None

    def _check_description_override(
        self,
        existing: ToolRegistration,
        new: ToolRegistration,
    ) -> ShadowFinding | None:
        """Check if the new tool's description contains manipulative language."""
        if not new.description:
            return None

        # Reuse the ToolDescriptionScanner pattern detection
        poisoning_findings = self._scanner.scan(
            new.tool_name,
            new.description,
            new.schema,
            server_name=new.server_name,
        )
        if poisoning_findings:
            return ShadowFinding(
                category="description_override",
                severity=Severity.MEDIUM,
                original=existing,
                shadow=new,
                detail=(
                    f"Tool '{new.tool_name}' from '{new.server_name}' has "
                    f"manipulative description patterns: "
                    f"{', '.join(f.pattern_name for f in poisoning_findings)}"
                ),
                similarity_score=1.0,
            )

        return None

    def _check_capability_claim(
        self,
        existing: ToolRegistration,
        new: ToolRegistration,
    ) -> ShadowFinding | None:
        """Check if the new tool claims capabilities of the existing tool."""
        existing_caps = _extract_capabilities(existing.description)
        new_caps = _extract_capabilities(new.description)

        if not existing_caps or not new_caps:
            return None

        overlap = existing_caps & new_caps
        if not overlap:
            return None

        # Require at least 2 overlapping capabilities or >50% of existing
        min_overlap = max(2, len(existing_caps) // 2)
        if len(overlap) < min_overlap:
            return None

        overlap_strs = [f"{v} {o}" for v, o in sorted(overlap)[:5]]
        return ShadowFinding(
            category="capability_claim",
            severity=Severity.MEDIUM,
            original=existing,
            shadow=new,
            detail=(
                f"Tool '{new.tool_name}' from '{new.server_name}' claims "
                f"capabilities of '{existing.tool_name}' from "
                f"'{existing.server_name}': {', '.join(overlap_strs)}"
            ),
            similarity_score=len(overlap) / max(len(existing_caps), 1),
        )
