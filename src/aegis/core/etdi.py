"""Enhanced Tool Definition Interface (ETDI) -- tool versioning and permissions.

Implements version pinning, rug-pull detection, and permission scope
checking for MCP tool definitions.  Tools declare their required
permissions at registration time; subsequent invocations are verified
against those declarations to prevent privilege escalation.

Key components:

* **ETDIVerifier** -- Central verifier that manages version pins and
  permission policies.
* **ToolDefinitionRecord** -- Immutable snapshot of a tool's identity,
  version, permissions, and lifecycle timestamps.
* **VersionPin** -- Pins a tool to a specific version + hash so that
  schema changes (rug pulls) can be detected.

Permission model: ``read``, ``write``, ``network``, ``exec``, ``fs``.
OAuth-style scope checking compares *declared* vs *requested* scopes
without requiring an actual OAuth flow.

Thread-safe: all mutable state is guarded by :class:`threading.Lock`.

Reference:
    ETDI: Enhanced Tool Definition Interface.
    arXiv:2506.01333 (2025).

Example::

    verifier = ETDIVerifier()
    record = verifier.register(
        "read_file", "1.0.0", {"type": "object"}, {"read", "fs"},
    )
    verifier.pin_version("read_file")
    violation = verifier.check_version("read_file", {"type": "object"})
    assert violation is None
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

# ---------------------------------------------------------------------------
# Permission model
# ---------------------------------------------------------------------------


class Permission(StrEnum):
    """MCP tool permission scopes."""

    READ = "read"
    WRITE = "write"
    NETWORK = "network"
    EXEC = "exec"
    FS = "fs"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolDefinitionRecord:
    """Immutable record of a registered tool definition.

    Attributes:
        tool_id: Unique tool identifier (usually ``server::tool_name``).
        name: Human-readable tool name.
        version: Semantic version string.
        schema_hash: SHA-256 hex digest of the canonical schema JSON.
        permissions: Set of declared permission scopes.
        created_at: Unix epoch when the tool was registered.
        deprecated_at: Unix epoch when the tool was deprecated (0.0 if active).
    """

    tool_id: str
    name: str
    version: str
    schema_hash: str
    permissions: frozenset[Permission]
    created_at: float
    deprecated_at: float = 0.0


@dataclass(frozen=True)
class VersionPin:
    """A version pin that locks a tool to a specific version and hash.

    Attributes:
        tool_id: Tool identifier.
        pinned_version: The version that was pinned.
        pinned_hash: The schema hash at pin time.
        policy: Pin policy (``"strict"`` or ``"warn"``).
    """

    tool_id: str
    pinned_version: str
    pinned_hash: str
    policy: str = "strict"


@dataclass(frozen=True)
class ETDIViolation:
    """A detected ETDI policy violation.

    Attributes:
        tool_id: Tool that violated the policy.
        violation_type: Category of violation (``"version_mismatch"``,
            ``"hash_mismatch"``, ``"permission_escalation"``,
            ``"unregistered_tool"``, ``"deprecated_tool"``).
        description: Human-readable explanation.
    """

    tool_id: str
    violation_type: str
    description: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _canonical_schema(schema: dict[str, Any] | None) -> str:
    return json.dumps(schema or {}, sort_keys=True, separators=(",", ":"))


def _schema_hash(schema: dict[str, Any] | None) -> str:
    return hashlib.sha256(_canonical_schema(schema).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# ETDIVerifier
# ---------------------------------------------------------------------------


class ETDIVerifier:
    """Tool definition verifier with version pinning and permission checks.

    Manages a registry of tool definitions, allows version pinning,
    and enforces permission scope policies.

    Args:
        default_pin_policy: Default policy for new version pins
            (``"strict"`` blocks, ``"warn"`` logs).
    """

    def __init__(self, *, default_pin_policy: str = "strict") -> None:
        self._default_policy = default_pin_policy
        self._records: dict[str, ToolDefinitionRecord] = {}
        self._pins: dict[str, VersionPin] = {}
        self._lock = threading.Lock()

    # -- registration -------------------------------------------------------

    def register(
        self,
        name: str,
        version: str,
        schema: dict[str, Any] | None = None,
        permissions: set[str] | frozenset[str] | None = None,
        *,
        tool_id: str | None = None,
    ) -> ToolDefinitionRecord:
        """Register a tool definition.

        Args:
            name: Tool name.
            version: Semantic version string.
            schema: JSON Schema for input parameters.
            permissions: Set of permission scope strings (must be valid
                :class:`Permission` values).
            tool_id: Optional explicit ID; defaults to *name*.

        Returns:
            The registered :class:`ToolDefinitionRecord`.
        """
        tid = tool_id or name
        perms = frozenset(Permission(p) for p in (permissions or set()))
        sh = _schema_hash(schema)

        record = ToolDefinitionRecord(
            tool_id=tid,
            name=name,
            version=version,
            schema_hash=sh,
            permissions=perms,
            created_at=time.time(),
        )
        with self._lock:
            self._records[tid] = record
        return record

    def deprecate(self, tool_id: str) -> ETDIViolation | None:
        """Mark a tool as deprecated.

        Returns an :class:`ETDIViolation` if the tool is not registered.
        """
        with self._lock:
            rec = self._records.get(tool_id)
            if rec is None:
                return ETDIViolation(
                    tool_id=tool_id,
                    violation_type="unregistered_tool",
                    description=f"Cannot deprecate unknown tool '{tool_id}'",
                )
            # Replace with deprecated copy
            self._records[tool_id] = ToolDefinitionRecord(
                tool_id=rec.tool_id,
                name=rec.name,
                version=rec.version,
                schema_hash=rec.schema_hash,
                permissions=rec.permissions,
                created_at=rec.created_at,
                deprecated_at=time.time(),
            )
        return None

    def is_deprecated(self, tool_id: str) -> bool:
        """Check whether a tool is deprecated."""
        with self._lock:
            rec = self._records.get(tool_id)
            return rec is not None and rec.deprecated_at > 0.0

    # -- version pinning ----------------------------------------------------

    def pin_version(
        self,
        tool_id: str,
        *,
        policy: str | None = None,
    ) -> VersionPin | ETDIViolation:
        """Pin the current version and schema hash of a tool.

        Args:
            tool_id: Tool to pin.
            policy: ``"strict"`` (default) or ``"warn"``.

        Returns:
            A :class:`VersionPin` on success, or an :class:`ETDIViolation`
            if the tool is not registered.
        """
        with self._lock:
            rec = self._records.get(tool_id)
            if rec is None:
                return ETDIViolation(
                    tool_id=tool_id,
                    violation_type="unregistered_tool",
                    description=f"Cannot pin unknown tool '{tool_id}'",
                )
            pin = VersionPin(
                tool_id=tool_id,
                pinned_version=rec.version,
                pinned_hash=rec.schema_hash,
                policy=policy or self._default_policy,
            )
            self._pins[tool_id] = pin
            return pin

    def is_pinned(self, tool_id: str) -> bool:
        """Check whether a tool is version-pinned."""
        with self._lock:
            return tool_id in self._pins

    # -- version checking (rug-pull detection) -------------------------------

    def check_version(
        self,
        tool_id: str,
        current_schema: dict[str, Any] | None = None,
        *,
        current_version: str | None = None,
    ) -> ETDIViolation | None:
        """Verify a tool has not been modified since pinning.

        This is the core rug-pull detection mechanism.  Compares the
        current schema hash (and optionally version) against the pin.

        Args:
            tool_id: Tool to check.
            current_schema: The tool's current JSON Schema.
            current_version: Optionally check version string too.

        Returns:
            An :class:`ETDIViolation` if the tool has changed, ``None``
            if clean or not pinned.
        """
        with self._lock:
            pin = self._pins.get(tool_id)

        if pin is None:
            return None  # Not pinned — nothing to check

        if current_version is not None and current_version != pin.pinned_version:
            return ETDIViolation(
                tool_id=tool_id,
                violation_type="version_mismatch",
                description=(
                    f"Tool '{tool_id}' version changed: "
                    f"pinned={pin.pinned_version}, current={current_version}"
                ),
            )

        if current_schema is not None:
            current_hash = _schema_hash(current_schema)
            if current_hash != pin.pinned_hash:
                return ETDIViolation(
                    tool_id=tool_id,
                    violation_type="hash_mismatch",
                    description=(
                        f"Tool '{tool_id}' schema hash changed: "
                        f"pinned={pin.pinned_hash[:16]}..., "
                        f"current={current_hash[:16]}..."
                    ),
                )

        return None

    # -- permission checking ------------------------------------------------

    def check_permissions(
        self,
        tool_id: str,
        requested: set[str] | frozenset[str],
    ) -> ETDIViolation | None:
        """Verify a tool's requested permissions against its declaration.

        OAuth-style scope comparison: the tool may only use permissions
        that it originally declared at registration.

        Args:
            tool_id: Tool to check.
            requested: Set of permission scope strings being requested.

        Returns:
            An :class:`ETDIViolation` if the tool requests more than
            declared, ``None`` if within bounds.
        """
        with self._lock:
            rec = self._records.get(tool_id)

        if rec is None:
            return ETDIViolation(
                tool_id=tool_id,
                violation_type="unregistered_tool",
                description=f"Cannot check permissions for unregistered tool '{tool_id}'",
            )

        requested_perms = frozenset(Permission(p) for p in requested)
        escalated = requested_perms - rec.permissions
        if escalated:
            return ETDIViolation(
                tool_id=tool_id,
                violation_type="permission_escalation",
                description=(
                    f"Tool '{tool_id}' requests undeclared permissions: "
                    f"{sorted(str(p) for p in escalated)}. "
                    f"Declared: {sorted(str(p) for p in rec.permissions)}"
                ),
            )
        return None

    def check_deprecated(self, tool_id: str) -> ETDIViolation | None:
        """Return a violation if the tool has been deprecated."""
        with self._lock:
            rec = self._records.get(tool_id)

        if rec is None:
            return ETDIViolation(
                tool_id=tool_id,
                violation_type="unregistered_tool",
                description=f"Tool '{tool_id}' is not registered",
            )

        if rec.deprecated_at > 0.0:
            return ETDIViolation(
                tool_id=tool_id,
                violation_type="deprecated_tool",
                description=f"Tool '{tool_id}' was deprecated at {rec.deprecated_at}",
            )
        return None

    # -- inspection ---------------------------------------------------------

    def get_record(self, tool_id: str) -> ToolDefinitionRecord | None:
        """Return the registered record for a tool, or ``None``."""
        with self._lock:
            return self._records.get(tool_id)

    def get_pin(self, tool_id: str) -> VersionPin | None:
        """Return the version pin for a tool, or ``None``."""
        with self._lock:
            return self._pins.get(tool_id)

    def list_tools(self) -> list[ToolDefinitionRecord]:
        """Return all registered tool records."""
        with self._lock:
            return list(self._records.values())

    def list_pins(self) -> list[VersionPin]:
        """Return all active version pins."""
        with self._lock:
            return list(self._pins.values())
