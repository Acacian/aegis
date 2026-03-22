"""Policy versioning and history system.

Tracks policy changes over time with git-like semantics: commit,
diff, rollback, and tagging.  Designed for enterprise change management
(SOC 2 CC8.1) and regulatory compliance audit trails.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyVersion:
    """Immutable snapshot of a policy at a point in time."""

    version_id: str
    version_number: int
    created_at: str
    author: str
    message: str
    policy_hash: str
    parent_version: str | None
    policy_dict: dict[str, object]


@dataclass(frozen=True)
class PolicyDelta:
    """Structured diff between two policy versions."""

    version_from: str
    version_to: str
    rules_added: list[str]
    rules_removed: list[str]
    rules_modified: list[str]
    defaults_changed: dict[str, tuple[str, str]]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _policy_to_dict(policy: object) -> dict[str, object]:
    """Convert a Policy instance to a serialisable dictionary.

    We avoid importing ``Policy`` directly so this module has zero
    coupling to YAML or heavy dependencies.  The function inspects
    the object's attributes to build the dict.
    """
    # ``Policy`` objects have ``rules``, ``default_risk_level``, etc.
    rules_list: list[dict[str, object]] = []
    for rule in getattr(policy, "rules", []):
        rule_dict: dict[str, object] = {
            "name": rule.name,
            "match": {
                "type": rule.match_type,
                "target": rule.match_target,
                "agent": rule.match_agent,
            },
            "risk_level": rule.risk_level.name.lower(),
            "approval": rule.approval.value,
        }
        if rule.conditions:
            rule_dict["conditions"] = rule.conditions
        rules_list.append(rule_dict)

    raw_risk = getattr(policy, "default_risk_level", "medium")
    risk_str: str = raw_risk if isinstance(raw_risk, str) else raw_risk.name.lower()

    raw_approval = getattr(policy, "default_approval", "approve")
    approval_str: str = raw_approval if isinstance(raw_approval, str) else raw_approval.value

    result: dict[str, object] = {
        "version": str(getattr(policy, "version", 1)),
        "defaults": {
            "risk_level": risk_str,
            "approval": approval_str,
        },
        "scope": getattr(policy, "scope", "global"),
        "scope_id": getattr(policy, "scope_id", ""),
    }
    if rules_list:
        result["rules"] = rules_list
    return result


def _hash_dict(d: dict[str, object]) -> str:
    """Deterministic SHA-256 hash of a JSON-serialisable dictionary."""
    canonical = json.dumps(d, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _version_to_serialisable(v: PolicyVersion) -> dict[str, object]:
    """Convert a ``PolicyVersion`` to a JSON-safe dictionary."""
    return {
        "version_id": v.version_id,
        "version_number": v.version_number,
        "created_at": v.created_at,
        "author": v.author,
        "message": v.message,
        "policy_hash": v.policy_hash,
        "parent_version": v.parent_version,
        "policy_dict": v.policy_dict,
    }


def _version_from_dict(d: dict[str, Any]) -> PolicyVersion:
    """Reconstruct a ``PolicyVersion`` from a deserialised dictionary."""
    return PolicyVersion(
        version_id=d["version_id"],
        version_number=d["version_number"],
        created_at=d["created_at"],
        author=d["author"],
        message=d["message"],
        policy_hash=d["policy_hash"],
        parent_version=d.get("parent_version"),
        policy_dict=d["policy_dict"],
    )


def _extract_rule_names(policy_dict: dict[str, object]) -> set[str]:
    """Return rule names present in a policy dictionary."""
    rules: list[dict[str, object]] = policy_dict.get("rules", [])  # type: ignore[assignment]
    return {str(r.get("name", "")) for r in rules}


def _rules_by_name(policy_dict: dict[str, object]) -> dict[str, dict[str, object]]:
    """Index rules by name for comparison."""
    rules: list[dict[str, object]] = policy_dict.get("rules", [])  # type: ignore[assignment]
    return {str(r.get("name", "")): r for r in rules}


# ---------------------------------------------------------------------------
# PolicyStore
# ---------------------------------------------------------------------------


class PolicyStore:
    """Thread-safe, optionally persistent store for policy versions.

    Implements git-like semantics: commit, diff, rollback, and tagging.
    When *store_path* is provided, ``save()`` and ``load()`` persist the
    full history to a JSON file.
    """

    def __init__(self, store_path: Path | None = None) -> None:
        self._store_path = store_path
        self._versions: list[PolicyVersion] = []
        self._versions_by_id: dict[str, PolicyVersion] = {}
        self._tags: dict[str, str] = {}  # tag -> version_id
        self._lock = threading.Lock()

    # -- core operations ----------------------------------------------------

    def commit(self, policy: object, author: str, message: str) -> PolicyVersion:
        """Create a new policy version (like ``git commit``).

        Args:
            policy: A ``Policy`` instance or any object whose attributes
                    can be serialised by ``_policy_to_dict``.
            author: Who made the change.
            message: Human-readable description of the change.

        Returns:
            The newly created ``PolicyVersion``.
        """
        policy_dict = _policy_to_dict(policy)
        policy_hash = _hash_dict(policy_dict)

        with self._lock:
            parent = self._versions[-1].version_id if self._versions else None
            version_number = len(self._versions) + 1
            version = PolicyVersion(
                version_id=uuid.uuid4().hex,
                version_number=version_number,
                created_at=datetime.now(UTC).isoformat(),
                author=author,
                message=message,
                policy_hash=policy_hash,
                parent_version=parent,
                policy_dict=policy_dict,
            )
            self._versions.append(version)
            self._versions_by_id[version.version_id] = version
            return version

    def get_version(self, version_id: str) -> PolicyVersion | None:
        """Look up a version by its ID."""
        with self._lock:
            return self._versions_by_id.get(version_id)

    def get_latest(self) -> PolicyVersion | None:
        """Return the most recent version, or ``None`` for an empty store."""
        with self._lock:
            return self._versions[-1] if self._versions else None

    def get_history(self, limit: int = 50) -> list[PolicyVersion]:
        """Return versions newest-first, up to *limit* entries."""
        with self._lock:
            return list(reversed(self._versions[-limit:]))

    # -- diff / rollback ----------------------------------------------------

    def diff(self, version_a: str, version_b: str) -> PolicyDelta:
        """Compute the delta between two versions.

        *version_a* is treated as the "old" side and *version_b* as "new".

        Raises:
            KeyError: If either version ID is unknown.
        """
        with self._lock:
            va = self._versions_by_id.get(version_a)
            vb = self._versions_by_id.get(version_b)
        if va is None:
            raise KeyError(f"Unknown version: {version_a}")
        if vb is None:
            raise KeyError(f"Unknown version: {version_b}")

        names_a = _extract_rule_names(va.policy_dict)
        names_b = _extract_rule_names(vb.policy_dict)

        rules_a = _rules_by_name(va.policy_dict)
        rules_b = _rules_by_name(vb.policy_dict)

        added = sorted(names_b - names_a)
        removed = sorted(names_a - names_b)

        modified: list[str] = []
        for name in sorted(names_a & names_b):
            if rules_a[name] != rules_b[name]:
                modified.append(name)

        # Compare defaults
        defaults_a: dict[str, str] = va.policy_dict.get("defaults", {})  # type: ignore[assignment]
        defaults_b: dict[str, str] = vb.policy_dict.get("defaults", {})  # type: ignore[assignment]
        defaults_changed: dict[str, tuple[str, str]] = {}
        for key in set(defaults_a) | set(defaults_b):
            old_val = str(defaults_a.get(key, ""))
            new_val = str(defaults_b.get(key, ""))
            if old_val != new_val:
                defaults_changed[key] = (old_val, new_val)

        return PolicyDelta(
            version_from=version_a,
            version_to=version_b,
            rules_added=added,
            rules_removed=removed,
            rules_modified=modified,
            defaults_changed=defaults_changed,
        )

    def rollback(self, version_id: str) -> PolicyVersion:
        """Create a new version that restores the content of *version_id*.

        This is a *forward* rollback: it appends a new entry rather than
        rewriting history, preserving the full audit trail.

        Raises:
            KeyError: If the version ID is unknown.
        """
        with self._lock:
            target = self._versions_by_id.get(version_id)
        if target is None:
            raise KeyError(f"Unknown version: {version_id}")

        # Re-use the target's policy_dict to create a fresh version.
        with self._lock:
            parent = self._versions[-1].version_id if self._versions else None
            version_number = len(self._versions) + 1
            version = PolicyVersion(
                version_id=uuid.uuid4().hex,
                version_number=version_number,
                created_at=datetime.now(UTC).isoformat(),
                author="system",
                message=f"Rollback to version {target.version_number} ({version_id})",
                policy_hash=target.policy_hash,
                parent_version=parent,
                policy_dict=target.policy_dict,
            )
            self._versions.append(version)
            self._versions_by_id[version.version_id] = version
            return version

    # -- tagging ------------------------------------------------------------

    def tag(self, version_id: str, tag: str) -> None:
        """Assign a tag (e.g. ``"production"``) to a version.

        Raises:
            KeyError: If the version ID is unknown.
        """
        with self._lock:
            if version_id not in self._versions_by_id:
                raise KeyError(f"Unknown version: {version_id}")
            self._tags[tag] = version_id

    def get_by_tag(self, tag: str) -> PolicyVersion | None:
        """Look up the version associated with *tag*."""
        with self._lock:
            vid = self._tags.get(tag)
            if vid is None:
                return None
            return self._versions_by_id.get(vid)

    # -- persistence --------------------------------------------------------

    def save(self) -> None:
        """Persist the store to the JSON file specified at construction.

        Raises:
            RuntimeError: If no *store_path* was provided.
        """
        if self._store_path is None:
            raise RuntimeError("No store_path configured for persistence")
        with self._lock:
            data: dict[str, object] = {
                "versions": [_version_to_serialisable(v) for v in self._versions],
                "tags": dict(self._tags),
            }
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        self._store_path.write_text(
            json.dumps(data, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def load(self) -> None:
        """Load the store from the JSON file specified at construction.

        Raises:
            RuntimeError: If no *store_path* was provided.
            FileNotFoundError: If the file does not exist.
        """
        if self._store_path is None:
            raise RuntimeError("No store_path configured for persistence")
        raw = json.loads(self._store_path.read_text(encoding="utf-8"))
        with self._lock:
            self._versions = [_version_from_dict(v) for v in raw["versions"]]
            self._versions_by_id = {v.version_id: v for v in self._versions}
            self._tags = dict(raw.get("tags", {}))
