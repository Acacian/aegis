"""Merkle tree audit log for efficient subset verification.

Extends the :mod:`aegis.core.crypto_audit` hash-chain with a Merkle tree
structure, enabling O(log n) inclusion proofs for individual audit entries
without downloading or verifying the entire chain.

Inspired by the "Right to History" framework (arXiv:2602.20214), which
proposes Merkle-based audit logs for AI agent interactions so that any
party can independently verify that a specific action was recorded.

Key capabilities:

- **Inclusion proofs**: Generate a compact proof that a specific audit
  entry is part of the tree (O(log n) hashes).
- **Proof verification**: Stateless verification given only the proof
  and the root hash — no access to the full tree required.
- **Batch proofs**: Verify multiple entries in a single pass.
- **Append-only**: New entries extend the tree without invalidating
  existing proofs (only the root hash changes).

No external dependencies.  Thread-safe.

Reference:
    Right to History: Verifiable Audit Trails for AI Agent Interactions.
    arXiv:2602.20214 (2025).

Example::

    tree = MerkleAuditTree()
    idx0 = tree.append("agent-1", "read", "database", "auto", "low")
    idx1 = tree.append("agent-1", "write", "file", "approve", "medium")

    proof = tree.prove(idx0)
    assert MerkleAuditTree.verify_proof(proof, tree.root_hash)

    # Third party can verify without the full tree
    assert MerkleAuditTree.verify_proof(proof, tree.root_hash)
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_EMPTY_HASH = "0" * 64


def _sha256(data: str) -> str:
    """Compute SHA-256 hex digest of a UTF-8 string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _hash_pair(left: str, right: str) -> str:
    """Hash two child hashes into a parent hash.

    Uses domain separation to prevent second-preimage attacks:
    the concatenation is prefixed with ``0x01`` for internal nodes
    (leaf nodes are prefixed with ``0x00`` during entry hashing).
    """
    return _sha256(f"\x01{left}{right}")


def _hash_leaf(data: str) -> str:
    """Hash a leaf node with domain-separated prefix."""
    return _sha256(f"\x00{data}")


def _canonical_json(d: dict[str, Any]) -> str:
    return json.dumps(d, sort_keys=True, separators=(",", ":"))


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MerkleLeaf:
    """A single audit entry stored as a Merkle tree leaf.

    Attributes:
        index: Leaf position (0-indexed).
        timestamp: ISO 8601 timestamp.
        agent_id: Agent that performed the action.
        action_type: Kind of operation.
        action_target: System or resource acted upon.
        decision: Governance decision.
        risk_level: Risk classification.
        metadata: Arbitrary extra context.
        leaf_hash: SHA-256 hash of this leaf's content.
    """

    index: int
    timestamp: str
    agent_id: str
    action_type: str
    action_target: str
    decision: str
    risk_level: str
    metadata: dict[str, Any] = field(default_factory=dict)
    leaf_hash: str = ""


@dataclass(frozen=True)
class MerkleProof:
    """An inclusion proof for a specific leaf.

    Contains the leaf hash plus the sibling hashes needed to
    reconstruct the root.

    Attributes:
        leaf_index: Index of the leaf being proved.
        leaf_hash: Hash of the leaf data.
        siblings: List of ``(hash, direction)`` pairs.
            Direction is ``"left"`` or ``"right"`` indicating
            where the sibling sits relative to the path node.
        tree_size: Total number of leaves when the proof was generated.
        root_hash: Expected root hash.
    """

    leaf_index: int
    leaf_hash: str
    siblings: tuple[tuple[str, str], ...]
    tree_size: int
    root_hash: str


@dataclass(frozen=True)
class BatchProofResult:
    """Result of verifying multiple proofs against a root.

    Attributes:
        all_valid: Whether every proof verified successfully.
        results: Per-index verification results.
        root_hash: The root hash verified against.
    """

    all_valid: bool
    results: dict[int, bool]
    root_hash: str


# ---------------------------------------------------------------------------
# Merkle tree
# ---------------------------------------------------------------------------


class MerkleAuditTree:
    """Append-only Merkle tree for audit entries.

    Thread-safe: all mutations and reads are guarded by a lock.
    """

    def __init__(self) -> None:
        self._leaves: list[MerkleLeaf] = []
        self._leaf_hashes: list[str] = []
        self._lock = threading.Lock()

    # -- properties ----------------------------------------------------------

    def __len__(self) -> int:
        with self._lock:
            return len(self._leaves)

    @property
    def root_hash(self) -> str:
        """Current Merkle root hash. Empty hash if tree is empty."""
        with self._lock:
            return self._compute_root()

    # -- append --------------------------------------------------------------

    def append(
        self,
        agent_id: str,
        action_type: str,
        action_target: str,
        decision: str,
        risk_level: str,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        """Append a new audit entry as a leaf. Returns the leaf index."""
        with self._lock:
            index = len(self._leaves)
            ts = _now_iso()
            meta = dict(metadata) if metadata else {}

            content = _canonical_json(
                {
                    "index": index,
                    "timestamp": ts,
                    "agent_id": agent_id,
                    "action_type": action_type,
                    "action_target": action_target,
                    "decision": decision,
                    "risk_level": risk_level,
                    "metadata": meta,
                }
            )
            lh = _hash_leaf(content)

            leaf = MerkleLeaf(
                index=index,
                timestamp=ts,
                agent_id=agent_id,
                action_type=action_type,
                action_target=action_target,
                decision=decision,
                risk_level=risk_level,
                metadata=meta,
                leaf_hash=lh,
            )
            self._leaves.append(leaf)
            self._leaf_hashes.append(lh)
            return index

    # -- proofs --------------------------------------------------------------

    def prove(self, leaf_index: int) -> MerkleProof:
        """Generate an inclusion proof for the leaf at *leaf_index*.

        Raises:
            IndexError: If *leaf_index* is out of range.
        """
        with self._lock:
            n = len(self._leaf_hashes)
            if leaf_index < 0 or leaf_index >= n:
                msg = f"Leaf index {leaf_index} out of range [0, {n})"
                raise IndexError(msg)

            siblings = self._collect_siblings(leaf_index, list(self._leaf_hashes))
            root = self._compute_root()

            return MerkleProof(
                leaf_index=leaf_index,
                leaf_hash=self._leaf_hashes[leaf_index],
                siblings=tuple(siblings),
                tree_size=n,
                root_hash=root,
            )

    @staticmethod
    def verify_proof(proof: MerkleProof, expected_root: str) -> bool:
        """Verify an inclusion proof against an expected root hash.

        This is a **stateless** operation — no access to the full tree
        is required.

        Args:
            proof: The inclusion proof to verify.
            expected_root: The root hash to verify against.

        Returns:
            ``True`` if the proof is valid.
        """
        current = proof.leaf_hash
        for sibling_hash, direction in proof.siblings:
            if direction == "left":
                current = _hash_pair(sibling_hash, current)
            else:
                current = _hash_pair(current, sibling_hash)
        return current == expected_root

    def verify_batch(self, proofs: list[MerkleProof]) -> BatchProofResult:
        """Verify multiple proofs against the current root.

        Returns:
            A :class:`BatchProofResult` with per-index results.
        """
        root = self.root_hash
        results: dict[int, bool] = {}
        for proof in proofs:
            results[proof.leaf_index] = self.verify_proof(proof, root)
        return BatchProofResult(
            all_valid=all(results.values()),
            results=results,
            root_hash=root,
        )

    # -- queries -------------------------------------------------------------

    def get_leaf(self, index: int) -> MerkleLeaf | None:
        """Get a leaf by index."""
        with self._lock:
            if 0 <= index < len(self._leaves):
                return self._leaves[index]
            return None

    def get_leaves(self, start: int = 0, end: int | None = None) -> list[MerkleLeaf]:
        """Get a slice of leaves."""
        with self._lock:
            return list(self._leaves[start:end])

    # -- serialisation -------------------------------------------------------

    def export_json(self) -> dict[str, Any]:
        """Export the tree state as a JSON-serialisable dict."""
        with self._lock:
            return {
                "root_hash": self._compute_root(),
                "size": len(self._leaves),
                "leaves": [asdict(leaf) for leaf in self._leaves],
            }

    # -- internal tree operations --------------------------------------------

    def _compute_root(self) -> str:
        """Compute Merkle root from current leaf hashes (caller holds lock)."""
        hashes = list(self._leaf_hashes)
        if not hashes:
            return _EMPTY_HASH

        # Pad to next power of 2
        n = len(hashes)
        size = 1 << math.ceil(math.log2(n)) if n > 1 else 1
        hashes.extend([_EMPTY_HASH] * (size - n))

        # Build tree bottom-up
        while len(hashes) > 1:
            next_level: list[str] = []
            for i in range(0, len(hashes), 2):
                next_level.append(_hash_pair(hashes[i], hashes[i + 1]))
            hashes = next_level

        return hashes[0]

    def _collect_siblings(
        self,
        index: int,
        hashes: list[str],
    ) -> list[tuple[str, str]]:
        """Collect sibling hashes for a proof path (caller holds lock).

        Returns list of ``(hash, direction)`` pairs from leaf to root.
        """
        n = len(hashes)
        if n <= 1:
            return []

        # Pad to next power of 2
        size = 1 << math.ceil(math.log2(n)) if n > 1 else 1
        hashes = hashes + [_EMPTY_HASH] * (size - n)

        siblings: list[tuple[str, str]] = []
        level = hashes
        idx = index

        while len(level) > 1:
            if idx % 2 == 0:
                sibling_idx = idx + 1
                siblings.append((level[sibling_idx], "right"))
            else:
                sibling_idx = idx - 1
                siblings.append((level[sibling_idx], "left"))

            # Move to parent level
            next_level: list[str] = []
            for i in range(0, len(level), 2):
                next_level.append(_hash_pair(level[i], level[i + 1]))
            level = next_level
            idx = idx // 2

        return siblings
