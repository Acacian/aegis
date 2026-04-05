"""Score agent actions by reversibility and manage rollback checkpoints.

Inspired by "Learning to Undo: Rollback-Augmented RL with Reversibility
Signals" -- agents should prefer reversible actions and maintain rollback
points so that harmful effects can be undone when possible.

Each action is scored on a 0.0--1.0 scale indicating how easily its
effects can be reversed:

* **1.0 (FULLY_REVERSIBLE)** -- read-only operations, draft saves,
  config toggles that have an inverse toggle.
* **0.3--0.7 (PARTIALLY_REVERSIBLE)** -- file edits (can restore from
  backup), database updates (depends on transaction log), API calls
  that expose an undo endpoint.
* **0.0 (IRREVERSIBLE)** -- permanent deletes without backup, sent
  emails/messages, external payment transactions.

Rollback checkpoints capture a state hash plus the action history so
that ``can_rollback()`` and ``estimate_rollback_cost()`` can reason
about whether returning to a prior state is feasible.

Pure Python, no external dependencies.  Thread-safe, sub-millisecond.

Reference:
    Learning to Undo: Rollback-Augmented RL with Reversibility Signals.
    arXiv:2510.14503 (2025).

Example::

    scorer = ReversibilityScorer()
    result = scorer.score_action("read_file")
    assert result.category == ReversibilityCategory.FULLY_REVERSIBLE

    scorer.create_checkpoint("agent-1", "abc123", ["read_file"])
    assert scorer.can_rollback("agent-1")
"""

from __future__ import annotations

import hashlib
import threading
import time
import uuid
from dataclasses import dataclass
from enum import StrEnum

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ReversibilityCategory(StrEnum):
    """Category of reversibility for an action."""

    FULLY_REVERSIBLE = "fully_reversible"
    PARTIALLY_REVERSIBLE = "partially_reversible"
    IRREVERSIBLE = "irreversible"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Frozen data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReversibilityScore:
    """Immutable reversibility assessment for a single action.

    Attributes:
        action_type: The action that was scored.
        score: Reversibility score from 0.0 (irreversible) to 1.0
            (fully reversible).
        category: Reversibility category derived from the score.
        description: Human-readable explanation of the score.
    """

    action_type: str
    score: float
    category: ReversibilityCategory
    description: str


@dataclass(frozen=True)
class RollbackPoint:
    """Immutable snapshot representing a rollback checkpoint.

    Attributes:
        point_id: Unique identifier for this checkpoint.
        agent_id: Agent that owns this checkpoint.
        timestamp: When the checkpoint was created (monotonic clock).
        state_hash: Hash of the captured state.
        action_history: Actions executed up to this point.
    """

    point_id: str
    agent_id: str
    timestamp: float
    state_hash: str
    action_history: tuple[str, ...]


@dataclass(frozen=True)
class RollbackResult:
    """Immutable result of a rollback attempt.

    Attributes:
        success: Whether the rollback succeeded conceptually.
        rolled_back_actions: Actions that were rolled back.
        remaining_effects: Effects that could not be reversed.
    """

    success: bool
    rolled_back_actions: tuple[str, ...]
    remaining_effects: tuple[str, ...]


@dataclass(frozen=True)
class RollbackCostEstimate:
    """Estimated cost and risk of rolling back to a checkpoint.

    Attributes:
        point_id: The checkpoint being evaluated.
        actions_to_undo: Number of actions that would need to be undone.
        reversible_count: How many of those actions are reversible.
        irreversible_count: How many are irreversible.
        estimated_risk: Risk score from 0.0 (safe) to 1.0 (very risky).
        feasible: Whether rollback appears feasible.
        description: Human-readable assessment.
    """

    point_id: str
    actions_to_undo: int
    reversible_count: int
    irreversible_count: int
    estimated_risk: float
    feasible: bool
    description: str


# ---------------------------------------------------------------------------
# Built-in reversibility database
# ---------------------------------------------------------------------------

_ActionEntry = tuple[float, ReversibilityCategory, str]

# Canonical action -> (score, category, description)
_BUILTIN_ACTIONS: dict[str, _ActionEntry] = {
    # FULLY_REVERSIBLE (1.0)
    "read_file": (1.0, ReversibilityCategory.FULLY_REVERSIBLE, "Read-only, no side effects"),
    "read": (1.0, ReversibilityCategory.FULLY_REVERSIBLE, "Read-only, no side effects"),
    "list_files": (1.0, ReversibilityCategory.FULLY_REVERSIBLE, "Read-only directory listing"),
    "list_directory": (1.0, ReversibilityCategory.FULLY_REVERSIBLE, "Read-only directory listing"),
    "search": (1.0, ReversibilityCategory.FULLY_REVERSIBLE, "Search operation, no mutation"),
    "grep": (1.0, ReversibilityCategory.FULLY_REVERSIBLE, "Text search, no mutation"),
    "get_status": (1.0, ReversibilityCategory.FULLY_REVERSIBLE, "Status query, no mutation"),
    "query": (1.0, ReversibilityCategory.FULLY_REVERSIBLE, "Read-only query"),
    "draft_save": (1.0, ReversibilityCategory.FULLY_REVERSIBLE, "Draft can be discarded"),
    "config_toggle": (1.0, ReversibilityCategory.FULLY_REVERSIBLE, "Toggle has inverse operation"),
    "preview": (1.0, ReversibilityCategory.FULLY_REVERSIBLE, "Preview only, no commit"),
    "validate": (1.0, ReversibilityCategory.FULLY_REVERSIBLE, "Validation check, no mutation"),
    "git_status": (1.0, ReversibilityCategory.FULLY_REVERSIBLE, "Git status is read-only"),
    "git_log": (1.0, ReversibilityCategory.FULLY_REVERSIBLE, "Git log is read-only"),
    "git_diff": (1.0, ReversibilityCategory.FULLY_REVERSIBLE, "Git diff is read-only"),
    # PARTIALLY_REVERSIBLE (0.3--0.7)
    "edit_file": (
        0.7,
        ReversibilityCategory.PARTIALLY_REVERSIBLE,
        "Can restore from backup or VCS",
    ),
    "write_file": (
        0.6,
        ReversibilityCategory.PARTIALLY_REVERSIBLE,
        "Can restore if backup exists",
    ),
    "create_file": (0.7, ReversibilityCategory.PARTIALLY_REVERSIBLE, "Can delete to undo"),
    "rename_file": (0.7, ReversibilityCategory.PARTIALLY_REVERSIBLE, "Can rename back"),
    "move_file": (0.7, ReversibilityCategory.PARTIALLY_REVERSIBLE, "Can move back"),
    "db_update": (0.5, ReversibilityCategory.PARTIALLY_REVERSIBLE, "Depends on transaction log"),
    "db_insert": (0.6, ReversibilityCategory.PARTIALLY_REVERSIBLE, "Can delete inserted rows"),
    "api_put": (0.5, ReversibilityCategory.PARTIALLY_REVERSIBLE, "Depends on API undo support"),
    "api_patch": (0.5, ReversibilityCategory.PARTIALLY_REVERSIBLE, "Depends on API undo support"),
    "git_commit": (0.7, ReversibilityCategory.PARTIALLY_REVERSIBLE, "Can git revert"),
    "git_branch": (0.8, ReversibilityCategory.PARTIALLY_REVERSIBLE, "Can delete branch"),
    "git_stash": (0.8, ReversibilityCategory.PARTIALLY_REVERSIBLE, "Can pop or drop stash"),
    "chmod": (0.6, ReversibilityCategory.PARTIALLY_REVERSIBLE, "Can restore permissions"),
    "config_change": (
        0.6,
        ReversibilityCategory.PARTIALLY_REVERSIBLE,
        "Can restore previous config",
    ),
    "install_package": (
        0.5,
        ReversibilityCategory.PARTIALLY_REVERSIBLE,
        "Can uninstall, may have side effects",
    ),
    "create_directory": (0.7, ReversibilityCategory.PARTIALLY_REVERSIBLE, "Can remove directory"),
    # IRREVERSIBLE (0.0)
    "delete_no_backup": (0.0, ReversibilityCategory.IRREVERSIBLE, "Permanent delete, no recovery"),
    "send_email": (0.0, ReversibilityCategory.IRREVERSIBLE, "Email sent, cannot unsend"),
    "send_message": (0.0, ReversibilityCategory.IRREVERSIBLE, "Message delivered, cannot recall"),
    "api_post_external": (0.0, ReversibilityCategory.IRREVERSIBLE, "External POST, no undo"),
    "payment_transaction": (
        0.0,
        ReversibilityCategory.IRREVERSIBLE,
        "Financial transaction committed",
    ),
    "publish": (0.0, ReversibilityCategory.IRREVERSIBLE, "Published content is public"),
    "deploy_production": (
        0.1,
        ReversibilityCategory.IRREVERSIBLE,
        "May be rollback-able but risky",
    ),
    "drop_table": (0.0, ReversibilityCategory.IRREVERSIBLE, "Database table destroyed"),
    "format_disk": (0.0, ReversibilityCategory.IRREVERSIBLE, "Disk formatted, data lost"),
    "git_push_force": (
        0.1,
        ReversibilityCategory.IRREVERSIBLE,
        "Force push rewrites remote history",
    ),
    "rm_rf": (0.0, ReversibilityCategory.IRREVERSIBLE, "Recursive delete, no recovery"),
    "truncate_table": (0.0, ReversibilityCategory.IRREVERSIBLE, "Table data destroyed"),
    "broadcast": (0.0, ReversibilityCategory.IRREVERSIBLE, "Message broadcast, cannot recall"),
    "revoke_access": (
        0.1,
        ReversibilityCategory.IRREVERSIBLE,
        "Access revoked, may cause disruption",
    ),
}

# Keyword-based fallback matching: (keyword, score, category, description)
_KEYWORD_RULES: list[tuple[str, float, ReversibilityCategory, str]] = [
    ("read", 1.0, ReversibilityCategory.FULLY_REVERSIBLE, "Read-like operation"),
    ("get", 1.0, ReversibilityCategory.FULLY_REVERSIBLE, "Getter operation"),
    ("list", 1.0, ReversibilityCategory.FULLY_REVERSIBLE, "Listing operation"),
    ("search", 1.0, ReversibilityCategory.FULLY_REVERSIBLE, "Search operation"),
    ("query", 1.0, ReversibilityCategory.FULLY_REVERSIBLE, "Query operation"),
    ("check", 1.0, ReversibilityCategory.FULLY_REVERSIBLE, "Check operation"),
    ("validate", 1.0, ReversibilityCategory.FULLY_REVERSIBLE, "Validation operation"),
    ("delete", 0.1, ReversibilityCategory.IRREVERSIBLE, "Delete operation"),
    ("remove", 0.2, ReversibilityCategory.IRREVERSIBLE, "Remove operation"),
    ("drop", 0.0, ReversibilityCategory.IRREVERSIBLE, "Drop operation"),
    ("send", 0.0, ReversibilityCategory.IRREVERSIBLE, "Send operation"),
    ("publish", 0.0, ReversibilityCategory.IRREVERSIBLE, "Publish operation"),
    ("deploy", 0.1, ReversibilityCategory.IRREVERSIBLE, "Deploy operation"),
    ("edit", 0.6, ReversibilityCategory.PARTIALLY_REVERSIBLE, "Edit operation"),
    ("write", 0.6, ReversibilityCategory.PARTIALLY_REVERSIBLE, "Write operation"),
    ("update", 0.5, ReversibilityCategory.PARTIALLY_REVERSIBLE, "Update operation"),
    ("create", 0.7, ReversibilityCategory.PARTIALLY_REVERSIBLE, "Create operation"),
    ("install", 0.5, ReversibilityCategory.PARTIALLY_REVERSIBLE, "Install operation"),
]


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------


class ReversibilityScorer:
    """Score agent actions by reversibility and manage rollback checkpoints.

    Maintains a database of action types and their reversibility scores.
    Custom actions can be registered at runtime.  Checkpoints capture
    a state hash and action history for rollback reasoning.

    Thread-safe: all mutations are guarded by an internal lock.

    Args:
        max_checkpoints: Maximum checkpoints to keep per agent.
    """

    def __init__(self, *, max_checkpoints: int = 100) -> None:
        self._max_checkpoints = max_checkpoints
        self._custom_actions: dict[str, _ActionEntry] = {}
        self._checkpoints: dict[str, list[RollbackPoint]] = {}  # agent_id -> list
        self._lock = threading.Lock()

    # -- scoring -------------------------------------------------------------

    def score_action(self, action_type: str) -> ReversibilityScore:
        """Score a single action's reversibility.

        Looks up the action in the built-in database first, then custom
        registrations, then falls back to keyword matching.

        Args:
            action_type: Identifier for the action (e.g. ``"read_file"``).

        Returns:
            A frozen :class:`ReversibilityScore`.
        """
        normalized = action_type.strip().lower()

        # 1. Exact match in custom actions
        with self._lock:
            entry = self._custom_actions.get(normalized)
        if entry is not None:
            return ReversibilityScore(
                action_type=action_type,
                score=entry[0],
                category=entry[1],
                description=entry[2],
            )

        # 2. Exact match in built-in database
        entry = _BUILTIN_ACTIONS.get(normalized)
        if entry is not None:
            return ReversibilityScore(
                action_type=action_type,
                score=entry[0],
                category=entry[1],
                description=entry[2],
            )

        # 3. Keyword fallback
        for keyword, score, category, desc in _KEYWORD_RULES:
            if keyword in normalized:
                return ReversibilityScore(
                    action_type=action_type,
                    score=score,
                    category=category,
                    description=desc,
                )

        # 4. Unknown
        return ReversibilityScore(
            action_type=action_type,
            score=0.5,
            category=ReversibilityCategory.UNKNOWN,
            description="Action type not recognized; defaulting to uncertain",
        )

    def score_actions(self, action_types: list[str]) -> list[ReversibilityScore]:
        """Score multiple actions at once.

        Args:
            action_types: List of action identifiers.

        Returns:
            List of :class:`ReversibilityScore` in the same order.
        """
        return [self.score_action(a) for a in action_types]

    # -- checkpoint management -----------------------------------------------

    def create_checkpoint(
        self,
        agent_id: str,
        state_hash: str,
        action_history: list[str],
    ) -> RollbackPoint:
        """Save a rollback checkpoint.

        Args:
            agent_id: Agent that owns this checkpoint.
            state_hash: Hash representing the current state.
            action_history: Actions taken up to this point.

        Returns:
            The created :class:`RollbackPoint`.
        """
        point = RollbackPoint(
            point_id=uuid.uuid4().hex[:16],
            agent_id=agent_id,
            timestamp=time.monotonic(),
            state_hash=state_hash,
            action_history=tuple(action_history),
        )
        with self._lock:
            if agent_id not in self._checkpoints:
                self._checkpoints[agent_id] = []
            cps = self._checkpoints[agent_id]
            cps.append(point)
            # Evict oldest if over limit
            if len(cps) > self._max_checkpoints:
                self._checkpoints[agent_id] = cps[-self._max_checkpoints :]
        return point

    def can_rollback(self, agent_id: str, point_id: str | None = None) -> bool:
        """Check if rollback to a checkpoint is possible.

        If *point_id* is ``None``, checks whether the agent has any
        checkpoint.  If a specific *point_id* is given, checks whether
        that checkpoint exists and all actions since are at least
        partially reversible.

        Args:
            agent_id: Agent to check.
            point_id: Optional specific checkpoint ID.

        Returns:
            ``True`` if rollback appears feasible.
        """
        with self._lock:
            cps = self._checkpoints.get(agent_id)
            if not cps:
                return False
            if point_id is None:
                return True
            # Find the checkpoint
            target_idx = None
            for idx, cp in enumerate(cps):
                if cp.point_id == point_id:
                    target_idx = idx
                    break
            if target_idx is None:
                return False

        # Check actions after the checkpoint in the latest checkpoint
        target_cp = cps[target_idx]
        if target_idx < len(cps) - 1:
            latest = cps[-1]
            actions_since = latest.action_history[len(target_cp.action_history) :]
        else:
            actions_since = ()

        for action in actions_since:
            score = self.score_action(action)
            if score.category == ReversibilityCategory.IRREVERSIBLE:
                return False
        return True

    def estimate_rollback_cost(
        self,
        agent_id: str,
        point_id: str,
    ) -> RollbackCostEstimate:
        """Estimate effort and risk of rolling back to a checkpoint.

        Args:
            agent_id: Agent that owns the checkpoint.
            point_id: Checkpoint to evaluate.

        Returns:
            A :class:`RollbackCostEstimate` with feasibility assessment.
        """
        with self._lock:
            cps = self._checkpoints.get(agent_id, [])
            target_cp: RollbackPoint | None = None
            target_idx: int | None = None
            for idx, cp in enumerate(cps):
                if cp.point_id == point_id:
                    target_cp = cp
                    target_idx = idx
                    break

        if target_cp is None:
            return RollbackCostEstimate(
                point_id=point_id,
                actions_to_undo=0,
                reversible_count=0,
                irreversible_count=0,
                estimated_risk=1.0,
                feasible=False,
                description="Checkpoint not found",
            )

        # Determine actions to undo: those between target and latest
        with self._lock:
            if target_idx is not None and target_idx < len(cps) - 1:
                latest = cps[-1]
                actions_since = list(latest.action_history[len(target_cp.action_history) :])
            else:
                actions_since = []

        reversible = 0
        irreversible = 0
        total_score = 0.0

        for action in actions_since:
            s = self.score_action(action)
            if s.category == ReversibilityCategory.IRREVERSIBLE:
                irreversible += 1
            else:
                reversible += 1
            total_score += s.score

        n = len(actions_since)
        if n == 0:
            risk = 0.0
            feasible = True
            desc = "No actions to undo"
        else:
            avg_score = total_score / n
            risk = round(1.0 - avg_score, 3)
            feasible = irreversible == 0
            if feasible:
                desc = f"All {n} actions are reversible"
            else:
                desc = f"{irreversible} of {n} actions are irreversible"

        return RollbackCostEstimate(
            point_id=point_id,
            actions_to_undo=n,
            reversible_count=reversible,
            irreversible_count=irreversible,
            estimated_risk=risk,
            feasible=feasible,
            description=desc,
        )

    def get_checkpoints(self, agent_id: str) -> list[RollbackPoint]:
        """Return all checkpoints for an agent.

        Args:
            agent_id: Agent to query.

        Returns:
            List of :class:`RollbackPoint` (oldest first).
        """
        with self._lock:
            return list(self._checkpoints.get(agent_id, []))

    # -- custom action registration ------------------------------------------

    def register_action_reversibility(
        self,
        action_type: str,
        score: float,
        category: ReversibilityCategory,
        description: str = "",
    ) -> None:
        """Register a domain-specific action with its reversibility score.

        Args:
            action_type: Action identifier.
            score: Reversibility score (0.0--1.0).
            category: Reversibility category.
            description: Human-readable description.

        Raises:
            ValueError: If *score* is outside [0.0, 1.0].
        """
        if not 0.0 <= score <= 1.0:
            msg = f"Score must be between 0.0 and 1.0, got {score}"
            raise ValueError(msg)
        normalized = action_type.strip().lower()
        with self._lock:
            self._custom_actions[normalized] = (
                score,
                category,
                description or f"Custom action: {action_type}",
            )

    # -- utility -------------------------------------------------------------

    @staticmethod
    def compute_state_hash(*parts: str) -> str:
        """Compute a SHA-256 hash from arbitrary string parts.

        Convenience method for building ``state_hash`` values.

        Args:
            *parts: String fragments to hash together.

        Returns:
            Hex-encoded SHA-256 digest.
        """
        h = hashlib.sha256()
        for p in parts:
            h.update(p.encode())
        return h.hexdigest()
