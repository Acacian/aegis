"""Trust Calibration -- dynamic approval threshold adjustment.

Uses a simplified contextual-bandit (LinUCB-style) algorithm to learn
optimal approval thresholds from feedback.  When an action request
arrives, the calibrator evaluates context features (risk level, agent
trust, recent success rate) and decides whether to auto-approve or
escalate to a human reviewer.  Over time the algorithm converges toward
thresholds that balance autonomy with safety.

Thread-safe via :class:`threading.Lock`.  Pure Python, no external deps.

References:
- "Dynamic Trust Calibration Using Contextual Bandits"
  (arXiv:2509.23497)
- Li et al. "A Contextual-Bandit Approach to Personalized News Article
  Recommendation" (WWW 2010): https://arxiv.org/abs/1003.0146
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Frozen data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CalibrationContext:
    """Feature vector describing the decision context."""

    risk_level: float  # 0.0 (none) to 1.0 (critical)
    agent_trust: float  # 0.0 to 1.0
    action_type: str
    recent_success_rate: float  # 0.0 to 1.0
    time_of_day: float  # 0.0 to 24.0 (hour)


@dataclass(frozen=True)
class CalibrationDecision:
    """Result of a calibration decision."""

    should_approve: bool
    confidence: float  # 0.0 to 1.0
    threshold_used: float
    context: CalibrationContext
    decision_id: str = ""


@dataclass(frozen=True)
class CalibrationStats:
    """Aggregate statistics for the calibrator."""

    total_decisions: int
    auto_approved: int
    escalated: int
    accuracy_estimate: float  # 0.0 to 1.0


@dataclass(frozen=True)
class CalibrationFeedback:
    """Feedback on a past calibration decision."""

    decision_id: str
    was_correct: bool
    timestamp: float = field(default_factory=time.monotonic)


# ---------------------------------------------------------------------------
# Simplified LinUCB arm
# ---------------------------------------------------------------------------


class _LinUCBArm:
    """One arm of the contextual bandit (approve or escalate).

    Maintains a weight vector and diagonal precision matrix for
    Thompson/UCB-style exploration.  Pure Python -- no numpy.

    The feature dimension is fixed at 4:
      [risk_level, agent_trust, recent_success_rate, bias=1.0]
    """

    __slots__ = ("dim", "weights", "precision_diag", "reward_sum", "n_pulls")

    def __init__(self, dim: int = 4) -> None:
        self.dim = dim
        self.weights: list[float] = [0.0] * dim
        self.precision_diag: list[float] = [1.0] * dim  # diagonal of A matrix
        self.reward_sum: list[float] = [0.0] * dim  # b vector
        self.n_pulls: int = 0

    def predict(self, features: list[float], alpha: float) -> float:
        """Return UCB score: w^T x + alpha * sqrt(x^T A^{-1} x)."""
        # w^T x
        mu = sum(w * f for w, f in zip(self.weights, features, strict=True))
        # x^T A^{-1} x  (diagonal A → element-wise)
        var = sum((f * f) / p for f, p in zip(features, self.precision_diag, strict=True))
        return mu + alpha * math.sqrt(var)

    def update(self, features: list[float], reward: float) -> None:
        """Update weights from observed reward."""
        self.n_pulls += 1
        for i in range(self.dim):
            self.precision_diag[i] += features[i] * features[i]
            self.reward_sum[i] += reward * features[i]
            # Recompute weight: w_i = b_i / A_ii
            if self.precision_diag[i] > 0:
                self.weights[i] = self.reward_sum[i] / self.precision_diag[i]


# ---------------------------------------------------------------------------
# TrustCalibrator
# ---------------------------------------------------------------------------


class TrustCalibrator:
    """Dynamic approval threshold adjustment using contextual bandits.

    Implements a simplified LinUCB algorithm from "Dynamic Trust
    Calibration Using Contextual Bandits" (arXiv:2509.23497).  The
    calibrator maintains two arms: ``approve`` and ``escalate``.  For
    each incoming context it computes upper confidence bounds and picks
    the arm with the higher bound.  Feedback updates the chosen arm's
    model so that future decisions improve.

    Args:
        alpha: Exploration parameter (higher = more exploration).
        initial_threshold: Starting approval threshold before learning.
        min_threshold: Floor for the approval threshold.
        max_history: Maximum stored decisions for feedback matching.
    """

    def __init__(
        self,
        alpha: float = 1.0,
        initial_threshold: float = 0.5,
        min_threshold: float = 0.1,
        max_history: int = 10000,
    ) -> None:
        self._alpha = alpha
        self._initial_threshold = initial_threshold
        self._min_threshold = min_threshold
        self._max_history = max_history

        # Two arms: 0 = approve, 1 = escalate
        self._arm_approve = _LinUCBArm()
        self._arm_escalate = _LinUCBArm()

        # Decision log for feedback matching
        self._decisions: dict[str, tuple[CalibrationDecision, list[float], int]] = {}
        self._decision_counter: int = 0

        # Running stats
        self._total_decisions: int = 0
        self._auto_approved: int = 0
        self._escalated: int = 0
        self._correct_count: int = 0
        self._feedback_count: int = 0

        self._lock = threading.Lock()

    # -- helpers (must be called under lock) ---------------------------------

    @staticmethod
    def _extract_features(ctx: CalibrationContext) -> list[float]:
        """Convert context to a feature vector [risk, trust, success, bias]."""
        return [
            ctx.risk_level,
            ctx.agent_trust,
            ctx.recent_success_rate,
            1.0,  # bias term
        ]

    def _next_decision_id(self) -> str:
        self._decision_counter += 1
        return f"cal-{self._decision_counter}"

    # -- public API ----------------------------------------------------------

    def decide(self, context: CalibrationContext) -> CalibrationDecision:
        """Given context, decide whether to auto-approve or escalate.

        Returns a :class:`CalibrationDecision` with a unique
        ``decision_id`` that can be used in :meth:`update` to provide
        feedback.
        """
        with self._lock:
            features = self._extract_features(context)

            approve_score = self._arm_approve.predict(features, self._alpha)
            escalate_score = self._arm_escalate.predict(features, self._alpha)

            # Compute a dynamic threshold from the learned weights
            threshold = self._compute_threshold(context)
            # Approval score incorporates trust exceeding threshold
            approval_signal = context.agent_trust - context.risk_level

            should_approve = approve_score >= escalate_score and approval_signal >= 0
            confidence = self._compute_confidence(approve_score, escalate_score)

            decision_id = self._next_decision_id()
            chosen_arm = 0 if should_approve else 1

            decision = CalibrationDecision(
                should_approve=should_approve,
                confidence=confidence,
                threshold_used=threshold,
                context=context,
                decision_id=decision_id,
            )

            # Store for feedback
            self._decisions[decision_id] = (decision, features, chosen_arm)
            # Evict old decisions
            if len(self._decisions) > self._max_history:
                oldest_key = next(iter(self._decisions))
                del self._decisions[oldest_key]

            self._total_decisions += 1
            if should_approve:
                self._auto_approved += 1
            else:
                self._escalated += 1

            return decision

    def update(self, decision_id: str, was_correct: bool) -> bool:
        """Provide feedback on a past decision.

        Args:
            decision_id: The ``decision_id`` from a prior
                :meth:`decide` call.
            was_correct: Whether the decision was correct.

        Returns:
            ``True`` if the feedback was applied, ``False`` if the
            decision_id was not found.
        """
        with self._lock:
            entry = self._decisions.get(decision_id)
            if entry is None:
                return False

            _, features, chosen_arm = entry
            reward = 1.0 if was_correct else 0.0

            if chosen_arm == 0:
                self._arm_approve.update(features, reward)
                # If approve was wrong, also positively reinforce escalate
                if not was_correct:
                    self._arm_escalate.update(features, 1.0)
            else:
                self._arm_escalate.update(features, reward)
                if not was_correct:
                    self._arm_approve.update(features, 1.0)

            self._feedback_count += 1
            if was_correct:
                self._correct_count += 1

            return True

    def get_stats(self) -> CalibrationStats:
        """Return aggregate calibration statistics."""
        with self._lock:
            accuracy = (
                self._correct_count / self._feedback_count if self._feedback_count > 0 else 0.0
            )
            return CalibrationStats(
                total_decisions=self._total_decisions,
                auto_approved=self._auto_approved,
                escalated=self._escalated,
                accuracy_estimate=accuracy,
            )

    def get_threshold(self, context: CalibrationContext) -> float:
        """Return the current effective threshold for a given context."""
        with self._lock:
            return self._compute_threshold(context)

    # -- internal scoring ----------------------------------------------------

    def _compute_threshold(self, context: CalibrationContext) -> float:
        """Compute dynamic threshold based on context and learned weights."""
        # Base threshold adjusted by risk and learned parameters
        risk_adjustment = context.risk_level * 0.3
        trust_adjustment = (1.0 - context.agent_trust) * 0.2
        threshold = self._initial_threshold + risk_adjustment + trust_adjustment

        # Incorporate learned approve-arm bias (lower weight = more caution)
        if self._arm_approve.n_pulls > 0:
            learned_bias = self._arm_approve.weights[-1]  # bias weight
            threshold -= learned_bias * 0.1

        return max(self._min_threshold, min(1.0, threshold))

    @staticmethod
    def _compute_confidence(approve_score: float, escalate_score: float) -> float:
        """Compute confidence from score difference using a sigmoid."""
        diff = approve_score - escalate_score
        # Sigmoid-like mapping: large |diff| → high confidence
        try:
            confidence = 1.0 / (1.0 + math.exp(-2.0 * diff))
        except OverflowError:
            confidence = 0.0 if diff < 0 else 1.0
        # Map from [0.5, 1.0] range to [0.0, 1.0]
        return max(0.0, min(1.0, abs(2.0 * confidence - 1.0)))
