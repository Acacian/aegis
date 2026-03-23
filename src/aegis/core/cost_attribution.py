"""Multi-agent cost attribution.

Tracks costs across delegated agent chains, enabling:

- **Per-agent budgets**: Each agent gets its own CostTracker that
  rolls up to the parent.
- **Delegation-aware attribution**: When agent A delegates to agent B,
  B's costs are visible in A's report.
- **Cost lineage**: Full trace from root to leaf showing which agent
  spent what and why.
- **Hierarchical reports**: Aggregated cost tree across the full
  agent delegation chain.

Usage::

    from aegis.core.cost_attribution import CostAttributionTree

    tree = CostAttributionTree(max_budget=10.0)
    tree.register_agent("orchestrator", max_budget=10.0)
    tree.register_agent("worker-1", parent_id="orchestrator", max_budget=3.0)

    tree.record("worker-1", TokenUsage(model="gpt-4o", input_tokens=1000, output_tokens=200))

    report = tree.attribution_report()
    # Shows cost breakdown per agent with parent rollup
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from aegis.core.budget import CostRecord, CostTracker, TokenUsage

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentCostNode:
    """A node in the cost attribution tree.

    Attributes:
        agent_id: Agent identifier.
        parent_id: Parent agent (``None`` for root).
        direct_cost: Cost incurred directly by this agent.
        delegated_cost: Cost incurred by children of this agent.
        total_cost: Sum of direct + delegated costs.
        call_count: Number of LLM calls by this agent.
        budget: Maximum budget for this agent.
        utilization: Budget utilization as fraction.
    """

    agent_id: str
    parent_id: str | None
    direct_cost: float
    delegated_cost: float
    total_cost: float
    call_count: int
    budget: float
    utilization: float


# ---------------------------------------------------------------------------
# Cost attribution tree
# ---------------------------------------------------------------------------


class CostAttributionTree:
    """Manages per-agent cost tracking across a delegation hierarchy.

    Each registered agent gets its own :class:`CostTracker`. Parent-child
    relationships form a tree where child costs roll up to parents.

    Args:
        max_budget: Global budget across all agents. ``0`` = unlimited.
        session_id: Session identifier for audit correlation.
    """

    def __init__(
        self,
        max_budget: float = 0.0,
        *,
        session_id: str = "",
    ) -> None:
        self._root_tracker = CostTracker(
            max_budget=max_budget,
            session_id=session_id,
        )
        self._trackers: dict[str, CostTracker] = {}
        self._parents: dict[str, str | None] = {}
        self._children: dict[str, list[str]] = {}
        self._lock = threading.Lock()

    @property
    def root_tracker(self) -> CostTracker:
        """The root-level cost tracker."""
        return self._root_tracker

    @property
    def agent_ids(self) -> list[str]:
        """List of registered agent IDs."""
        with self._lock:
            return list(self._trackers.keys())

    def register_agent(
        self,
        agent_id: str,
        *,
        parent_id: str | None = None,
        max_budget: float = 0.0,
    ) -> CostTracker:
        """Register an agent in the cost tree.

        Args:
            agent_id: Unique agent identifier.
            parent_id: Parent agent for delegation hierarchy.
                If ``None``, the agent is a root-level agent.
            max_budget: Maximum budget for this agent.
                Capped to parent's remaining budget if parent exists.

        Returns:
            The agent's :class:`CostTracker`.

        Raises:
            ValueError: If the agent is already registered or the parent
                is unknown.
        """
        with self._lock:
            if agent_id in self._trackers:
                raise ValueError(f"Agent already registered: {agent_id}")

            if parent_id is not None and parent_id not in self._trackers:
                raise ValueError(f"Unknown parent agent: {parent_id}")

            # Create tracker as child of parent (or root)
            if parent_id is not None:
                parent_tracker = self._trackers[parent_id]
                tracker = parent_tracker.child(
                    max_budget,
                    session_id=self._root_tracker.session_id,
                )
            else:
                tracker = self._root_tracker.child(
                    max_budget,
                    session_id=self._root_tracker.session_id,
                )

            self._trackers[agent_id] = tracker
            self._parents[agent_id] = parent_id
            self._children.setdefault(agent_id, [])
            if parent_id is not None:
                self._children.setdefault(parent_id, []).append(agent_id)
            return tracker

    def get_tracker(self, agent_id: str) -> CostTracker | None:
        """Get the cost tracker for a specific agent."""
        with self._lock:
            return self._trackers.get(agent_id)

    def record(
        self,
        agent_id: str,
        usage: TokenUsage,
        *,
        action_type: str = "",
    ) -> CostRecord:
        """Record a cost for a specific agent.

        Args:
            agent_id: The agent that incurred the cost.
            usage: Token usage from the LLM call.
            action_type: Optional action type for audit.

        Returns:
            The :class:`CostRecord` from the agent's tracker.

        Raises:
            ValueError: If the agent is not registered.
        """
        with self._lock:
            tracker = self._trackers.get(agent_id)
        if tracker is None:
            raise ValueError(f"Unknown agent: {agent_id}")
        return tracker.record(usage, agent_id=agent_id, action_type=action_type)

    def get_agent_cost(self, agent_id: str) -> float:
        """Get the direct cost spent by a specific agent."""
        with self._lock:
            tracker = self._trackers.get(agent_id)
        if tracker is None:
            return 0.0
        return tracker.spent

    def get_subtree_cost(self, agent_id: str) -> float:
        """Get the total cost of an agent and all its descendants."""
        with self._lock:
            return self._subtree_cost_unlocked(agent_id)

    def _subtree_cost_unlocked(self, agent_id: str) -> float:
        """Compute subtree cost without acquiring the lock."""
        tracker = self._trackers.get(agent_id)
        if tracker is None:
            return 0.0
        total = tracker.spent
        for child_id in self._children.get(agent_id, []):
            total += self._subtree_cost_unlocked(child_id)
        return total

    def attribution_report(self) -> list[AgentCostNode]:
        """Generate a cost attribution report for all agents.

        Returns a list of :class:`AgentCostNode` objects, one per
        registered agent, sorted by total cost descending.
        """
        with self._lock:
            nodes: list[AgentCostNode] = []
            for agent_id, tracker in self._trackers.items():
                direct = tracker.spent
                children_cost = sum(
                    self._subtree_cost_unlocked(cid) for cid in self._children.get(agent_id, [])
                )
                total = direct + children_cost
                nodes.append(
                    AgentCostNode(
                        agent_id=agent_id,
                        parent_id=self._parents.get(agent_id),
                        direct_cost=round(direct, 6),
                        delegated_cost=round(children_cost, 6),
                        total_cost=round(total, 6),
                        call_count=len(tracker.records),
                        budget=tracker.max_budget,
                        utilization=tracker.utilization,
                    )
                )
            nodes.sort(key=lambda n: n.total_cost, reverse=True)
            return nodes

    def format_report(self) -> str:
        """Generate a human-readable cost attribution report."""
        nodes = self.attribution_report()
        if not nodes:
            return "No agents registered."

        lines: list[str] = []
        lines.append("Multi-Agent Cost Attribution")
        lines.append("=" * 40)
        lines.append(f"Global: ${self._root_tracker.spent:.4f} spent")
        if self._root_tracker.max_budget > 0:
            lines.append(
                f"Budget: ${self._root_tracker.max_budget:.2f} "
                f"({self._root_tracker.utilization:.0%} used)"
            )
        lines.append("")

        lines.append(f"{'Agent':<20} {'Direct':>10} {'Delegated':>10} {'Total':>10} {'Calls':>6}")
        lines.append("-" * 60)
        for node in nodes:
            prefix = "  " if node.parent_id else ""
            lines.append(
                f"{prefix}{node.agent_id:<18} "
                f"${node.direct_cost:>9.4f} "
                f"${node.delegated_cost:>9.4f} "
                f"${node.total_cost:>9.4f} "
                f"{node.call_count:>5}"
            )
        return "\n".join(lines)
