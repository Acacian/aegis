"""Decision Dependence Graph for tool poisoning detection.

Tracks influence relationships between tool calls in an AI agent
system and detects anomalous influence patterns that may indicate
tool poisoning attacks -- where a compromised tool manipulates
downstream decision-making through its output.

Key mechanisms:

* **Influence graph** -- directed acyclic graph (DAG) where nodes
  represent tool calls and edges represent data-flow dependencies.
* **Outsized influence** -- a single tool node influencing more than
  *influence_fan_out_threshold* downstream nodes.
* **Circular influence** -- cycles in the dependency graph (should be
  a DAG; cycles indicate potential manipulation).
* **Influence spikes** -- a recently added node dominating the
  decision chain disproportionately.
* **Depth threshold** -- influence chains deeper than
  *max_influence_depth* are flagged.

Thread-safe via :class:`threading.Lock`.  Pure Python, no external deps.

Reference:
    MindGuard: Decision Dependence Graphs for Tool Poisoning.
    arXiv:2508.20412 (2025).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class SignalType(StrEnum):
    """Type of poisoning signal detected in the influence graph."""

    OUTSIZED_INFLUENCE = "outsized_influence"
    CIRCULAR_INFLUENCE = "circular_influence"
    INFLUENCE_SPIKE = "influence_spike"
    DEPTH_EXCEEDED = "depth_exceeded"


class EdgeType(StrEnum):
    """Type of dependency edge between tool calls."""

    DATA_FLOW = "data_flow"
    CONTROL_FLOW = "control_flow"
    CONTEXT = "context"


# ---------------------------------------------------------------------------
# Frozen data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DDGNode:
    """A node in the decision dependence graph (a single tool call)."""

    node_id: str
    tool_name: str
    timestamp: float
    influence_score: float = 0.0
    parent_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class DDGEdge:
    """A directed edge representing influence between tool calls."""

    source_id: str
    target_id: str
    weight: float = 1.0
    edge_type: str = EdgeType.DATA_FLOW


@dataclass(frozen=True)
class PoisoningSignal:
    """A single detected poisoning signal."""

    source_tool: str
    target_tool: str
    influence_score: float
    signal_type: str
    description: str


@dataclass(frozen=True)
class PoisoningReport:
    """Full graph analysis report."""

    total_nodes: int
    signals: list[PoisoningSignal] = field(default_factory=list)
    max_influence_depth: int = 0
    risk_score: float = 0.0
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _severity_from_score(score: float) -> str:
    """Map a 0.0-1.0 score to a severity label."""
    if score >= 0.8:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class DecisionDependenceGraph:
    """Track influence relationships between tool calls and detect poisoning.

    Parameters
    ----------
    max_influence_depth:
        Maximum allowed depth of influence chains before flagging.
    influence_fan_out_threshold:
        Maximum number of downstream nodes a single node may influence
        before being flagged as outsized influence.
    spike_ratio:
        Ratio of total nodes that a single recent node must influence
        to be considered an influence spike (0.0-1.0).
    max_nodes:
        Maximum number of nodes to retain (oldest are evicted).
    """

    def __init__(
        self,
        max_influence_depth: int = 5,
        influence_fan_out_threshold: int = 10,
        spike_ratio: float = 0.5,
        max_nodes: int = 10000,
    ) -> None:
        self._max_depth = max_influence_depth
        self._fan_out_threshold = influence_fan_out_threshold
        self._spike_ratio = spike_ratio
        self._max_nodes = max_nodes

        self._nodes: dict[str, DDGNode] = {}
        self._edges: list[DDGEdge] = []
        # Adjacency: source_id -> list of target_ids
        self._children: dict[str, list[str]] = {}
        # Reverse adjacency: target_id -> list of source_ids
        self._parents: dict[str, list[str]] = {}
        self._insertion_order: list[str] = []
        self._lock = threading.Lock()

    # -- public API --------------------------------------------------------

    def add_node(
        self,
        node_id: str,
        tool_name: str,
        timestamp: float | None = None,
        influence_score: float = 0.0,
        parent_ids: tuple[str, ...] | None = None,
    ) -> DDGNode:
        """Register a tool call as a graph node.

        Returns the created :class:`DDGNode`.
        """
        ts = timestamp if timestamp is not None else time.time()
        pids = parent_ids or ()
        node = DDGNode(
            node_id=node_id,
            tool_name=tool_name,
            timestamp=ts,
            influence_score=influence_score,
            parent_ids=pids,
        )
        with self._lock:
            self._nodes[node_id] = node
            self._insertion_order.append(node_id)
            if node_id not in self._children:
                self._children[node_id] = []
            if node_id not in self._parents:
                self._parents[node_id] = []
            # Auto-add edges for declared parents.
            for pid in pids:
                if pid in self._nodes:
                    self._add_edge_unlocked(pid, node_id)
            # Evict oldest nodes if over capacity.
            while len(self._nodes) > self._max_nodes and self._insertion_order:
                old_id = self._insertion_order.pop(0)
                self._evict_node_unlocked(old_id)
        return node

    def add_dependency(
        self,
        source_id: str,
        target_id: str,
        weight: float = 1.0,
        edge_type: str = EdgeType.DATA_FLOW,
    ) -> DDGEdge | None:
        """Record that *source_id*'s output influenced *target_id*'s input.

        Returns the created :class:`DDGEdge`, or ``None`` if either node
        does not exist.
        """
        with self._lock:
            if source_id not in self._nodes or target_id not in self._nodes:
                return None
            edge = DDGEdge(
                source_id=source_id,
                target_id=target_id,
                weight=weight,
                edge_type=edge_type,
            )
            self._edges.append(edge)
            self._children.setdefault(source_id, []).append(target_id)
            self._parents.setdefault(target_id, []).append(source_id)
            return edge

    def detect_poisoning(self) -> list[PoisoningSignal]:
        """Analyze graph for anomalous influence patterns.

        Returns a list of :class:`PoisoningSignal` instances.
        """
        with self._lock:
            signals: list[PoisoningSignal] = []
            signals.extend(self._detect_outsized_influence())
            signals.extend(self._detect_circular_influence())
            signals.extend(self._detect_influence_spikes())
            signals.extend(self._detect_depth_exceeded())
            return signals

    def get_influence_path(self, node_id: str) -> list[str]:
        """Trace the influence chain leading to *node_id*.

        Returns a list of node IDs from the root(s) to *node_id*.
        """
        with self._lock:
            return self._trace_path_unlocked(node_id)

    def get_downstream(self, node_id: str) -> set[str]:
        """Return all nodes transitively influenced by *node_id*."""
        with self._lock:
            return self._get_downstream_unlocked(node_id)

    def report(self) -> PoisoningReport:
        """Generate a full graph analysis report."""
        signals = self.detect_poisoning()
        with self._lock:
            max_depth = self._compute_max_depth_unlocked()
            total = len(self._nodes)
        risk = min(len(signals) / max(total, 1), 1.0)
        return PoisoningReport(
            total_nodes=total,
            signals=signals,
            max_influence_depth=max_depth,
            risk_score=risk,
        )

    # -- internal (must be called under lock) --------------------------------

    def _add_edge_unlocked(self, source_id: str, target_id: str) -> None:
        edge = DDGEdge(source_id=source_id, target_id=target_id)
        self._edges.append(edge)
        self._children.setdefault(source_id, []).append(target_id)
        self._parents.setdefault(target_id, []).append(source_id)

    def _evict_node_unlocked(self, node_id: str) -> None:
        self._nodes.pop(node_id, None)
        self._children.pop(node_id, None)
        self._parents.pop(node_id, None)
        self._edges = [e for e in self._edges if e.source_id != node_id and e.target_id != node_id]
        for clist in self._children.values():
            while node_id in clist:
                clist.remove(node_id)
        for plist in self._parents.values():
            while node_id in plist:
                plist.remove(node_id)

    def _get_downstream_unlocked(self, node_id: str) -> set[str]:
        """BFS to find all transitively reachable nodes."""
        visited: set[str] = set()
        queue = list(self._children.get(node_id, []))
        while queue:
            nid = queue.pop(0)
            if nid in visited:
                continue
            visited.add(nid)
            queue.extend(self._children.get(nid, []))
        return visited

    def _trace_path_unlocked(self, node_id: str) -> list[str]:
        """DFS backward through parents to find the longest path to a root."""
        if node_id not in self._nodes:
            return []
        parents = self._parents.get(node_id, [])
        if not parents:
            return [node_id]
        # Take the longest parent path.
        best: list[str] = []
        for pid in parents:
            path = self._trace_path_unlocked(pid)
            if len(path) > len(best):
                best = path
        return best + [node_id]

    def _compute_max_depth_unlocked(self) -> int:
        """Find the maximum depth of any influence chain."""
        if not self._nodes:
            return 0
        max_d = 0
        # Roots are nodes with no parents.
        roots = [nid for nid in self._nodes if not self._parents.get(nid)]
        for root in roots:
            depth = self._depth_from_unlocked(root, set())
            if depth > max_d:
                max_d = depth
        return max_d

    def _depth_from_unlocked(self, node_id: str, visited: set[str]) -> int:
        if node_id in visited:
            return 0
        visited.add(node_id)
        children = self._children.get(node_id, [])
        if not children:
            return 1
        return 1 + max(self._depth_from_unlocked(c, visited) for c in children)

    # -- detection methods ---------------------------------------------------

    def _detect_outsized_influence(self) -> list[PoisoningSignal]:
        signals: list[PoisoningSignal] = []
        for nid, node in self._nodes.items():
            downstream = self._get_downstream_unlocked(nid)
            if len(downstream) >= self._fan_out_threshold:
                # Find the most-influenced downstream tool.
                target_tools = [self._nodes[d].tool_name for d in downstream if d in self._nodes]
                target_str = target_tools[0] if target_tools else "unknown"
                score = min(len(downstream) / max(len(self._nodes), 1), 1.0)
                signals.append(
                    PoisoningSignal(
                        source_tool=node.tool_name,
                        target_tool=target_str,
                        influence_score=score,
                        signal_type=SignalType.OUTSIZED_INFLUENCE,
                        description=(
                            f"Tool '{node.tool_name}' (node {nid}) influences "
                            f"{len(downstream)} downstream nodes "
                            f"(threshold: {self._fan_out_threshold})."
                        ),
                    )
                )
        return signals

    def _detect_circular_influence(self) -> list[PoisoningSignal]:
        """Detect cycles using iterative DFS with explicit color tracking."""
        signals: list[PoisoningSignal] = []
        WHITE, GRAY, BLACK = 0, 1, 2
        color: dict[str, int] = {nid: WHITE for nid in self._nodes}
        reported_cycles: set[tuple[str, str]] = set()

        for start in self._nodes:
            if color[start] != WHITE:
                continue
            stack: list[tuple[str, int]] = [(start, 0)]
            color[start] = GRAY
            while stack:
                nid, idx = stack[-1]
                children = self._children.get(nid, [])
                if idx < len(children):
                    stack[-1] = (nid, idx + 1)
                    child = children[idx]
                    if child not in self._nodes:
                        continue
                    if color[child] == GRAY:
                        pair = (min(nid, child), max(nid, child))
                        if pair not in reported_cycles:
                            reported_cycles.add(pair)
                            src_node = self._nodes[nid]
                            tgt_node = self._nodes[child]
                            signals.append(
                                PoisoningSignal(
                                    source_tool=src_node.tool_name,
                                    target_tool=tgt_node.tool_name,
                                    influence_score=1.0,
                                    signal_type=SignalType.CIRCULAR_INFLUENCE,
                                    description=(
                                        f"Circular influence detected: "
                                        f"'{src_node.tool_name}' (node {nid}) <-> "
                                        f"'{tgt_node.tool_name}' (node {child})."
                                    ),
                                )
                            )
                    elif color[child] == WHITE:
                        color[child] = GRAY
                        stack.append((child, 0))
                else:
                    color[nid] = BLACK
                    stack.pop()
        return signals

    def _detect_influence_spikes(self) -> list[PoisoningSignal]:
        """Flag nodes that appeared recently and dominate the graph."""
        signals: list[PoisoningSignal] = []
        total = len(self._nodes)
        if total < 3:
            return signals
        threshold = max(int(total * self._spike_ratio), 1)
        # Consider the most recently added 25% of nodes as "recent".
        recent_count = max(total // 4, 1)
        recent_ids = self._insertion_order[-recent_count:]
        for nid in recent_ids:
            if nid not in self._nodes:
                continue
            downstream = self._get_downstream_unlocked(nid)
            if len(downstream) >= threshold:
                node = self._nodes[nid]
                score = min(len(downstream) / total, 1.0)
                targets = [self._nodes[d].tool_name for d in downstream if d in self._nodes]
                target_str = targets[0] if targets else "unknown"
                signals.append(
                    PoisoningSignal(
                        source_tool=node.tool_name,
                        target_tool=target_str,
                        influence_score=score,
                        signal_type=SignalType.INFLUENCE_SPIKE,
                        description=(
                            f"Recent node '{node.tool_name}' (node {nid}) "
                            f"influences {len(downstream)}/{total} nodes "
                            f"(spike ratio: {self._spike_ratio})."
                        ),
                    )
                )
        return signals

    def _detect_depth_exceeded(self) -> list[PoisoningSignal]:
        """Flag influence chains that exceed the depth threshold."""
        signals: list[PoisoningSignal] = []
        # Find leaf nodes and trace back.
        leaves = [nid for nid in self._nodes if not self._children.get(nid)]
        for leaf_id in leaves:
            path = self._trace_path_unlocked(leaf_id)
            if len(path) > self._max_depth:
                root_node = self._nodes.get(path[0])
                leaf_node = self._nodes.get(leaf_id)
                if root_node and leaf_node:
                    signals.append(
                        PoisoningSignal(
                            source_tool=root_node.tool_name,
                            target_tool=leaf_node.tool_name,
                            influence_score=min(len(path) / self._max_depth, 1.0),
                            signal_type=SignalType.DEPTH_EXCEEDED,
                            description=(
                                f"Influence chain depth {len(path)} exceeds "
                                f"threshold {self._max_depth}: "
                                f"{' -> '.join(path)}."
                            ),
                        )
                    )
        return signals
