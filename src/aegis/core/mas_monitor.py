"""Multi-Agent System communication graph monitor.

Monitors inter-agent communication in a multi-agent system (MAS) and
detects topological anomalies that may indicate compromised agents,
coordination failures, or adversarial manipulation.

Anomaly types:

* **ISOLATION** -- an agent stops communicating (no messages sent or
  received within the activity window).
* **DOMINATION** -- one agent sends more than 50 % of all messages.
* **CLIQUE** -- a subset of agents only talk to each other, excluding
  the rest of the system.
* **FLOOD** -- a sudden spike in message rate from a single agent.
* **ASYMMETRY** -- one-directional communication between two agents
  (A -> B but never B -> A).
* **GHOST** -- messages addressed to agents not registered in the
  system.

Thread-safe via :class:`threading.Lock`.  Pure Python, no external deps.

Reference:
    Monitoring LLM Multi-Agent Systems via Node Evaluation.
    arXiv:2510.19420 (2025).
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AnomalyType(StrEnum):
    """Type of topological anomaly in the MAS communication graph."""

    ISOLATION = "isolation"
    DOMINATION = "domination"
    CLIQUE = "clique"
    FLOOD = "flood"
    ASYMMETRY = "asymmetry"
    GHOST = "ghost"


class MessageType(StrEnum):
    """Common inter-agent message types."""

    REQUEST = "request"
    RESPONSE = "response"
    BROADCAST = "broadcast"
    HEARTBEAT = "heartbeat"


# ---------------------------------------------------------------------------
# Frozen data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentNode:
    """Immutable snapshot of a registered agent."""

    agent_id: str
    role: str
    trust_score: float
    message_count: int
    error_count: int


@dataclass(frozen=True)
class MessageEdge:
    """Immutable record of an inter-agent message."""

    source_id: str
    target_id: str
    timestamp: float
    message_type: str = MessageType.REQUEST
    size: int = 0


@dataclass(frozen=True)
class TopologyAnomaly:
    """A detected anomaly in the communication topology."""

    anomaly_type: str
    agents_involved: tuple[str, ...]
    description: str
    severity: str = "medium"


@dataclass(frozen=True)
class MASReport:
    """Full MAS health report."""

    total_agents: int
    total_messages: int
    anomalies: list[TopologyAnomaly] = field(default_factory=list)
    topology_health: float = 1.0
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# Internal mutable state
# ---------------------------------------------------------------------------


class _AgentRecord:
    """Mutable bookkeeping for a single agent."""

    __slots__ = (
        "agent_id",
        "role",
        "trust_score",
        "sent_count",
        "received_count",
        "error_count",
        "last_active",
        "isolated",
    )

    def __init__(self, agent_id: str, role: str = "", trust_score: float = 1.0) -> None:
        self.agent_id = agent_id
        self.role = role
        self.trust_score = trust_score
        self.sent_count: int = 0
        self.received_count: int = 0
        self.error_count: int = 0
        self.last_active: float = time.time()
        self.isolated: bool = False

    def snapshot(self) -> AgentNode:
        return AgentNode(
            agent_id=self.agent_id,
            role=self.role,
            trust_score=self.trust_score,
            message_count=self.sent_count + self.received_count,
            error_count=self.error_count,
        )


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class MASMonitor:
    """Monitor multi-agent system communication for anomalies.

    Parameters
    ----------
    activity_window_s:
        Seconds of inactivity before an agent is considered isolated.
    domination_threshold:
        Fraction of total messages (0.0-1.0) that constitutes domination.
    flood_rate:
        Messages per second above which a flood is detected.
    flood_window_s:
        Window in seconds for computing flood rate.
    max_messages:
        Maximum number of messages to retain.
    """

    def __init__(
        self,
        activity_window_s: float = 60.0,
        domination_threshold: float = 0.5,
        flood_rate: float = 100.0,
        flood_window_s: float = 5.0,
        max_messages: int = 50000,
    ) -> None:
        self._activity_window = activity_window_s
        self._domination_threshold = domination_threshold
        self._flood_rate = flood_rate
        self._flood_window = flood_window_s
        self._max_messages = max_messages

        self._agents: dict[str, _AgentRecord] = {}
        self._messages: deque[MessageEdge] = deque(maxlen=max_messages)
        # Directed edge counts: (source, target) -> count
        self._edge_counts: dict[tuple[str, str], int] = {}
        # Per-agent recent send timestamps for flood detection
        self._send_times: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    # -- public API --------------------------------------------------------

    def register_agent(
        self,
        agent_id: str,
        role: str = "",
        trust_score: float = 1.0,
    ) -> AgentNode:
        """Register an agent in the monitor. Returns its snapshot."""
        with self._lock:
            rec = self._agents.get(agent_id)
            if rec is None:
                rec = _AgentRecord(agent_id, role, trust_score)
                self._agents[agent_id] = rec
            else:
                rec.role = role
                rec.trust_score = trust_score
            return rec.snapshot()

    def record_message(
        self,
        source_id: str,
        target_id: str,
        message_type: str = MessageType.REQUEST,
        size: int = 0,
        timestamp: float | None = None,
    ) -> list[TopologyAnomaly]:
        """Record an inter-agent message. Returns any immediate anomalies."""
        ts = timestamp if timestamp is not None else time.time()
        edge = MessageEdge(
            source_id=source_id,
            target_id=target_id,
            timestamp=ts,
            message_type=message_type,
            size=size,
        )
        with self._lock:
            self._messages.append(edge)
            anomalies: list[TopologyAnomaly] = []

            # Update source agent.
            src = self._agents.get(source_id)
            if src is not None:
                src.sent_count += 1
                src.last_active = ts
                src.isolated = False
            # Update target agent.
            tgt = self._agents.get(target_id)
            if tgt is not None:
                tgt.received_count += 1
                tgt.last_active = ts
                tgt.isolated = False

            # Track edge counts.
            key = (source_id, target_id)
            self._edge_counts[key] = self._edge_counts.get(key, 0) + 1

            # Track send timestamps for flood detection.
            send_buf = self._send_times.setdefault(source_id, deque(maxlen=self._max_messages))
            send_buf.append(ts)

            # Check ghost: message to unregistered agent.
            if target_id not in self._agents:
                anomalies.append(
                    TopologyAnomaly(
                        anomaly_type=AnomalyType.GHOST,
                        agents_involved=(source_id, target_id),
                        description=(
                            f"Message from '{source_id}' to unregistered agent '{target_id}'."
                        ),
                        severity="high",
                    )
                )

            # Check flood from source.
            flood = self._check_flood_unlocked(source_id, ts)
            if flood:
                anomalies.append(flood)

            return anomalies

    def detect_anomalies(self) -> list[TopologyAnomaly]:
        """Analyze the full communication graph for all anomaly types."""
        with self._lock:
            anomalies: list[TopologyAnomaly] = []
            now = time.time()
            anomalies.extend(self._detect_isolation_unlocked(now))
            anomalies.extend(self._detect_domination_unlocked())
            anomalies.extend(self._detect_clique_unlocked())
            anomalies.extend(self._detect_asymmetry_unlocked())
            return anomalies

    def isolate_agent(self, agent_id: str) -> bool:
        """Remove an agent from communication (defensive action).

        Returns True if the agent was found and isolated.
        """
        with self._lock:
            rec = self._agents.get(agent_id)
            if rec is None:
                return False
            rec.isolated = True
            rec.trust_score = 0.0
            return True

    def get_topology(self) -> dict[str, list[str]]:
        """Return the current communication graph as adjacency lists."""
        with self._lock:
            graph: dict[str, list[str]] = {}
            for src, tgt in self._edge_counts:
                graph.setdefault(src, [])
                if tgt not in graph[src]:
                    graph[src].append(tgt)
            return graph

    def get_agent(self, agent_id: str) -> AgentNode | None:
        """Return snapshot of a registered agent, or None."""
        with self._lock:
            rec = self._agents.get(agent_id)
            return rec.snapshot() if rec else None

    def report(self) -> MASReport:
        """Generate a full MAS health report."""
        anomalies = self.detect_anomalies()
        with self._lock:
            total_agents = len(self._agents)
            total_messages = len(self._messages)
        # Health score: starts at 1.0, reduced by anomaly count.
        health = max(1.0 - (len(anomalies) * 0.15), 0.0)
        return MASReport(
            total_agents=total_agents,
            total_messages=total_messages,
            anomalies=anomalies,
            topology_health=health,
        )

    # -- detection methods (must be called under lock) -----------------------

    def _check_flood_unlocked(
        self,
        agent_id: str,
        now: float,
    ) -> TopologyAnomaly | None:
        """Check if agent is flooding messages."""
        send_buf = self._send_times.get(agent_id)
        if not send_buf:
            return None
        cutoff = now - self._flood_window
        recent = [t for t in send_buf if t >= cutoff]
        if len(recent) < 2:
            return None
        span = recent[-1] - recent[0]
        rate = float(len(recent)) if span <= 0 else len(recent) / span
        if rate < self._flood_rate:
            return None
        return TopologyAnomaly(
            anomaly_type=AnomalyType.FLOOD,
            agents_involved=(agent_id,),
            description=(
                f"Agent '{agent_id}' sending at {rate:.1f} msg/s "
                f"(threshold: {self._flood_rate} msg/s)."
            ),
            severity="high",
        )

    def _detect_isolation_unlocked(
        self,
        now: float,
    ) -> list[TopologyAnomaly]:
        """Detect agents that have stopped communicating."""
        anomalies: list[TopologyAnomaly] = []
        for rec in self._agents.values():
            if rec.isolated:
                continue
            if (rec.sent_count + rec.received_count) == 0:
                # Never communicated -- skip, might be newly registered.
                continue
            if now - rec.last_active > self._activity_window:
                anomalies.append(
                    TopologyAnomaly(
                        anomaly_type=AnomalyType.ISOLATION,
                        agents_involved=(rec.agent_id,),
                        description=(
                            f"Agent '{rec.agent_id}' has been inactive for "
                            f"{now - rec.last_active:.1f}s "
                            f"(window: {self._activity_window}s)."
                        ),
                        severity="medium",
                    )
                )
        return anomalies

    def _detect_domination_unlocked(self) -> list[TopologyAnomaly]:
        """Detect agents that send more than the domination threshold of messages."""
        anomalies: list[TopologyAnomaly] = []
        total_sent = sum(r.sent_count for r in self._agents.values())
        if total_sent == 0:
            return anomalies
        for rec in self._agents.values():
            ratio = rec.sent_count / total_sent
            if ratio > self._domination_threshold:
                anomalies.append(
                    TopologyAnomaly(
                        anomaly_type=AnomalyType.DOMINATION,
                        agents_involved=(rec.agent_id,),
                        description=(
                            f"Agent '{rec.agent_id}' sent {ratio:.0%} of all "
                            f"messages ({rec.sent_count}/{total_sent}). "
                            f"Threshold: {self._domination_threshold:.0%}."
                        ),
                        severity="high",
                    )
                )
        return anomalies

    def _detect_clique_unlocked(self) -> list[TopologyAnomaly]:
        """Detect cliques: subsets of agents that only talk to each other."""
        anomalies: list[TopologyAnomaly] = []
        if len(self._agents) < 3:
            return anomalies

        # Build communication partner sets for each agent.
        partners: dict[str, set[str]] = {aid: set() for aid in self._agents}
        for src, tgt in self._edge_counts:
            if src in partners:
                partners[src].add(tgt)
            if tgt in partners:
                partners[tgt].add(src)

        all_ids = set(self._agents.keys())
        # An agent forms a clique if it only communicates with a strict
        # subset of agents, and all members of that subset also only
        # communicate among themselves.
        checked: set[frozenset[str]] = set()
        for aid in self._agents:
            group = partners.get(aid, set()) | {aid}
            if len(group) < 2 or group == all_ids:
                continue
            group_key = frozenset(group)
            if group_key in checked:
                continue
            checked.add(group_key)
            # Check if all members of the group only talk within the group.
            is_clique = True
            for member in group:
                member_partners = partners.get(member, set()) | {member}
                if not member_partners.issubset(group):
                    is_clique = False
                    break
            if is_clique and len(group) < len(all_ids):
                anomalies.append(
                    TopologyAnomaly(
                        anomaly_type=AnomalyType.CLIQUE,
                        agents_involved=tuple(sorted(group)),
                        description=(
                            f"Clique detected: agents {sorted(group)} only "
                            f"communicate among themselves, excluding "
                            f"{sorted(all_ids - group)}."
                        ),
                        severity="medium",
                    )
                )
        return anomalies

    def _detect_asymmetry_unlocked(self) -> list[TopologyAnomaly]:
        """Detect one-directional communication between agent pairs."""
        anomalies: list[TopologyAnomaly] = []
        checked: set[frozenset[str]] = set()
        for src, tgt in self._edge_counts:
            pair = frozenset((src, tgt))
            if pair in checked:
                continue
            checked.add(pair)
            forward = self._edge_counts.get((src, tgt), 0)
            reverse = self._edge_counts.get((tgt, src), 0)
            if forward > 0 and reverse == 0:
                anomalies.append(
                    TopologyAnomaly(
                        anomaly_type=AnomalyType.ASYMMETRY,
                        agents_involved=(src, tgt),
                        description=(
                            f"One-directional communication: '{src}' -> '{tgt}' "
                            f"({forward} messages) with no reverse traffic."
                        ),
                        severity="low",
                    )
                )
            elif reverse > 0 and forward == 0:
                anomalies.append(
                    TopologyAnomaly(
                        anomaly_type=AnomalyType.ASYMMETRY,
                        agents_involved=(tgt, src),
                        description=(
                            f"One-directional communication: '{tgt}' -> '{src}' "
                            f"({reverse} messages) with no reverse traffic."
                        ),
                        severity="low",
                    )
                )
        return anomalies
