"""Tests for the Multi-Agent System communication monitor."""

from __future__ import annotations

import threading
import time

import pytest

from aegis.core.mas_monitor import (
    AgentNode,
    AnomalyType,
    MASMonitor,
    MASReport,
    MessageEdge,
    MessageType,
    TopologyAnomaly,
)

# ---------------------------------------------------------------------------
# Frozen dataclass smoke tests
# ---------------------------------------------------------------------------


class TestDataModels:
    def test_agent_node_frozen(self) -> None:
        n = AgentNode(
            agent_id="a1", role="worker", trust_score=1.0, message_count=0, error_count=0
        )
        with pytest.raises(AttributeError):
            n.agent_id = "a2"  # type: ignore[misc]

    def test_message_edge_frozen(self) -> None:
        e = MessageEdge(source_id="a", target_id="b", timestamp=1.0)
        with pytest.raises(AttributeError):
            e.source_id = "c"  # type: ignore[misc]

    def test_topology_anomaly_frozen(self) -> None:
        a = TopologyAnomaly(
            anomaly_type=AnomalyType.ISOLATION,
            agents_involved=("a1",),
            description="test",
        )
        with pytest.raises(AttributeError):
            a.anomaly_type = AnomalyType.FLOOD  # type: ignore[misc]

    def test_mas_report_frozen(self) -> None:
        r = MASReport(total_agents=3, total_messages=10)
        with pytest.raises(AttributeError):
            r.total_agents = 5  # type: ignore[misc]

    def test_message_edge_defaults(self) -> None:
        e = MessageEdge(source_id="a", target_id="b", timestamp=0.0)
        assert e.message_type == MessageType.REQUEST
        assert e.size == 0


# ---------------------------------------------------------------------------
# Agent registration
# ---------------------------------------------------------------------------


class TestAgentRegistration:
    def test_register_agent(self) -> None:
        m = MASMonitor()
        node = m.register_agent("a1", role="worker")
        assert node.agent_id == "a1"
        assert node.role == "worker"
        assert node.trust_score == 1.0

    def test_register_updates_existing(self) -> None:
        m = MASMonitor()
        m.register_agent("a1", role="worker")
        node = m.register_agent("a1", role="coordinator", trust_score=0.5)
        assert node.role == "coordinator"
        assert node.trust_score == 0.5

    def test_get_agent(self) -> None:
        m = MASMonitor()
        m.register_agent("a1", role="worker")
        node = m.get_agent("a1")
        assert node is not None
        assert node.agent_id == "a1"

    def test_get_nonexistent_agent(self) -> None:
        m = MASMonitor()
        assert m.get_agent("nonexistent") is None


# ---------------------------------------------------------------------------
# Message recording
# ---------------------------------------------------------------------------


class TestMessageRecording:
    def test_record_message_updates_counts(self) -> None:
        m = MASMonitor()
        m.register_agent("a1")
        m.register_agent("a2")
        m.record_message("a1", "a2")
        a1 = m.get_agent("a1")
        a2 = m.get_agent("a2")
        assert a1 is not None and a1.message_count == 1  # sent
        assert a2 is not None and a2.message_count == 1  # received

    def test_record_message_topology(self) -> None:
        m = MASMonitor()
        m.register_agent("a1")
        m.register_agent("a2")
        m.record_message("a1", "a2")
        topo = m.get_topology()
        assert "a1" in topo
        assert "a2" in topo["a1"]


# ---------------------------------------------------------------------------
# Ghost detection
# ---------------------------------------------------------------------------


class TestGhostDetection:
    def test_ghost_message_detected(self) -> None:
        m = MASMonitor()
        m.register_agent("a1")
        anomalies = m.record_message("a1", "nonexistent")
        ghosts = [a for a in anomalies if a.anomaly_type == AnomalyType.GHOST]
        assert len(ghosts) == 1
        assert "nonexistent" in ghosts[0].description

    def test_no_ghost_for_registered(self) -> None:
        m = MASMonitor()
        m.register_agent("a1")
        m.register_agent("a2")
        anomalies = m.record_message("a1", "a2")
        ghosts = [a for a in anomalies if a.anomaly_type == AnomalyType.GHOST]
        assert len(ghosts) == 0


# ---------------------------------------------------------------------------
# Flood detection
# ---------------------------------------------------------------------------


class TestFloodDetection:
    def test_flood_detected(self) -> None:
        m = MASMonitor(flood_rate=5.0, flood_window_s=2.0)
        m.register_agent("a1")
        m.register_agent("a2")
        now = time.time()
        anomalies: list[TopologyAnomaly] = []
        # Send many messages at the same timestamp to trigger flood.
        for i in range(20):
            result = m.record_message("a1", "a2", timestamp=now + i * 0.01)
            anomalies.extend(result)
        floods = [a for a in anomalies if a.anomaly_type == AnomalyType.FLOOD]
        assert len(floods) >= 1
        assert "a1" in floods[0].agents_involved

    def test_no_flood_at_normal_rate(self) -> None:
        m = MASMonitor(flood_rate=100.0, flood_window_s=5.0)
        m.register_agent("a1")
        m.register_agent("a2")
        now = time.time()
        anomalies: list[TopologyAnomaly] = []
        for i in range(5):
            result = m.record_message("a1", "a2", timestamp=now + i * 1.0)
            anomalies.extend(result)
        floods = [a for a in anomalies if a.anomaly_type == AnomalyType.FLOOD]
        assert len(floods) == 0


# ---------------------------------------------------------------------------
# Isolation detection
# ---------------------------------------------------------------------------


class TestIsolationDetection:
    def test_isolation_detected(self) -> None:
        m = MASMonitor(activity_window_s=0.05)
        m.register_agent("a1")
        m.register_agent("a2")
        # Record activity, then wait.
        m.record_message("a1", "a2", timestamp=time.time() - 1.0)
        time.sleep(0.06)
        anomalies = m.detect_anomalies()
        isolated = [a for a in anomalies if a.anomaly_type == AnomalyType.ISOLATION]
        assert len(isolated) >= 1

    def test_no_isolation_for_active_agents(self) -> None:
        m = MASMonitor(activity_window_s=60.0)
        m.register_agent("a1")
        m.register_agent("a2")
        m.record_message("a1", "a2")
        anomalies = m.detect_anomalies()
        isolated = [a for a in anomalies if a.anomaly_type == AnomalyType.ISOLATION]
        assert len(isolated) == 0

    def test_no_isolation_for_new_agents(self) -> None:
        """Newly registered agents with no messages should not be flagged."""
        m = MASMonitor(activity_window_s=0.01)
        m.register_agent("a1")
        time.sleep(0.02)
        anomalies = m.detect_anomalies()
        isolated = [a for a in anomalies if a.anomaly_type == AnomalyType.ISOLATION]
        assert len(isolated) == 0


# ---------------------------------------------------------------------------
# Domination detection
# ---------------------------------------------------------------------------


class TestDominationDetection:
    def test_domination_detected(self) -> None:
        m = MASMonitor(domination_threshold=0.5)
        m.register_agent("boss")
        m.register_agent("worker1")
        m.register_agent("worker2")
        # Boss sends 80% of messages.
        for _ in range(8):
            m.record_message("boss", "worker1")
        for _ in range(2):
            m.record_message("worker2", "worker1")
        anomalies = m.detect_anomalies()
        dom = [a for a in anomalies if a.anomaly_type == AnomalyType.DOMINATION]
        assert len(dom) >= 1
        assert "boss" in dom[0].agents_involved

    def test_no_domination_with_balanced_traffic(self) -> None:
        m = MASMonitor(domination_threshold=0.5)
        m.register_agent("a1")
        m.register_agent("a2")
        m.register_agent("a3")
        for _ in range(5):
            m.record_message("a1", "a2")
            m.record_message("a2", "a3")
            m.record_message("a3", "a1")
        anomalies = m.detect_anomalies()
        dom = [a for a in anomalies if a.anomaly_type == AnomalyType.DOMINATION]
        assert len(dom) == 0


# ---------------------------------------------------------------------------
# Clique detection
# ---------------------------------------------------------------------------


class TestCliqueDetection:
    def test_clique_detected(self) -> None:
        m = MASMonitor()
        m.register_agent("a1")
        m.register_agent("a2")
        m.register_agent("a3")
        m.register_agent("outsider")
        # a1 and a2 only talk to each other.
        for _ in range(10):
            m.record_message("a1", "a2")
            m.record_message("a2", "a1")
        # a3 talks to outsider.
        for _ in range(10):
            m.record_message("a3", "outsider")
            m.record_message("outsider", "a3")
        anomalies = m.detect_anomalies()
        cliques = [a for a in anomalies if a.anomaly_type == AnomalyType.CLIQUE]
        assert len(cliques) >= 1

    def test_no_clique_when_all_connected(self) -> None:
        m = MASMonitor()
        agents = ["a1", "a2", "a3"]
        for a in agents:
            m.register_agent(a)
        for a in agents:
            for b in agents:
                if a != b:
                    m.record_message(a, b)
        anomalies = m.detect_anomalies()
        cliques = [a for a in anomalies if a.anomaly_type == AnomalyType.CLIQUE]
        assert len(cliques) == 0


# ---------------------------------------------------------------------------
# Asymmetry detection
# ---------------------------------------------------------------------------


class TestAsymmetryDetection:
    def test_asymmetry_detected(self) -> None:
        m = MASMonitor()
        m.register_agent("a1")
        m.register_agent("a2")
        # Only a1 -> a2, never a2 -> a1.
        for _ in range(5):
            m.record_message("a1", "a2")
        anomalies = m.detect_anomalies()
        asym = [a for a in anomalies if a.anomaly_type == AnomalyType.ASYMMETRY]
        assert len(asym) >= 1

    def test_no_asymmetry_bidirectional(self) -> None:
        m = MASMonitor()
        m.register_agent("a1")
        m.register_agent("a2")
        for _ in range(5):
            m.record_message("a1", "a2")
            m.record_message("a2", "a1")
        anomalies = m.detect_anomalies()
        asym = [a for a in anomalies if a.anomaly_type == AnomalyType.ASYMMETRY]
        assert len(asym) == 0


# ---------------------------------------------------------------------------
# Agent isolation (defensive)
# ---------------------------------------------------------------------------


class TestAgentIsolation:
    def test_isolate_agent(self) -> None:
        m = MASMonitor()
        m.register_agent("bad_agent")
        assert m.isolate_agent("bad_agent") is True
        node = m.get_agent("bad_agent")
        assert node is not None
        assert node.trust_score == 0.0

    def test_isolate_nonexistent(self) -> None:
        m = MASMonitor()
        assert m.isolate_agent("nonexistent") is False


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


class TestReport:
    def test_empty_report(self) -> None:
        m = MASMonitor()
        r = m.report()
        assert r.total_agents == 0
        assert r.total_messages == 0
        assert r.anomalies == []
        assert r.topology_health == 1.0

    def test_report_with_anomalies(self) -> None:
        m = MASMonitor(domination_threshold=0.3)
        m.register_agent("dom")
        m.register_agent("sub")
        for _ in range(20):
            m.record_message("dom", "sub")
        r = m.report()
        assert r.total_agents == 2
        assert r.total_messages == 20
        assert len(r.anomalies) > 0
        assert r.topology_health < 1.0

    def test_report_generated_at(self) -> None:
        m = MASMonitor()
        r = m.report()
        assert r.generated_at is not None


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------


class TestTopology:
    def test_get_topology(self) -> None:
        m = MASMonitor()
        m.register_agent("a1")
        m.register_agent("a2")
        m.register_agent("a3")
        m.record_message("a1", "a2")
        m.record_message("a1", "a3")
        m.record_message("a2", "a3")
        topo = m.get_topology()
        assert set(topo["a1"]) == {"a2", "a3"}
        assert "a3" in topo["a2"]

    def test_empty_topology(self) -> None:
        m = MASMonitor()
        assert m.get_topology() == {}


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_messages_and_detection(self) -> None:
        m = MASMonitor(flood_rate=10000.0)
        m.register_agent("a1")
        m.register_agent("a2")
        m.register_agent("a3")
        errors: list[Exception] = []

        def sender(src: str, tgt: str) -> None:
            try:
                for _ in range(50):
                    m.record_message(src, tgt)
            except Exception as exc:
                errors.append(exc)

        def detector() -> None:
            try:
                for _ in range(50):
                    m.detect_anomalies()
                    m.report()
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=sender, args=("a1", "a2")),
            threading.Thread(target=sender, args=("a2", "a3")),
            threading.Thread(target=sender, args=("a3", "a1")),
            threading.Thread(target=detector),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        assert errors == []


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_few_agents_no_clique(self) -> None:
        """Clique detection requires >=3 agents."""
        m = MASMonitor()
        m.register_agent("a1")
        m.register_agent("a2")
        m.record_message("a1", "a2")
        anomalies = m.detect_anomalies()
        cliques = [a for a in anomalies if a.anomaly_type == AnomalyType.CLIQUE]
        assert len(cliques) == 0

    def test_no_messages_no_domination(self) -> None:
        m = MASMonitor()
        m.register_agent("a1")
        anomalies = m.detect_anomalies()
        dom = [a for a in anomalies if a.anomaly_type == AnomalyType.DOMINATION]
        assert len(dom) == 0
