"""Tests for the Decision Dependence Graph tool poisoning detection module."""

from __future__ import annotations

import threading

import pytest

from aegis.core.tool_poisoning_graph import (
    DDGEdge,
    DDGNode,
    DecisionDependenceGraph,
    EdgeType,
    PoisoningReport,
    PoisoningSignal,
    SignalType,
)

# ---------------------------------------------------------------------------
# Frozen dataclass smoke tests
# ---------------------------------------------------------------------------


class TestDataModels:
    def test_ddg_node_frozen(self) -> None:
        node = DDGNode(node_id="n1", tool_name="search", timestamp=1.0)
        with pytest.raises(AttributeError):
            node.node_id = "n2"  # type: ignore[misc]

    def test_ddg_edge_frozen(self) -> None:
        edge = DDGEdge(source_id="n1", target_id="n2")
        with pytest.raises(AttributeError):
            edge.weight = 5.0  # type: ignore[misc]

    def test_poisoning_signal_frozen(self) -> None:
        sig = PoisoningSignal(
            source_tool="a",
            target_tool="b",
            influence_score=0.5,
            signal_type=SignalType.OUTSIZED_INFLUENCE,
            description="test",
        )
        with pytest.raises(AttributeError):
            sig.influence_score = 1.0  # type: ignore[misc]

    def test_poisoning_report_frozen(self) -> None:
        r = PoisoningReport(total_nodes=5)
        with pytest.raises(AttributeError):
            r.total_nodes = 10  # type: ignore[misc]

    def test_ddg_node_default_values(self) -> None:
        node = DDGNode(node_id="n1", tool_name="t", timestamp=0.0)
        assert node.influence_score == 0.0
        assert node.parent_ids == ()

    def test_ddg_edge_default_values(self) -> None:
        edge = DDGEdge(source_id="a", target_id="b")
        assert edge.weight == 1.0
        assert edge.edge_type == EdgeType.DATA_FLOW


# ---------------------------------------------------------------------------
# Node and edge management
# ---------------------------------------------------------------------------


class TestNodeManagement:
    def test_add_node(self) -> None:
        g = DecisionDependenceGraph()
        node = g.add_node("n1", "web_search", timestamp=100.0)
        assert node.node_id == "n1"
        assert node.tool_name == "web_search"
        assert node.timestamp == 100.0

    def test_add_node_with_parents(self) -> None:
        g = DecisionDependenceGraph()
        g.add_node("n1", "search")
        g.add_node("n2", "parse", parent_ids=("n1",))
        # Edge should have been auto-created.
        path = g.get_influence_path("n2")
        assert path == ["n1", "n2"]

    def test_add_dependency(self) -> None:
        g = DecisionDependenceGraph()
        g.add_node("n1", "search")
        g.add_node("n2", "parse")
        edge = g.add_dependency("n1", "n2", weight=0.8)
        assert edge is not None
        assert edge.source_id == "n1"
        assert edge.target_id == "n2"
        assert edge.weight == 0.8

    def test_add_dependency_missing_node_returns_none(self) -> None:
        g = DecisionDependenceGraph()
        g.add_node("n1", "search")
        assert g.add_dependency("n1", "nonexistent") is None
        assert g.add_dependency("nonexistent", "n1") is None

    def test_node_eviction(self) -> None:
        g = DecisionDependenceGraph(max_nodes=3)
        g.add_node("n1", "a")
        g.add_node("n2", "b")
        g.add_node("n3", "c")
        g.add_node("n4", "d")
        # n1 should have been evicted.
        report = g.report()
        assert report.total_nodes == 3


# ---------------------------------------------------------------------------
# Influence path tracing
# ---------------------------------------------------------------------------


class TestInfluencePath:
    def test_simple_chain(self) -> None:
        g = DecisionDependenceGraph()
        g.add_node("n1", "search")
        g.add_node("n2", "parse")
        g.add_node("n3", "decide")
        g.add_dependency("n1", "n2")
        g.add_dependency("n2", "n3")
        path = g.get_influence_path("n3")
        assert path == ["n1", "n2", "n3"]

    def test_root_node_path(self) -> None:
        g = DecisionDependenceGraph()
        g.add_node("n1", "search")
        path = g.get_influence_path("n1")
        assert path == ["n1"]

    def test_nonexistent_node(self) -> None:
        g = DecisionDependenceGraph()
        assert g.get_influence_path("nonexistent") == []

    def test_get_downstream(self) -> None:
        g = DecisionDependenceGraph()
        g.add_node("n1", "search")
        g.add_node("n2", "parse")
        g.add_node("n3", "decide")
        g.add_dependency("n1", "n2")
        g.add_dependency("n2", "n3")
        downstream = g.get_downstream("n1")
        assert downstream == {"n2", "n3"}

    def test_get_downstream_leaf(self) -> None:
        g = DecisionDependenceGraph()
        g.add_node("n1", "search")
        assert g.get_downstream("n1") == set()


# ---------------------------------------------------------------------------
# Outsized influence detection
# ---------------------------------------------------------------------------


class TestOutsizedInfluence:
    def test_outsized_influence_detected(self) -> None:
        g = DecisionDependenceGraph(influence_fan_out_threshold=3)
        g.add_node("root", "evil_tool")
        for i in range(5):
            nid = f"child_{i}"
            g.add_node(nid, f"tool_{i}")
            g.add_dependency("root", nid)
        signals = g.detect_poisoning()
        outsized = [s for s in signals if s.signal_type == SignalType.OUTSIZED_INFLUENCE]
        assert len(outsized) >= 1
        assert outsized[0].source_tool == "evil_tool"

    def test_no_outsized_below_threshold(self) -> None:
        g = DecisionDependenceGraph(influence_fan_out_threshold=10)
        g.add_node("root", "tool")
        for i in range(3):
            nid = f"child_{i}"
            g.add_node(nid, f"t{i}")
            g.add_dependency("root", nid)
        signals = g.detect_poisoning()
        outsized = [s for s in signals if s.signal_type == SignalType.OUTSIZED_INFLUENCE]
        assert len(outsized) == 0


# ---------------------------------------------------------------------------
# Circular influence detection
# ---------------------------------------------------------------------------


class TestCircularInfluence:
    def test_cycle_detected(self) -> None:
        g = DecisionDependenceGraph()
        g.add_node("n1", "tool_a")
        g.add_node("n2", "tool_b")
        g.add_dependency("n1", "n2")
        g.add_dependency("n2", "n1")
        signals = g.detect_poisoning()
        circular = [s for s in signals if s.signal_type == SignalType.CIRCULAR_INFLUENCE]
        assert len(circular) >= 1

    def test_no_cycle_in_dag(self) -> None:
        g = DecisionDependenceGraph()
        g.add_node("n1", "a")
        g.add_node("n2", "b")
        g.add_node("n3", "c")
        g.add_dependency("n1", "n2")
        g.add_dependency("n2", "n3")
        signals = g.detect_poisoning()
        circular = [s for s in signals if s.signal_type == SignalType.CIRCULAR_INFLUENCE]
        assert len(circular) == 0


# ---------------------------------------------------------------------------
# Influence spike detection
# ---------------------------------------------------------------------------


class TestInfluenceSpike:
    def test_spike_detected(self) -> None:
        g = DecisionDependenceGraph(spike_ratio=0.3)
        # Build a graph with many old nodes.
        for i in range(10):
            g.add_node(f"old_{i}", "old_tool")
        # Add a recent node that influences most others.
        g.add_node("new_root", "new_tool")
        for i in range(10):
            g.add_dependency("new_root", f"old_{i}")
        signals = g.detect_poisoning()
        spikes = [s for s in signals if s.signal_type == SignalType.INFLUENCE_SPIKE]
        assert len(spikes) >= 1
        assert spikes[0].source_tool == "new_tool"

    def test_no_spike_small_graph(self) -> None:
        g = DecisionDependenceGraph(spike_ratio=0.5)
        g.add_node("n1", "a")
        g.add_node("n2", "b")
        signals = g.detect_poisoning()
        spikes = [s for s in signals if s.signal_type == SignalType.INFLUENCE_SPIKE]
        assert len(spikes) == 0


# ---------------------------------------------------------------------------
# Depth exceeded detection
# ---------------------------------------------------------------------------


class TestDepthExceeded:
    def test_depth_exceeded_detected(self) -> None:
        g = DecisionDependenceGraph(max_influence_depth=3)
        # Build a chain of depth 5.
        g.add_node("n1", "t1")
        g.add_node("n2", "t2")
        g.add_node("n3", "t3")
        g.add_node("n4", "t4")
        g.add_node("n5", "t5")
        g.add_dependency("n1", "n2")
        g.add_dependency("n2", "n3")
        g.add_dependency("n3", "n4")
        g.add_dependency("n4", "n5")
        signals = g.detect_poisoning()
        depth = [s for s in signals if s.signal_type == SignalType.DEPTH_EXCEEDED]
        assert len(depth) >= 1

    def test_no_depth_exceeded_within_limit(self) -> None:
        g = DecisionDependenceGraph(max_influence_depth=5)
        g.add_node("n1", "t1")
        g.add_node("n2", "t2")
        g.add_node("n3", "t3")
        g.add_dependency("n1", "n2")
        g.add_dependency("n2", "n3")
        signals = g.detect_poisoning()
        depth = [s for s in signals if s.signal_type == SignalType.DEPTH_EXCEEDED]
        assert len(depth) == 0


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


class TestReport:
    def test_empty_graph_report(self) -> None:
        g = DecisionDependenceGraph()
        r = g.report()
        assert r.total_nodes == 0
        assert r.signals == []
        assert r.max_influence_depth == 0
        assert r.risk_score == 0.0

    def test_report_with_signals(self) -> None:
        g = DecisionDependenceGraph(influence_fan_out_threshold=2)
        g.add_node("root", "evil")
        for i in range(5):
            g.add_node(f"c{i}", f"t{i}")
            g.add_dependency("root", f"c{i}")
        r = g.report()
        assert r.total_nodes == 6
        assert len(r.signals) > 0
        assert r.risk_score > 0.0

    def test_report_generated_at(self) -> None:
        g = DecisionDependenceGraph()
        r = g.report()
        assert r.generated_at is not None


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_add_and_detect(self) -> None:
        g = DecisionDependenceGraph(influence_fan_out_threshold=5)
        errors: list[Exception] = []

        def adder(prefix: str) -> None:
            try:
                for i in range(20):
                    g.add_node(f"{prefix}_{i}", f"tool_{prefix}")
                    if i > 0:
                        g.add_dependency(f"{prefix}_{i - 1}", f"{prefix}_{i}")
            except Exception as exc:
                errors.append(exc)

        def detector() -> None:
            try:
                for _ in range(20):
                    g.detect_poisoning()
                    g.report()
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=adder, args=(f"a{j}",)) for j in range(3)]
        threads.append(threading.Thread(target=detector))
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        assert errors == []
