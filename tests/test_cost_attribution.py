"""Tests for multi-agent cost attribution."""

from __future__ import annotations

import pytest

from aegis.core.budget import TokenUsage
from aegis.core.cost_attribution import AgentCostNode, CostAttributionTree

# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_register_root_agent(self) -> None:
        tree = CostAttributionTree(max_budget=10.0)
        tracker = tree.register_agent("agent-1", max_budget=5.0)
        assert tracker is not None
        assert "agent-1" in tree.agent_ids

    def test_register_child_agent(self) -> None:
        tree = CostAttributionTree(max_budget=10.0)
        tree.register_agent("parent", max_budget=8.0)
        tree.register_agent("child", parent_id="parent", max_budget=3.0)
        assert "child" in tree.agent_ids

    def test_duplicate_registration_raises(self) -> None:
        tree = CostAttributionTree(max_budget=10.0)
        tree.register_agent("agent-1", max_budget=5.0)
        with pytest.raises(ValueError, match="already registered"):
            tree.register_agent("agent-1", max_budget=5.0)

    def test_unknown_parent_raises(self) -> None:
        tree = CostAttributionTree(max_budget=10.0)
        with pytest.raises(ValueError, match="Unknown parent"):
            tree.register_agent("child", parent_id="nonexistent", max_budget=3.0)

    def test_get_tracker(self) -> None:
        tree = CostAttributionTree(max_budget=10.0)
        tree.register_agent("agent-1", max_budget=5.0)
        assert tree.get_tracker("agent-1") is not None
        assert tree.get_tracker("nonexistent") is None


# ---------------------------------------------------------------------------
# Cost recording
# ---------------------------------------------------------------------------


class TestCostRecording:
    def test_record_cost(self) -> None:
        tree = CostAttributionTree(max_budget=10.0)
        tree.register_agent("agent-1", max_budget=5.0)
        usage = TokenUsage(model="gpt-4o", input_tokens=1000, output_tokens=200)
        record = tree.record("agent-1", usage)
        assert record.cost > 0
        assert tree.get_agent_cost("agent-1") > 0

    def test_unknown_agent_raises(self) -> None:
        tree = CostAttributionTree(max_budget=10.0)
        usage = TokenUsage(model="gpt-4o", input_tokens=100, output_tokens=50)
        with pytest.raises(ValueError, match="Unknown agent"):
            tree.record("nonexistent", usage)

    def test_child_cost_rolls_up(self) -> None:
        tree = CostAttributionTree(max_budget=10.0)
        tree.register_agent("parent", max_budget=8.0)
        tree.register_agent("child", parent_id="parent", max_budget=3.0)

        usage = TokenUsage(model="gpt-4o", input_tokens=1000, output_tokens=200)
        tree.record("child", usage)

        assert tree.get_agent_cost("child") > 0
        # Parent sees child's cost via rollup (CostTracker.child() behavior)
        assert tree.get_agent_cost("parent") > 0

    def test_subtree_cost(self) -> None:
        tree = CostAttributionTree(max_budget=10.0)
        tree.register_agent("parent", max_budget=8.0)
        tree.register_agent("child-1", parent_id="parent", max_budget=3.0)
        tree.register_agent("child-2", parent_id="parent", max_budget=3.0)

        usage = TokenUsage(model="gpt-4o", input_tokens=1000, output_tokens=200)
        tree.record("child-1", usage)
        tree.record("child-2", usage)
        tree.record("parent", usage)

        subtree = tree.get_subtree_cost("parent")
        parent_direct = tree.get_agent_cost("parent")
        child1_cost = tree.get_agent_cost("child-1")
        child2_cost = tree.get_agent_cost("child-2")
        assert subtree == pytest.approx(parent_direct + child1_cost + child2_cost, rel=1e-4)


# ---------------------------------------------------------------------------
# Attribution report
# ---------------------------------------------------------------------------


class TestAttributionReport:
    def test_empty_report(self) -> None:
        tree = CostAttributionTree(max_budget=10.0)
        report = tree.attribution_report()
        assert report == []

    def test_single_agent_report(self) -> None:
        tree = CostAttributionTree(max_budget=10.0)
        tree.register_agent("agent-1", max_budget=5.0)
        usage = TokenUsage(model="gpt-4o", input_tokens=1000, output_tokens=200)
        tree.record("agent-1", usage)

        nodes = tree.attribution_report()
        assert len(nodes) == 1
        assert isinstance(nodes[0], AgentCostNode)
        assert nodes[0].agent_id == "agent-1"
        assert nodes[0].direct_cost > 0
        assert nodes[0].delegated_cost == 0
        assert nodes[0].call_count == 1

    def test_multi_agent_report(self) -> None:
        tree = CostAttributionTree(max_budget=100.0)
        tree.register_agent("orchestrator", max_budget=50.0)
        tree.register_agent("worker-1", parent_id="orchestrator", max_budget=20.0)
        tree.register_agent("worker-2", parent_id="orchestrator", max_budget=20.0)

        # Workers do work
        tree.record("worker-1", TokenUsage(model="gpt-4o", input_tokens=5000, output_tokens=1000))
        tree.record(
            "worker-2",
            TokenUsage(model="claude-sonnet-4", input_tokens=3000, output_tokens=500),
        )
        # Orchestrator does some too
        tree.record(
            "orchestrator",
            TokenUsage(model="gpt-4o", input_tokens=500, output_tokens=100),
        )

        nodes = tree.attribution_report()
        assert len(nodes) == 3

        # Orchestrator should have highest total (direct + delegated)
        orch = next(n for n in nodes if n.agent_id == "orchestrator")
        assert orch.delegated_cost > 0
        assert orch.total_cost > orch.direct_cost

    def test_report_sorted_by_total_cost(self) -> None:
        tree = CostAttributionTree(max_budget=100.0)
        tree.register_agent("cheap", max_budget=50.0)
        tree.register_agent("expensive", max_budget=50.0)

        tree.record("cheap", TokenUsage(model="gpt-4o-mini", input_tokens=100, output_tokens=50))
        tree.record(
            "expensive",
            TokenUsage(model="gpt-4o", input_tokens=10000, output_tokens=5000),
        )

        nodes = tree.attribution_report()
        assert nodes[0].agent_id == "expensive"
        assert nodes[1].agent_id == "cheap"

    def test_parent_id_populated(self) -> None:
        tree = CostAttributionTree(max_budget=100.0)
        tree.register_agent("parent", max_budget=50.0)
        tree.register_agent("child", parent_id="parent", max_budget=20.0)

        tree.record("child", TokenUsage(model="gpt-4o", input_tokens=100, output_tokens=50))

        nodes = tree.attribution_report()
        child_node = next(n for n in nodes if n.agent_id == "child")
        assert child_node.parent_id == "parent"

        parent_node = next(n for n in nodes if n.agent_id == "parent")
        assert parent_node.parent_id is None


# ---------------------------------------------------------------------------
# Format report
# ---------------------------------------------------------------------------


class TestFormatReport:
    def test_no_agents(self) -> None:
        tree = CostAttributionTree()
        report = tree.format_report()
        assert "No agents registered" in report

    def test_with_agents(self) -> None:
        tree = CostAttributionTree(max_budget=10.0)
        tree.register_agent("agent-1", max_budget=5.0)
        tree.record("agent-1", TokenUsage(model="gpt-4o", input_tokens=1000, output_tokens=200))
        report = tree.format_report()
        assert "Multi-Agent Cost Attribution" in report
        assert "agent-1" in report
        assert "$" in report

    def test_hierarchical_display(self) -> None:
        tree = CostAttributionTree(max_budget=10.0)
        tree.register_agent("parent", max_budget=8.0)
        tree.register_agent("child", parent_id="parent", max_budget=3.0)
        tree.record("child", TokenUsage(model="gpt-4o", input_tokens=100, output_tokens=50))
        report = tree.format_report()
        assert "parent" in report
        assert "child" in report


# ---------------------------------------------------------------------------
# Deep delegation chain
# ---------------------------------------------------------------------------


class TestDeepDelegation:
    def test_three_level_chain(self) -> None:
        tree = CostAttributionTree(max_budget=100.0)
        tree.register_agent("root", max_budget=100.0)
        tree.register_agent("mid", parent_id="root", max_budget=50.0)
        tree.register_agent("leaf", parent_id="mid", max_budget=20.0)

        tree.record("leaf", TokenUsage(model="gpt-4o", input_tokens=1000, output_tokens=200))

        leaf_cost = tree.get_agent_cost("leaf")
        assert leaf_cost > 0
        assert tree.get_subtree_cost("mid") >= leaf_cost
        assert tree.get_subtree_cost("root") >= leaf_cost
