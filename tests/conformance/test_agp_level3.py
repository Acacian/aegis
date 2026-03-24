"""AGP Level 3 (Full) conformance tests.

Level 3 requires (in addition to Level 2):
- Multi-agent chain tracking (agent_id, parent_agent_id, chain_id, chain_depth)
- Cost tracking produces cost_alert events
- Cryptographic audit chain verification (tamper detection)
- Rate limiter produces rate_limit events

Tests exercise the actual Aegis modules: agent_identity, cost_attribution,
budget, crypto_audit, and rate_limiter.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis.core.action import Action
from aegis.core.agent_identity import AgentIdentity, AgentRegistry
from aegis.core.budget import BudgetExhausted, CostTracker, TokenUsage
from aegis.core.cost_attribution import CostAttributionTree
from aegis.core.crypto_audit import CryptoAuditChain
from aegis.core.rate_limiter import RateLimiter, RateLimitResult, RateLimitRule

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def registry() -> AgentRegistry:
    """Pre-populated agent registry with a delegation chain."""
    reg = AgentRegistry()
    root = AgentIdentity(
        agent_id="orchestrator",
        name="Orchestrator",
        capabilities=frozenset({"read_*", "write_*", "delete_*"}),
        trust_level=90,
    )
    reg.register(root)

    worker = AgentIdentity(
        agent_id="worker-1",
        name="Data Worker",
        capabilities=frozenset({"read_db", "write_db"}),
        trust_level=70,
    )
    reg.delegate("orchestrator", worker)

    leaf = AgentIdentity(
        agent_id="leaf-1",
        name="Leaf Agent",
        capabilities=frozenset({"read_db"}),
        trust_level=50,
    )
    reg.delegate("worker-1", leaf)

    return reg


@pytest.fixture()
def chain() -> CryptoAuditChain:
    return CryptoAuditChain()


@pytest.fixture()
def cost_tree() -> CostAttributionTree:
    tree = CostAttributionTree(max_budget=10.0)
    tree.register_agent("orchestrator", max_budget=10.0)
    tree.register_agent("worker-1", parent_id="orchestrator", max_budget=5.0)
    return tree


@pytest.fixture()
def rate_limiter() -> RateLimiter:
    return RateLimiter(
        rules=[
            RateLimitRule(
                name="api_limit",
                match_type="api_*",
                max_requests=5,
                window_seconds=60.0,
                per_agent=True,
                action_on_limit="block",
            ),
            RateLimitRule(
                name="write_limit",
                match_type="write*",
                max_requests=10,
                window_seconds=60.0,
                per_agent=False,
                action_on_limit="throttle",
            ),
        ]
    )


# ---------------------------------------------------------------------------
# Multi-agent chain tracking
# ---------------------------------------------------------------------------


class TestMultiAgentChainTracking:
    """Agents have identity, parent, chain_id, and chain_depth."""

    def test_root_agent_has_no_parent(self, registry: AgentRegistry) -> None:
        root = registry.get("orchestrator")
        assert root is not None
        assert root.parent_id is None

    def test_delegated_agent_has_parent(self, registry: AgentRegistry) -> None:
        worker = registry.get("worker-1")
        assert worker is not None
        assert worker.parent_id == "orchestrator"

    def test_leaf_agent_chain_depth(self, registry: AgentRegistry) -> None:
        """Trust chain from root to leaf has depth 3."""
        chain = registry.get_trust_chain("leaf-1")
        assert len(chain) == 3
        assert chain[0].agent_id == "orchestrator"
        assert chain[1].agent_id == "worker-1"
        assert chain[2].agent_id == "leaf-1"

    def test_capabilities_are_subset(self, registry: AgentRegistry) -> None:
        """Delegated agent capabilities are a subset of parent's."""
        root = registry.get("orchestrator")
        worker = registry.get("worker-1")
        leaf = registry.get("leaf-1")
        assert root is not None
        assert worker is not None
        assert leaf is not None

        # Worker got intersection of root and worker requested caps
        assert "read_db" in worker.capabilities
        assert "write_db" in worker.capabilities

        # Leaf only has read_db
        assert "read_db" in leaf.capabilities
        assert "write_db" not in leaf.capabilities

    def test_trust_level_is_minimum(self, registry: AgentRegistry) -> None:
        """Delegated trust_level is min(parent, child)."""
        worker = registry.get("worker-1")
        leaf = registry.get("leaf-1")
        assert worker is not None
        assert leaf is not None
        assert worker.trust_level <= 90  # min(90, 70)
        assert leaf.trust_level <= 70  # min(70, 50)

    def test_action_carries_chain_fields(self) -> None:
        """Action dataclass supports multi-agent chain fields."""
        action = Action(
            type="read",
            target="database",
            agent_id="worker-1",
            parent_agent_id="orchestrator",
            chain_id="chain-001",
            chain_depth=1,
        )
        assert action.agent_id == "worker-1"
        assert action.parent_agent_id == "orchestrator"
        assert action.chain_id == "chain-001"
        assert action.chain_depth == 1

    def test_chain_fields_map_to_agef_agent_section(self) -> None:
        """Multi-agent fields can populate the AGEF agent section."""
        action = Action(
            type="read",
            target="db",
            agent_id="leaf-1",
            parent_agent_id="worker-1",
            chain_id="chain-abc",
            chain_depth=2,
        )
        agef_agent = {
            "id": action.agent_id,
            "parent_agent_id": action.parent_agent_id,
            "chain_id": action.chain_id,
            "chain_depth": action.chain_depth,
        }
        assert agef_agent["id"] == "leaf-1"
        assert agef_agent["parent_agent_id"] == "worker-1"
        assert agef_agent["chain_id"] == "chain-abc"
        assert agef_agent["chain_depth"] == 2

    def test_revocation_cascades(self, registry: AgentRegistry) -> None:
        """Revoking a parent revokes all descendants."""
        revoked = registry.revoke("worker-1")
        assert "worker-1" in revoked
        assert "leaf-1" in revoked
        assert registry.get("worker-1") is None
        assert registry.get("leaf-1") is None
        # Root should remain
        assert registry.get("orchestrator") is not None

    def test_delegation_log_records_events(self, registry: AgentRegistry) -> None:
        """Every delegation is recorded in the delegation log."""
        log = registry.delegation_log
        assert len(log) >= 2  # worker-1 and leaf-1
        parent_ids = {e.parent_id for e in log}
        assert "orchestrator" in parent_ids


# ---------------------------------------------------------------------------
# Cost tracking produces cost_alert events
# ---------------------------------------------------------------------------


class TestCostTracking:
    """Cost tracking and budget enforcement."""

    def test_cost_tracker_records_usage(self) -> None:
        """CostTracker accumulates costs from token usage."""
        tracker = CostTracker(max_budget=10.0)
        usage = TokenUsage(model="gpt-4o", input_tokens=1000, output_tokens=200)
        tracker.record(usage)

        assert tracker.spent > 0
        assert tracker.remaining < 10.0
        assert len(tracker.records) == 1

    def test_budget_exhaustion_raises(self) -> None:
        """Exceeding budget raises BudgetExhausted."""
        tracker = CostTracker(max_budget=0.001)
        usage = TokenUsage(model="gpt-4o", input_tokens=100000, output_tokens=50000)

        with pytest.raises(BudgetExhausted):
            tracker.record(usage)

    def test_cost_data_maps_to_agef_cost_alert(self) -> None:
        """CostTracker state can populate an AGEF cost_alert event."""
        tracker = CostTracker(max_budget=10.0)
        usage = TokenUsage(model="gpt-4o", input_tokens=5000, output_tokens=1000)
        tracker.record(usage)

        agef_cost = {
            "event_type": "cost_alert",
            "cost": {
                "model": "gpt-4o",
                "input_tokens": usage.input_tokens,
                "output_tokens": usage.output_tokens,
                "total_tokens": usage.input_tokens + usage.output_tokens,
                "estimated_cost_usd": tracker.spent,
                "cumulative_cost_usd": tracker.spent,
                "budget_remaining_usd": tracker.remaining,
                "budget_limit_usd": tracker.max_budget,
                "budget_utilization_pct": (tracker.spent / tracker.max_budget) * 100,
            },
        }

        assert agef_cost["event_type"] == "cost_alert"
        assert agef_cost["cost"]["input_tokens"] == 5000
        assert agef_cost["cost"]["output_tokens"] == 1000
        assert agef_cost["cost"]["total_tokens"] == 6000
        assert agef_cost["cost"]["estimated_cost_usd"] > 0
        assert agef_cost["cost"]["budget_limit_usd"] == 10.0
        assert 0 <= agef_cost["cost"]["budget_utilization_pct"] <= 100

    def test_cost_attribution_tree_tracks_hierarchy(self, cost_tree: CostAttributionTree) -> None:
        """CostAttributionTree tracks costs across the delegation chain."""
        usage = TokenUsage(model="gpt-4o", input_tokens=1000, output_tokens=200)
        cost_tree.record("worker-1", usage)

        report = cost_tree.attribution_report()
        agent_ids = {node.agent_id for node in report}
        assert "worker-1" in agent_ids
        assert "orchestrator" in agent_ids

        worker_node = next(n for n in report if n.agent_id == "worker-1")
        assert worker_node.direct_cost > 0

        orchestrator_node = next(n for n in report if n.agent_id == "orchestrator")
        assert orchestrator_node.delegated_cost > 0


# ---------------------------------------------------------------------------
# Cryptographic audit chain verification
# ---------------------------------------------------------------------------


class TestCryptoAuditChain:
    """Crypto audit chain supports tamper detection and evidence integrity."""

    def test_chain_with_mixed_decisions(self, chain: CryptoAuditChain) -> None:
        """Chain handles a mix of auto/approve/block decisions."""
        decisions = ["auto", "approve", "block", "auto", "approve"]
        for i, d in enumerate(decisions):
            chain.append(
                agent_id=f"agent-{i}",
                action_type="action",
                action_target="target",
                decision=d,
                risk_level="medium",
                matched_rule="rule",
            )

        result = chain.verify()
        assert result.valid is True
        assert result.chain_length == 5

    def test_tamper_detection_on_decision_field(self, chain: CryptoAuditChain) -> None:
        """Changing the decision field of an entry is detected."""
        from dataclasses import replace

        chain.append(
            agent_id="agent",
            action_type="write",
            action_target="db",
            decision="approve",
            risk_level="medium",
            matched_rule="rule",
        )
        chain.append(
            agent_id="agent",
            action_type="delete",
            action_target="db",
            decision="block",
            risk_level="critical",
            matched_rule="rule",
        )

        # Tamper: change block to auto
        chain._chain[1] = replace(chain._chain[1], decision="auto")
        result = chain.verify()
        assert result.valid is False

    def test_evidence_package_generation(self, chain: CryptoAuditChain, tmp_path: Path) -> None:
        """Evidence package is generated with verification result."""
        for i in range(5):
            chain.append(
                agent_id=f"agent-{i}",
                action_type="read",
                action_target="db",
                decision="auto",
                risk_level="low",
                matched_rule="rule",
            )

        pkg = chain.generate_evidence_package(tmp_path / "evidence.json")
        assert pkg.chain_length == 5
        assert pkg.verification_result.valid is True
        assert pkg.algorithm == "sha256"
        assert len(pkg.compliance_notes) > 0

    def test_jsonl_export_import_roundtrip(self, chain: CryptoAuditChain, tmp_path: Path) -> None:
        """Export to JSONL and re-import preserves chain integrity."""
        for i in range(3):
            chain.append(
                agent_id=f"agent-{i}",
                action_type="read",
                action_target="db",
                decision="auto",
                risk_level="low",
                matched_rule="rule",
            )

        path = tmp_path / "audit.jsonl"
        chain.export_jsonl(path)

        chain2 = CryptoAuditChain()
        chain2.import_jsonl(path)
        assert len(chain2) == 3
        assert chain2.verify().valid is True

    def test_verify_entry_individual(self, chain: CryptoAuditChain) -> None:
        """Individual entry verification works."""
        for i in range(3):
            chain.append(
                agent_id=f"agent-{i}",
                action_type="read",
                action_target="db",
                decision="auto",
                risk_level="low",
                matched_rule="rule",
            )

        assert chain.verify_entry(0) is True
        assert chain.verify_entry(1) is True
        assert chain.verify_entry(2) is True


# ---------------------------------------------------------------------------
# Rate limiter produces rate_limit events
# ---------------------------------------------------------------------------


class TestRateLimiter:
    """Rate limiter checks and produces rate_limit event data."""

    def test_rate_limiter_allows_within_limit(self, rate_limiter: RateLimiter) -> None:
        """Actions within the limit are allowed."""
        action = Action("api_call", "external-service")
        result = rate_limiter.check(action, agent_id="agent-1")
        assert isinstance(result, RateLimitResult)
        assert result.allowed is True

    def test_rate_limiter_blocks_over_limit(self, rate_limiter: RateLimiter) -> None:
        """Exceeding the rate limit produces a block result."""
        action = Action("api_call", "external-service")
        # Record 5 requests to fill the limit
        for _ in range(5):
            rate_limiter.record(action, agent_id="agent-1")

        # 6th check should be blocked
        result = rate_limiter.check(action, agent_id="agent-1")
        assert result.allowed is False
        assert result.rule_name == "api_limit"
        assert result.action in ("block", "blocked")

    def test_rate_limit_result_has_required_fields(self, rate_limiter: RateLimiter) -> None:
        """RateLimitResult has fields needed for AGEF rate_limit events."""
        action = Action("api_call", "service")
        result = rate_limiter.check(action, agent_id="agent-1")
        assert hasattr(result, "allowed")
        assert hasattr(result, "rule_name")
        assert hasattr(result, "current_count")
        assert hasattr(result, "max_requests")
        assert hasattr(result, "retry_after_seconds")
        assert hasattr(result, "action")

    def test_rate_limit_maps_to_agef_event(self, rate_limiter: RateLimiter) -> None:
        """RateLimitResult can populate an AGEF rate_limit event."""
        action = Action("api_call", "service")
        # Exhaust the limit
        for _ in range(5):
            rate_limiter.record(action, agent_id="agent-1")
        result = rate_limiter.check(action, agent_id="agent-1")

        agef = {
            "event_type": "rate_limit",
            "rate_limit": {
                "limit_type": "requests_per_minute",
                "limit_value": result.max_requests,
                "current_value": result.current_count,
                "window_seconds": 60,
                "action_taken": result.action,
                "retry_after_seconds": (
                    int(result.retry_after_seconds) if result.retry_after_seconds else None
                ),
            },
        }

        assert agef["event_type"] == "rate_limit"
        assert agef["rate_limit"]["limit_value"] == 5
        assert agef["rate_limit"]["current_value"] >= 5
        assert agef["rate_limit"]["action_taken"] in ("block", "blocked", "throttle", "warn")

    def test_unmatched_action_is_allowed(self, rate_limiter: RateLimiter) -> None:
        """Actions not matching any rule are allowed."""
        action = Action("read", "database")
        result = rate_limiter.check(action, agent_id="agent-1")
        assert result.allowed is True
        assert result.rule_name is None

    def test_per_agent_isolation(self, rate_limiter: RateLimiter) -> None:
        """Per-agent limits are tracked independently."""
        action = Action("api_call", "service")
        # Fill limit for agent-1
        for _ in range(5):
            rate_limiter.record(action, agent_id="agent-1")

        # agent-2 should still be allowed
        result = rate_limiter.check(action, agent_id="agent-2")
        assert result.allowed is True

    def test_global_limit_shared(self, rate_limiter: RateLimiter) -> None:
        """Global limits (per_agent=False) are shared across agents."""
        action = Action("write_data", "database")
        # Fill limit across agents
        for i in range(10):
            rate_limiter.record(action, agent_id=f"agent-{i}")

        # Next check should be throttled regardless of agent
        result = rate_limiter.check(action, agent_id="agent-new")
        assert result.allowed is False
        assert result.rule_name == "write_limit"


# ---------------------------------------------------------------------------
# End-to-end: full governance chain
# ---------------------------------------------------------------------------


class TestEndToEndGovernanceChain:
    """Full governance chain from multi-agent action through audit."""

    def test_full_chain_produces_valid_evidence(self, chain: CryptoAuditChain) -> None:
        """Simulate a multi-agent governance flow and verify the audit trail."""
        # Step 1: Root orchestrator declares an action
        chain.append(
            agent_id="orchestrator",
            action_type="delegate",
            action_target="worker-1",
            decision="auto",
            risk_level="low",
            matched_rule="delegation_rule",
            metadata={"chain_id": "chain-001", "chain_depth": "0"},
        )

        # Step 2: Worker performs a governed action
        chain.append(
            agent_id="worker-1",
            action_type="write",
            action_target="production_db",
            decision="approve",
            risk_level="medium",
            matched_rule="write_approve",
            metadata={"chain_id": "chain-001", "chain_depth": "1"},
        )

        # Step 3: Guardrail activation
        chain.append(
            agent_id="worker-1",
            action_type="guardrail_check",
            action_target="pii_detector",
            decision="auto",
            risk_level="low",
            matched_rule="guardrail_rule",
            metadata={"guardrail_type": "pii_detection", "action": "masked"},
        )

        # Step 4: Cost tracking event
        chain.append(
            agent_id="worker-1",
            action_type="cost_check",
            action_target="budget",
            decision="auto",
            risk_level="low",
            matched_rule="budget_rule",
            metadata={"cost_usd": "0.05", "budget_remaining": "9.95"},
        )

        # Verify the entire chain
        result = chain.verify()
        assert result.valid is True
        assert result.chain_length == 4
        assert result.verified_entries == 4

        # Verify individual entries
        for i in range(4):
            assert chain.verify_entry(i) is True

    def test_multi_agent_audit_entries_have_distinct_agents(self, chain: CryptoAuditChain) -> None:
        """Audit entries from different agents have different agent_ids."""
        chain.append(
            agent_id="orchestrator",
            action_type="read",
            action_target="db",
            decision="auto",
            risk_level="low",
            matched_rule="rule",
        )
        chain.append(
            agent_id="worker-1",
            action_type="write",
            action_target="db",
            decision="approve",
            risk_level="medium",
            matched_rule="rule",
        )

        entries = chain.get_entries()
        agent_ids = {e.agent_id for e in entries}
        assert len(agent_ids) == 2
        assert "orchestrator" in agent_ids
        assert "worker-1" in agent_ids
