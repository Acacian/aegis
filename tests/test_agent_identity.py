"""Tests for the Agent Trust Chain system.

Covers AgentIdentity, AgentRegistry, DelegationEvent,
capability matching, trust chain traversal, revocation,
and policy integration helpers.
"""

from __future__ import annotations

import threading

import pytest

from aegis.core.agent_identity import (
    AgentIdentity,
    AgentRegistry,
    DelegationEvent,
    _effective_capabilities,
    capability_matches,
    has_capability,
)

# ======================================================================
# 1. capability_matches — glob matching
# ======================================================================


class TestCapabilityMatches:
    """Glob-based capability matching."""

    def test_exact_match(self):
        assert capability_matches("read_crm", "read_crm")

    def test_wildcard_suffix(self):
        assert capability_matches("read_crm", "read_*")

    def test_wildcard_prefix(self):
        assert capability_matches("read_crm", "*_crm")

    def test_full_wildcard(self):
        assert capability_matches("anything", "*")

    def test_no_match(self):
        assert not capability_matches("write_crm", "read_*")

    def test_question_mark(self):
        assert capability_matches("read_a", "read_?")
        assert not capability_matches("read_ab", "read_?")

    def test_empty_capability_matches_star(self):
        assert capability_matches("", "*")

    def test_empty_pattern_no_match(self):
        assert not capability_matches("read_crm", "")


# ======================================================================
# 2. has_capability — agent capability check
# ======================================================================


class TestHasCapability:
    """Check whether an agent's capability set covers a requirement."""

    def test_exact_capability(self):
        caps = frozenset({"read_crm", "write_crm"})
        assert has_capability(caps, "read_crm")
        assert has_capability(caps, "write_crm")

    def test_glob_capability_covers_specific(self):
        caps = frozenset({"read_*"})
        assert has_capability(caps, "read_crm")
        assert has_capability(caps, "read_salesforce")

    def test_no_matching_capability(self):
        caps = frozenset({"read_crm"})
        assert not has_capability(caps, "write_crm")

    def test_empty_capabilities_never_match(self):
        assert not has_capability(frozenset(), "read_crm")

    def test_glob_does_not_reverse_match(self):
        # Agent has "write_crm", checking for "write_*"
        # The agent's specific capability should NOT match a wider requirement
        caps = frozenset({"write_crm"})
        assert not has_capability(caps, "write_*")

    def test_full_wildcard_cap_matches_anything(self):
        caps = frozenset({"*"})
        assert has_capability(caps, "read_crm")
        assert has_capability(caps, "delete_production")


# ======================================================================
# 3. _effective_capabilities — intersection logic
# ======================================================================


class TestEffectiveCapabilities:
    """Delegation intersection: child caps filtered by parent caps."""

    def test_exact_intersection(self):
        parent = frozenset({"read_crm", "write_crm", "delete_crm"})
        child = frozenset({"read_crm", "write_crm"})
        result = _effective_capabilities(parent, child)
        assert result == frozenset({"read_crm", "write_crm"})

    def test_parent_glob_covers_child_specific(self):
        parent = frozenset({"read_*", "write_crm"})
        child = frozenset({"read_crm", "read_salesforce", "write_crm"})
        result = _effective_capabilities(parent, child)
        assert result == frozenset({"read_crm", "read_salesforce", "write_crm"})

    def test_child_requests_uncovered_capability(self):
        parent = frozenset({"read_*"})
        child = frozenset({"read_crm", "delete_production"})
        result = _effective_capabilities(parent, child)
        assert result == frozenset({"read_crm"})

    def test_no_overlap_empty_result(self):
        parent = frozenset({"read_*"})
        child = frozenset({"write_crm"})
        result = _effective_capabilities(parent, child)
        assert result == frozenset()

    def test_parent_star_grants_everything(self):
        parent = frozenset({"*"})
        child = frozenset({"read_crm", "write_crm", "delete_all"})
        result = _effective_capabilities(parent, child)
        assert result == child

    def test_both_empty(self):
        result = _effective_capabilities(frozenset(), frozenset())
        assert result == frozenset()


# ======================================================================
# 4. AgentIdentity — construction and validation
# ======================================================================


class TestAgentIdentity:
    """AgentIdentity dataclass, frozen, with validation."""

    def test_basic_construction(self):
        agent = AgentIdentity(
            agent_id="bot-1",
            name="Bot One",
            capabilities=frozenset({"read_*"}),
            trust_level=80,
        )
        assert agent.agent_id == "bot-1"
        assert agent.name == "Bot One"
        assert agent.capabilities == frozenset({"read_*"})
        assert agent.trust_level == 80
        assert agent.parent_id is None
        assert agent.metadata == {}

    def test_frozen(self):
        agent = AgentIdentity(agent_id="bot-1", name="Bot", trust_level=50)
        with pytest.raises(AttributeError):
            agent.trust_level = 99  # type: ignore[misc]

    def test_empty_agent_id_raises(self):
        with pytest.raises(ValueError, match="agent_id"):
            AgentIdentity(agent_id="", name="Bad")

    def test_trust_level_below_zero_raises(self):
        with pytest.raises(ValueError, match="trust_level"):
            AgentIdentity(agent_id="x", name="Bad", trust_level=-1)

    def test_trust_level_above_100_raises(self):
        with pytest.raises(ValueError, match="trust_level"):
            AgentIdentity(agent_id="x", name="Bad", trust_level=101)

    def test_trust_level_boundary_zero(self):
        agent = AgentIdentity(agent_id="low", name="Low Trust", trust_level=0)
        assert agent.trust_level == 0

    def test_trust_level_boundary_100(self):
        agent = AgentIdentity(agent_id="high", name="High Trust", trust_level=100)
        assert agent.trust_level == 100

    def test_with_parent_id(self):
        agent = AgentIdentity(
            agent_id="child",
            name="Child",
            trust_level=50,
            parent_id="parent",
        )
        assert agent.parent_id == "parent"

    def test_with_metadata(self):
        agent = AgentIdentity(
            agent_id="bot-1",
            name="Bot",
            trust_level=50,
            metadata={"team": "platform", "env": "staging"},
        )
        assert agent.metadata["team"] == "platform"
        assert agent.metadata["env"] == "staging"

    def test_str_representation(self):
        agent = AgentIdentity(
            agent_id="bot-1",
            name="Bot",
            capabilities=frozenset({"read_*"}),
            trust_level=80,
        )
        s = str(agent)
        assert "bot-1" in s
        assert "trust=80" in s

    def test_str_with_parent(self):
        agent = AgentIdentity(
            agent_id="child",
            name="Child",
            trust_level=50,
            parent_id="parent",
        )
        s = str(agent)
        assert "parent=parent" in s

    def test_equality(self):
        a1 = AgentIdentity(agent_id="bot", name="Bot", trust_level=50)
        a2 = AgentIdentity(agent_id="bot", name="Bot", trust_level=50)
        assert a1 == a2

    def test_default_capabilities_empty(self):
        agent = AgentIdentity(agent_id="bot", name="Bot", trust_level=50)
        assert agent.capabilities == frozenset()


# ======================================================================
# 5. AgentRegistry — register, get, list
# ======================================================================


class TestAgentRegistryBasic:
    """Basic registry operations."""

    def test_register_and_get(self):
        registry = AgentRegistry()
        agent = AgentIdentity(
            agent_id="bot-1", name="Bot", trust_level=80, capabilities=frozenset({"read_*"})
        )
        registry.register(agent)
        assert registry.get("bot-1") == agent

    def test_get_unknown_returns_none(self):
        registry = AgentRegistry()
        assert registry.get("nonexistent") is None

    def test_register_duplicate_raises(self):
        registry = AgentRegistry()
        agent = AgentIdentity(agent_id="bot-1", name="Bot", trust_level=80)
        registry.register(agent)
        with pytest.raises(ValueError, match="already registered"):
            registry.register(agent)

    def test_list_agents(self):
        registry = AgentRegistry()
        a1 = AgentIdentity(agent_id="a", name="A", trust_level=50)
        a2 = AgentIdentity(agent_id="b", name="B", trust_level=60)
        registry.register(a1)
        registry.register(a2)
        agents = registry.list_agents()
        assert len(agents) == 2
        ids = {a.agent_id for a in agents}
        assert ids == {"a", "b"}

    def test_list_agents_empty(self):
        assert AgentRegistry().list_agents() == []


# ======================================================================
# 6. AgentRegistry — delegation
# ======================================================================


class TestAgentRegistryDelegation:
    """Delegation: capability intersection, trust clamping, audit."""

    def _make_registry_with_root(self) -> tuple[AgentRegistry, AgentIdentity]:
        registry = AgentRegistry()
        root = AgentIdentity(
            agent_id="orchestrator",
            name="Orchestrator",
            capabilities=frozenset({"read_*", "write_crm", "delete_staging"}),
            trust_level=90,
        )
        registry.register(root)
        return registry, root

    def test_delegate_basic(self):
        registry, root = self._make_registry_with_root()
        child = AgentIdentity(
            agent_id="worker-1",
            name="Worker",
            capabilities=frozenset({"read_crm", "write_crm"}),
            trust_level=80,
        )
        delegated = registry.delegate("orchestrator", child)
        assert delegated.agent_id == "worker-1"
        assert delegated.parent_id == "orchestrator"
        assert delegated.capabilities == frozenset({"read_crm", "write_crm"})
        assert delegated.trust_level == 80  # min(90, 80)

    def test_delegate_trust_clamped_to_parent(self):
        registry, root = self._make_registry_with_root()
        child = AgentIdentity(
            agent_id="worker-1",
            name="Worker",
            capabilities=frozenset({"read_crm"}),
            trust_level=95,  # higher than parent's 90
        )
        delegated = registry.delegate("orchestrator", child)
        assert delegated.trust_level == 90  # clamped to parent

    def test_delegate_capabilities_intersection(self):
        registry, root = self._make_registry_with_root()
        child = AgentIdentity(
            agent_id="worker-1",
            name="Worker",
            capabilities=frozenset({"read_crm", "write_crm", "admin_panel"}),
            trust_level=70,
        )
        delegated = registry.delegate("orchestrator", child)
        # admin_panel not covered by parent -> excluded
        assert "admin_panel" not in delegated.capabilities
        assert "read_crm" in delegated.capabilities
        assert "write_crm" in delegated.capabilities

    def test_delegate_glob_parent_covers_specific_child(self):
        registry, root = self._make_registry_with_root()
        child = AgentIdentity(
            agent_id="reader",
            name="Reader",
            capabilities=frozenset({"read_salesforce", "read_stripe"}),
            trust_level=60,
        )
        delegated = registry.delegate("orchestrator", child)
        # Parent has read_* which covers both
        assert delegated.capabilities == frozenset({"read_salesforce", "read_stripe"})

    def test_delegate_zero_overlap_raises(self):
        registry, root = self._make_registry_with_root()
        child = AgentIdentity(
            agent_id="rogue",
            name="Rogue",
            capabilities=frozenset({"admin_panel", "nuke_production"}),
            trust_level=50,
        )
        with pytest.raises(ValueError, match="zero effective capabilities"):
            registry.delegate("orchestrator", child)

    def test_delegate_unknown_parent_raises(self):
        registry = AgentRegistry()
        child = AgentIdentity(
            agent_id="worker",
            name="Worker",
            capabilities=frozenset({"read_crm"}),
            trust_level=50,
        )
        with pytest.raises(KeyError, match="Parent agent not found"):
            registry.delegate("ghost", child)

    def test_delegate_duplicate_child_raises(self):
        registry, root = self._make_registry_with_root()
        child = AgentIdentity(
            agent_id="worker-1",
            name="Worker",
            capabilities=frozenset({"read_crm"}),
            trust_level=50,
        )
        registry.delegate("orchestrator", child)
        child2 = AgentIdentity(
            agent_id="worker-1",
            name="Worker Duplicate",
            capabilities=frozenset({"read_crm"}),
            trust_level=40,
        )
        with pytest.raises(ValueError, match="already registered"):
            registry.delegate("orchestrator", child2)

    def test_delegate_auto_registers(self):
        registry, root = self._make_registry_with_root()
        child = AgentIdentity(
            agent_id="worker-1",
            name="Worker",
            capabilities=frozenset({"read_crm"}),
            trust_level=50,
        )
        registry.delegate("orchestrator", child)
        assert registry.get("worker-1") is not None

    def test_delegation_event_logged(self):
        registry, root = self._make_registry_with_root()
        child = AgentIdentity(
            agent_id="worker-1",
            name="Worker",
            capabilities=frozenset({"read_crm"}),
            trust_level=70,
        )
        delegated = registry.delegate("orchestrator", child)

        log = registry.delegation_log
        assert len(log) == 1
        event = log[0]
        assert isinstance(event, DelegationEvent)
        assert event.parent_id == "orchestrator"
        assert event.child_id == "worker-1"
        assert event.granted_capabilities == delegated.capabilities
        assert event.effective_trust == 70
        assert event.timestamp is not None

    def test_child_metadata_preserved(self):
        registry, root = self._make_registry_with_root()
        child = AgentIdentity(
            agent_id="worker-1",
            name="Worker",
            capabilities=frozenset({"read_crm"}),
            trust_level=50,
            metadata={"team": "sales"},
        )
        delegated = registry.delegate("orchestrator", child)
        assert delegated.metadata == {"team": "sales"}


# ======================================================================
# 7. AgentRegistry — multi-level delegation chain
# ======================================================================


class TestMultiLevelDelegation:
    """Chains of 3+ agents, verifying transitive trust clamping."""

    def test_three_level_chain(self):
        registry = AgentRegistry()
        root = AgentIdentity(
            agent_id="root",
            name="Root",
            capabilities=frozenset({"read_*", "write_*", "delete_*"}),
            trust_level=100,
        )
        registry.register(root)

        mid = AgentIdentity(
            agent_id="mid",
            name="Mid",
            capabilities=frozenset({"read_*", "write_crm"}),
            trust_level=80,
        )
        delegated_mid = registry.delegate("root", mid)
        assert delegated_mid.trust_level == 80
        assert delegated_mid.capabilities == frozenset({"read_*", "write_crm"})

        leaf = AgentIdentity(
            agent_id="leaf",
            name="Leaf",
            capabilities=frozenset({"read_crm"}),
            trust_level=60,
        )
        delegated_leaf = registry.delegate("mid", leaf)
        assert delegated_leaf.trust_level == 60  # min(80, 60)
        assert delegated_leaf.capabilities == frozenset({"read_crm"})

    def test_deep_chain_trust_always_decreases(self):
        registry = AgentRegistry()
        prev_id = "root"
        registry.register(
            AgentIdentity(
                agent_id=prev_id,
                name="Root",
                capabilities=frozenset({"read_*"}),
                trust_level=100,
            )
        )

        for i in range(1, 6):
            child = AgentIdentity(
                agent_id=f"agent-{i}",
                name=f"Agent {i}",
                capabilities=frozenset({"read_crm"}),
                trust_level=100 - i * 10,
            )
            delegated = registry.delegate(prev_id, child)
            assert delegated.trust_level == 100 - i * 10
            prev_id = f"agent-{i}"

        chain = registry.get_trust_chain("agent-5")
        assert len(chain) == 6
        # Trust should be monotonically decreasing
        for j in range(len(chain) - 1):
            assert chain[j].trust_level >= chain[j + 1].trust_level


# ======================================================================
# 8. AgentRegistry — get_trust_chain
# ======================================================================


class TestGetTrustChain:
    """Trust chain traversal from root to leaf."""

    def _make_chain_registry(self) -> AgentRegistry:
        registry = AgentRegistry()
        root = AgentIdentity(
            agent_id="root",
            name="Root",
            capabilities=frozenset({"read_*", "write_*"}),
            trust_level=100,
        )
        registry.register(root)

        mid = AgentIdentity(
            agent_id="mid",
            name="Mid",
            capabilities=frozenset({"read_*", "write_crm"}),
            trust_level=80,
        )
        registry.delegate("root", mid)

        leaf = AgentIdentity(
            agent_id="leaf",
            name="Leaf",
            capabilities=frozenset({"read_crm"}),
            trust_level=60,
        )
        registry.delegate("mid", leaf)
        return registry

    def test_chain_for_leaf(self):
        registry = self._make_chain_registry()
        chain = registry.get_trust_chain("leaf")
        assert len(chain) == 3
        assert chain[0].agent_id == "root"
        assert chain[1].agent_id == "mid"
        assert chain[2].agent_id == "leaf"

    def test_chain_for_mid(self):
        registry = self._make_chain_registry()
        chain = registry.get_trust_chain("mid")
        assert len(chain) == 2
        assert chain[0].agent_id == "root"
        assert chain[1].agent_id == "mid"

    def test_chain_for_root(self):
        registry = self._make_chain_registry()
        chain = registry.get_trust_chain("root")
        assert len(chain) == 1
        assert chain[0].agent_id == "root"

    def test_chain_unknown_agent_raises(self):
        registry = self._make_chain_registry()
        with pytest.raises(KeyError, match="Agent not found"):
            registry.get_trust_chain("ghost")


# ======================================================================
# 9. AgentRegistry — revocation
# ======================================================================


class TestAgentRevocation:
    """Revoking an agent cascades to all descendants."""

    def test_revoke_leaf(self):
        registry = AgentRegistry()
        root = AgentIdentity(
            agent_id="root",
            name="Root",
            capabilities=frozenset({"read_*"}),
            trust_level=100,
        )
        registry.register(root)
        child = AgentIdentity(
            agent_id="child",
            name="Child",
            capabilities=frozenset({"read_crm"}),
            trust_level=50,
        )
        registry.delegate("root", child)

        revoked = registry.revoke("child")
        assert revoked == ["child"]
        assert registry.get("child") is None
        assert registry.get("root") is not None

    def test_revoke_cascades_to_descendants(self):
        registry = AgentRegistry()
        root = AgentIdentity(
            agent_id="root",
            name="Root",
            capabilities=frozenset({"read_*", "write_*"}),
            trust_level=100,
        )
        registry.register(root)

        mid = AgentIdentity(
            agent_id="mid",
            name="Mid",
            capabilities=frozenset({"read_*"}),
            trust_level=80,
        )
        registry.delegate("root", mid)

        leaf = AgentIdentity(
            agent_id="leaf",
            name="Leaf",
            capabilities=frozenset({"read_crm"}),
            trust_level=60,
        )
        registry.delegate("mid", leaf)

        revoked = registry.revoke("mid")
        assert set(revoked) == {"mid", "leaf"}
        assert registry.get("mid") is None
        assert registry.get("leaf") is None
        assert registry.get("root") is not None

    def test_revoke_root_removes_all(self):
        registry = AgentRegistry()
        root = AgentIdentity(
            agent_id="root",
            name="Root",
            capabilities=frozenset({"*"}),
            trust_level=100,
        )
        registry.register(root)

        for i in range(3):
            child = AgentIdentity(
                agent_id=f"child-{i}",
                name=f"Child {i}",
                capabilities=frozenset({"read_crm"}),
                trust_level=50,
            )
            registry.delegate("root", child)

        revoked = registry.revoke("root")
        assert len(revoked) == 4  # root + 3 children
        assert registry.list_agents() == []

    def test_revoke_unknown_raises(self):
        registry = AgentRegistry()
        with pytest.raises(KeyError, match="Agent not found"):
            registry.revoke("ghost")


# ======================================================================
# 10. AgentRegistry — capability and trust checks
# ======================================================================


class TestRegistryChecks:
    """check_capability and check_trust_level for policy integration."""

    def test_check_capability_passes(self):
        registry = AgentRegistry()
        agent = AgentIdentity(
            agent_id="bot",
            name="Bot",
            capabilities=frozenset({"read_*", "write_crm"}),
            trust_level=80,
        )
        registry.register(agent)
        assert registry.check_capability("bot", "read_crm")
        assert registry.check_capability("bot", "write_crm")

    def test_check_capability_fails(self):
        registry = AgentRegistry()
        agent = AgentIdentity(
            agent_id="bot",
            name="Bot",
            capabilities=frozenset({"read_*"}),
            trust_level=80,
        )
        registry.register(agent)
        assert not registry.check_capability("bot", "delete_production")

    def test_check_capability_unknown_agent(self):
        registry = AgentRegistry()
        assert not registry.check_capability("ghost", "read_crm")

    def test_check_trust_level_passes(self):
        registry = AgentRegistry()
        agent = AgentIdentity(agent_id="bot", name="Bot", trust_level=80)
        registry.register(agent)
        assert registry.check_trust_level("bot", 70)
        assert registry.check_trust_level("bot", 80)

    def test_check_trust_level_fails(self):
        registry = AgentRegistry()
        agent = AgentIdentity(agent_id="bot", name="Bot", trust_level=60)
        registry.register(agent)
        assert not registry.check_trust_level("bot", 70)

    def test_check_trust_level_unknown_agent(self):
        registry = AgentRegistry()
        assert not registry.check_trust_level("ghost", 50)


# ======================================================================
# 11. Delegation audit log
# ======================================================================


class TestDelegationAuditLog:
    """Delegation events are recorded chronologically."""

    def test_multiple_delegations_logged_in_order(self):
        registry = AgentRegistry()
        root = AgentIdentity(
            agent_id="root",
            name="Root",
            capabilities=frozenset({"read_*", "write_*"}),
            trust_level=100,
        )
        registry.register(root)

        for i in range(3):
            child = AgentIdentity(
                agent_id=f"child-{i}",
                name=f"Child {i}",
                capabilities=frozenset({"read_crm"}),
                trust_level=70 - i * 10,
            )
            registry.delegate("root", child)

        log = registry.delegation_log
        assert len(log) == 3
        assert log[0].child_id == "child-0"
        assert log[1].child_id == "child-1"
        assert log[2].child_id == "child-2"

    def test_log_is_snapshot(self):
        """Mutating the returned list should not affect the registry."""
        registry = AgentRegistry()
        root = AgentIdentity(
            agent_id="root",
            name="Root",
            capabilities=frozenset({"read_*"}),
            trust_level=100,
        )
        registry.register(root)
        child = AgentIdentity(
            agent_id="child",
            name="Child",
            capabilities=frozenset({"read_crm"}),
            trust_level=50,
        )
        registry.delegate("root", child)

        log = registry.delegation_log
        log.clear()
        assert len(registry.delegation_log) == 1


# ======================================================================
# 12. Thread safety
# ======================================================================


class TestThreadSafety:
    """Concurrent register/delegate should not corrupt state."""

    def test_concurrent_register(self):
        registry = AgentRegistry()
        errors: list[Exception] = []

        def register_agent(idx: int) -> None:
            try:
                registry.register(
                    AgentIdentity(
                        agent_id=f"agent-{idx}",
                        name=f"Agent {idx}",
                        trust_level=50,
                    )
                )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=register_agent, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(registry.list_agents()) == 50

    def test_concurrent_delegate(self):
        registry = AgentRegistry()
        root = AgentIdentity(
            agent_id="root",
            name="Root",
            capabilities=frozenset({"*"}),
            trust_level=100,
        )
        registry.register(root)
        errors: list[Exception] = []

        def delegate_child(idx: int) -> None:
            try:
                child = AgentIdentity(
                    agent_id=f"worker-{idx}",
                    name=f"Worker {idx}",
                    capabilities=frozenset({"read_crm"}),
                    trust_level=50,
                )
                registry.delegate("root", child)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=delegate_child, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        # root + 50 workers
        assert len(registry.list_agents()) == 51


# ======================================================================
# 13. Policy integration — min_trust_level condition
# ======================================================================


class TestPolicyIntegrationTrustLevel:
    """YAML-loaded policies with min_trust_level conditions
    integrated via AgentRegistry checks."""

    def test_trusted_agent_passes_min_trust(self):
        from aegis.core.action import Action
        from aegis.core.policy import Policy

        registry = AgentRegistry()
        agent = AgentIdentity(
            agent_id="trusted-bot",
            name="Trusted",
            capabilities=frozenset({"write_*"}),
            trust_level=85,
        )
        registry.register(agent)

        policy = Policy.from_dict(
            {
                "rules": [
                    {
                        "name": "trusted_agents_only",
                        "match": {"type": "write_*"},
                        "conditions": {"param_gte": {"min_trust_level": 70}},
                        "approval": "approve",
                    }
                ],
                "defaults": {"approval": "block"},
            }
        )

        action = Action(
            type="write_crm",
            target="salesforce",
            agent_id="trusted-bot",
            params={"min_trust_level": agent.trust_level},
        )
        decision = policy.evaluate(action)
        assert decision.approval.value == "approve"

    def test_untrusted_agent_blocked_by_registry_check(self):
        registry = AgentRegistry()
        agent = AgentIdentity(
            agent_id="untrusted-bot",
            name="Untrusted",
            capabilities=frozenset({"write_crm"}),
            trust_level=40,
        )
        registry.register(agent)

        # Direct registry check
        assert not registry.check_trust_level("untrusted-bot", 70)

    def test_capability_check_blocks_unauthorized_action(self):
        from aegis.core.action import Action

        registry = AgentRegistry()
        agent = AgentIdentity(
            agent_id="reader-bot",
            name="Reader",
            capabilities=frozenset({"read_*"}),
            trust_level=80,
        )
        registry.register(agent)

        action = Action(type="delete_production", target="db", agent_id="reader-bot")
        # Registry says: no delete capability
        assert not registry.check_capability("reader-bot", action.type)


# ======================================================================
# 14. Edge cases
# ======================================================================


class TestEdgeCases:
    """Various boundary conditions and edge cases."""

    def test_delegation_preserves_child_name(self):
        registry = AgentRegistry()
        root = AgentIdentity(
            agent_id="root",
            name="Root",
            capabilities=frozenset({"read_*"}),
            trust_level=100,
        )
        registry.register(root)
        child = AgentIdentity(
            agent_id="child",
            name="Custom Name",
            capabilities=frozenset({"read_crm"}),
            trust_level=50,
        )
        delegated = registry.delegate("root", child)
        assert delegated.name == "Custom Name"

    def test_revoke_then_re_register(self):
        registry = AgentRegistry()
        agent = AgentIdentity(
            agent_id="bot",
            name="Bot",
            capabilities=frozenset({"read_*"}),
            trust_level=50,
        )
        registry.register(agent)
        registry.revoke("bot")
        assert registry.get("bot") is None

        # Re-register with same ID should work
        new_agent = AgentIdentity(
            agent_id="bot",
            name="Bot v2",
            capabilities=frozenset({"write_*"}),
            trust_level=70,
        )
        registry.register(new_agent)
        assert registry.get("bot") == new_agent

    def test_delegation_log_survives_revocation(self):
        """Delegation events are audit records — never deleted."""
        registry = AgentRegistry()
        root = AgentIdentity(
            agent_id="root",
            name="Root",
            capabilities=frozenset({"read_*"}),
            trust_level=100,
        )
        registry.register(root)
        child = AgentIdentity(
            agent_id="child",
            name="Child",
            capabilities=frozenset({"read_crm"}),
            trust_level=50,
        )
        registry.delegate("root", child)
        registry.revoke("child")

        # Log still has the delegation event
        assert len(registry.delegation_log) == 1
        assert registry.delegation_log[0].child_id == "child"

    def test_delegation_event_frozen(self):
        registry = AgentRegistry()
        root = AgentIdentity(
            agent_id="root",
            name="Root",
            capabilities=frozenset({"read_*"}),
            trust_level=100,
        )
        registry.register(root)
        child = AgentIdentity(
            agent_id="child",
            name="Child",
            capabilities=frozenset({"read_crm"}),
            trust_level=50,
        )
        registry.delegate("root", child)

        event = registry.delegation_log[0]
        with pytest.raises(AttributeError):
            event.parent_id = "tampered"  # type: ignore[misc]

    def test_wide_delegation_fan_out(self):
        """One root delegates to many children."""
        registry = AgentRegistry()
        root = AgentIdentity(
            agent_id="root",
            name="Root",
            capabilities=frozenset({"*"}),
            trust_level=100,
        )
        registry.register(root)

        for i in range(100):
            child = AgentIdentity(
                agent_id=f"worker-{i}",
                name=f"Worker {i}",
                capabilities=frozenset({"read_crm"}),
                trust_level=50,
            )
            registry.delegate("root", child)

        assert len(registry.list_agents()) == 101
        assert len(registry.delegation_log) == 100

    def test_revoke_middle_of_chain(self):
        """Revoking a mid-level agent removes it and all descendants below."""
        registry = AgentRegistry()
        root = AgentIdentity(
            agent_id="root",
            name="Root",
            capabilities=frozenset({"*"}),
            trust_level=100,
        )
        registry.register(root)

        mid = AgentIdentity(
            agent_id="mid",
            name="Mid",
            capabilities=frozenset({"read_*"}),
            trust_level=80,
        )
        registry.delegate("root", mid)

        leaf1 = AgentIdentity(
            agent_id="leaf-1",
            name="Leaf 1",
            capabilities=frozenset({"read_crm"}),
            trust_level=60,
        )
        registry.delegate("mid", leaf1)

        leaf2 = AgentIdentity(
            agent_id="leaf-2",
            name="Leaf 2",
            capabilities=frozenset({"read_crm"}),
            trust_level=40,
        )
        registry.delegate("mid", leaf2)

        # Also a sibling directly under root
        sibling = AgentIdentity(
            agent_id="sibling",
            name="Sibling",
            capabilities=frozenset({"read_crm"}),
            trust_level=70,
        )
        registry.delegate("root", sibling)

        revoked = registry.revoke("mid")
        assert set(revoked) == {"mid", "leaf-1", "leaf-2"}
        assert registry.get("root") is not None
        assert registry.get("sibling") is not None
