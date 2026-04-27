"""Tests for aegis.server.agents — AgentRegistry."""

from __future__ import annotations

import time

from aegis.server.agents import AgentRecord, AgentRegistry


def test_register_and_get():
    reg = AgentRegistry()
    rec = reg.register("a1", name="Agent One", framework="langchain", version="0.2")
    assert rec.agent_id == "a1"
    assert rec.name == "Agent One"
    assert reg.count == 1
    assert reg.get("a1") is rec


def test_register_updates_existing():
    reg = AgentRegistry()
    reg.register("a1", name="V1")
    rec = reg.register("a1", name="V2", framework="crewai")
    assert rec.name == "V2"
    assert rec.framework == "crewai"
    assert reg.count == 1


def test_heartbeat():
    reg = AgentRegistry()
    reg.register("a1", name="Agent")
    rec = reg.heartbeat("a1")
    assert rec is not None
    assert rec.agent_id == "a1"

    # Non-existent agent
    assert reg.heartbeat("nope") is None


def test_unregister():
    reg = AgentRegistry()
    reg.register("a1", name="Agent")
    assert reg.unregister("a1") is True
    assert reg.get("a1") is None
    assert reg.unregister("a1") is False


def test_list_all():
    reg = AgentRegistry()
    reg.register("a1", name="One")
    reg.register("a2", name="Two")
    assert len(reg.list_all()) == 2


def test_list_alive_filters_stale():
    reg = AgentRegistry(heartbeat_timeout=1)
    rec = reg.register("a1", name="Stale")
    # Artificially make it stale
    rec.last_heartbeat = time.time() - 10
    reg.register("a2", name="Fresh")

    alive = reg.list_alive()
    assert len(alive) == 1
    assert alive[0].agent_id == "a2"
    assert reg.alive_count == 1


def test_agent_record_to_dict():
    rec = AgentRecord(
        agent_id="a1",
        name="Test",
        framework="openai",
        version="1.0",
    )
    d = rec.to_dict(timeout=60)
    assert d["agent_id"] == "a1"
    assert d["status"] == "alive"
    assert "uptime_seconds" in d


def test_agent_record_stale_status():
    rec = AgentRecord(
        agent_id="a1",
        name="Old",
        last_heartbeat=time.time() - 120,
    )
    d = rec.to_dict(timeout=60)
    assert d["status"] == "stale"
