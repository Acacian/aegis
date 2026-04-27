"""Tests for agent management REST API endpoints."""

from __future__ import annotations

import pytest

from aegis.server.app import create_app


@pytest.fixture
def client():
    """Create a Starlette test client."""
    try:
        from starlette.testclient import TestClient
    except ImportError:
        pytest.skip("starlette not installed")
    app = create_app(enable_dashboard=False)
    return TestClient(app)


def test_register_agent(client):
    resp = client.post(
        "/api/v1/agents",
        json={"agent_id": "test-1", "name": "Test Agent", "framework": "langchain"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["agent_id"] == "test-1"
    assert data["name"] == "Test Agent"
    assert data["framework"] == "langchain"
    assert data["status"] == "alive"


def test_register_agent_missing_id(client):
    resp = client.post("/api/v1/agents", json={"name": "No ID"})
    assert resp.status_code == 400


def test_list_agents(client):
    client.post("/api/v1/agents", json={"agent_id": "a1", "name": "One"})
    client.post("/api/v1/agents", json={"agent_id": "a2", "name": "Two"})
    resp = client.get("/api/v1/agents")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    assert len(data["agents"]) == 2


def test_get_agent(client):
    client.post("/api/v1/agents", json={"agent_id": "a1", "name": "One"})
    resp = client.get("/api/v1/agents/a1")
    assert resp.status_code == 200
    assert resp.json()["agent_id"] == "a1"


def test_get_agent_not_found(client):
    resp = client.get("/api/v1/agents/nope")
    assert resp.status_code == 404


def test_heartbeat(client):
    client.post("/api/v1/agents", json={"agent_id": "a1", "name": "One"})
    resp = client.post("/api/v1/agents/a1/heartbeat")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_heartbeat_not_found(client):
    resp = client.post("/api/v1/agents/nope/heartbeat")
    assert resp.status_code == 404


def test_unregister_agent(client):
    client.post("/api/v1/agents", json={"agent_id": "a1", "name": "One"})
    resp = client.delete("/api/v1/agents/a1")
    assert resp.status_code == 200
    assert resp.json()["status"] == "removed"

    resp = client.get("/api/v1/agents/a1")
    assert resp.status_code == 404


def test_unregister_not_found(client):
    resp = client.delete("/api/v1/agents/nope")
    assert resp.status_code == 404
