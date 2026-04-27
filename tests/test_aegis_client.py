"""Tests for aegis.client — AegisClient SDK."""

from __future__ import annotations

import threading

import pytest

from aegis.server.app import create_app


@pytest.fixture
def server_and_client():
    """Start a test server and return an AegisClient connected to it."""
    try:
        from starlette.testclient import TestClient
    except ImportError:
        pytest.skip("starlette not installed")
    try:
        import httpx
    except ImportError:
        pytest.skip("httpx not installed")

    app = create_app(enable_dashboard=False)
    test_client = TestClient(app)

    # Patch AegisClient to use the test client's internal transport
    from aegis.client import AegisClient

    client = AegisClient.__new__(AegisClient)
    client._base_url = "http://testserver"
    client._agent_id = "test-agent"
    client._name = "Test Agent"
    client._framework = "pytest"
    client._version = "1.0"
    client._heartbeat_interval = 300  # Don't actually heartbeat in tests
    client._headers = {}
    # Use starlette's internal transport for in-process testing
    transport = test_client._transport
    client._http = httpx.Client(
        transport=transport,
        base_url="http://testserver",
        timeout=10.0,
    )
    client._heartbeat_stop = threading.Event()
    client._heartbeat_thread = None
    client._registered = False

    yield client

    client._heartbeat_stop.set()
    client._http.close()


def test_register(server_and_client):
    client = server_and_client
    result = client.register()
    assert result["agent_id"] == "test-agent"
    assert result["status"] == "alive"
    assert client.is_registered is True


def test_evaluate(server_and_client):
    client = server_and_client
    result = client.evaluate("read", "users")
    assert "risk_level" in result
    assert "approval" in result
    assert "is_allowed" in result


def test_execute(server_and_client):
    client = server_and_client
    result = client.execute("read", "users")
    assert "status" in result


def test_get_policy(server_and_client):
    client = server_and_client
    result = client.get_policy()
    assert "rules" in result
    assert "default_risk_level" in result


def test_status_after_register(server_and_client):
    client = server_and_client
    client.register()
    result = client.status()
    assert result["agent_id"] == "test-agent"
    assert result["status"] == "alive"


def test_status_not_registered(server_and_client):
    import httpx

    client = server_and_client
    with pytest.raises(httpx.HTTPStatusError):
        client.status()


def test_disconnect(server_and_client):
    import httpx

    client = server_and_client
    client.register()
    assert client.is_registered
    client.disconnect()
    assert client.is_registered is False
    # Agent should be gone from server
    with pytest.raises(httpx.HTTPStatusError):
        client.status()


def test_context_manager(server_and_client):
    client = server_and_client
    client.register()
    client.__exit__(None, None, None)
    assert client.is_registered is False


def test_check_guardrails_not_configured(server_and_client):
    """Server without guardrails returns 501."""
    import httpx

    client = server_and_client
    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        client.check_guardrails("test content")
    assert exc_info.value.response.status_code == 501
