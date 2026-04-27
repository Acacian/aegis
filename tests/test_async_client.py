"""Tests for aegis.client — AsyncAegisClient SDK."""

from __future__ import annotations

import pytest

from aegis.server.app import create_app


@pytest.fixture
def async_client():
    """Return an AsyncAegisClient connected to a test server."""
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
    transport = test_client._transport

    from aegis.client import AsyncAegisClient

    client = AsyncAegisClient.__new__(AsyncAegisClient)
    client._base_url = "http://testserver"
    client._agent_id = "async-agent"
    client._name = "Async Test Agent"
    client._framework = "pytest"
    client._version = "1.0"
    client._heartbeat_interval = 300
    client._auto_register = False
    client._http = httpx.AsyncClient(
        transport=httpx.MockTransport(transport.handle_request),
        base_url="http://testserver",
        timeout=10.0,
    )
    client._heartbeat_task = None
    client._registered = False

    yield client

    # Cleanup
    import asyncio

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            pass  # Can't close in running loop
        else:
            loop.run_until_complete(client._http.aclose())
    except Exception:
        pass


@pytest.mark.asyncio
async def test_async_register(async_client):
    result = await async_client.register()
    assert result["agent_id"] == "async-agent"
    assert result["status"] == "alive"
    assert async_client.is_registered is True


@pytest.mark.asyncio
async def test_async_evaluate(async_client):
    result = await async_client.evaluate("read", "users")
    assert "risk_level" in result
    assert "is_allowed" in result


@pytest.mark.asyncio
async def test_async_execute(async_client):
    result = await async_client.execute("read", "users")
    assert "status" in result


@pytest.mark.asyncio
async def test_async_get_policy(async_client):
    result = await async_client.get_policy()
    assert "rules" in result


@pytest.mark.asyncio
async def test_async_status_after_register(async_client):
    await async_client.register()
    result = await async_client.status()
    assert result["agent_id"] == "async-agent"


@pytest.mark.asyncio
async def test_async_disconnect(async_client):
    import httpx

    await async_client.register()
    assert async_client.is_registered
    await async_client.disconnect()
    assert async_client.is_registered is False
    with pytest.raises(httpx.HTTPStatusError):
        await async_client.status()


@pytest.mark.asyncio
async def test_async_check_guardrails_not_configured(async_client):
    """Server without guardrails returns 501."""
    import httpx

    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        await async_client.check_guardrails("test content")
    assert exc_info.value.response.status_code == 501
