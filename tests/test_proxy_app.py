"""Tests for aegis.proxy.app — ASGI application endpoints."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from starlette.testclient import TestClient

from aegis.proxy.app import create_app
from aegis.proxy.config import (
    AuthConfig,
    ClaimsConfig,
    ProxyConfig,
    UpstreamConfig,
)
from aegis.proxy.server import ProxyResult


@pytest.fixture
def config() -> ProxyConfig:
    return ProxyConfig(
        upstreams=[UpstreamConfig(name="test-srv", url="http://test:9000")],
        mode="permissive",
        claims=ClaimsConfig(enabled=False),
    )


@pytest.fixture
def client(config: ProxyConfig) -> TestClient:
    app = create_app(config)
    return TestClient(app)


class TestHealthEndpoint:
    def test_health_returns_ok(self, client: TestClient) -> None:
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["mode"] == "permissive"


class TestStatusEndpoint:
    def test_status_returns_config(self, client: TestClient) -> None:
        resp = client.get("/v1/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["mode"] == "permissive"
        assert len(data["upstreams"]) == 1
        assert data["upstreams"][0]["name"] == "test-srv"


class TestToolCallEndpoint:
    def test_invalid_json_returns_400(self, client: TestClient) -> None:
        resp = client.post(
            "/v1/tool-call",
            content=b"not json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400
        assert "Invalid JSON" in resp.json()["error"]

    def test_missing_fields_returns_400(self, client: TestClient) -> None:
        resp = client.post("/v1/tool-call", json={"arguments": {}})
        assert resp.status_code == 400
        assert "required" in resp.json()["error"].lower()

    @patch("aegis.proxy.app.AegisProxy")
    def test_allowed_call(self, mock_cls: AsyncMock, config: ProxyConfig) -> None:
        mock_proxy = AsyncMock()
        mock_proxy.authenticate.return_value = True
        mock_proxy.handle_tool_call.return_value = ProxyResult(
            allowed=True,
            data={"result": "ok"},
            trace_id="abc123",
        )
        mock_cls.return_value = mock_proxy

        app = create_app(config)
        client = TestClient(app)

        resp = client.post(
            "/v1/tool-call",
            json={
                "tool_name": "read_file",
                "arguments": {"path": "/tmp/test"},
                "server_name": "test-srv",
                "agent_id": "agent-1",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["allowed"] is True
        assert data["trace_id"] == "abc123"

    @patch("aegis.proxy.app.AegisProxy")
    def test_blocked_call_returns_403(self, mock_cls: AsyncMock, config: ProxyConfig) -> None:
        mock_proxy = AsyncMock()
        mock_proxy.authenticate.return_value = True
        mock_proxy.handle_tool_call.return_value = ProxyResult(
            allowed=False,
            reason="Policy blocked",
            trace_id="def456",
        )
        mock_cls.return_value = mock_proxy

        app = create_app(config)
        client = TestClient(app)

        resp = client.post(
            "/v1/tool-call",
            json={
                "tool_name": "drop_table",
                "arguments": {},
                "server_name": "test-srv",
            },
        )
        assert resp.status_code == 403
        data = resp.json()
        assert data["allowed"] is False
        assert "Policy blocked" in data["reason"]

    def test_auth_failure_returns_401(self) -> None:
        config = ProxyConfig(
            upstreams=[UpstreamConfig(name="srv", url="http://srv:9000")],
            mode="permissive",
            auth=AuthConfig(mode="bearer", tokens={"agent-1": "secret"}),
        )
        app = create_app(config)
        client = TestClient(app)

        resp = client.post(
            "/v1/tool-call",
            json={
                "tool_name": "read",
                "arguments": {},
                "server_name": "srv",
                "agent_id": "agent-1",
                "token": "wrong-token",
            },
        )
        assert resp.status_code == 401


class TestMcpJsonRpcEndpoint:
    def test_parse_error(self, client: TestClient) -> None:
        resp = client.post(
            "/mcp",
            content=b"bad json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert data["error"]["code"] == -32700

    def test_method_not_found(self, client: TestClient) -> None:
        resp = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "method": "unknown/method",
                "params": {},
                "id": 1,
            },
        )
        data = resp.json()
        assert data["error"]["code"] == -32601

    @patch("aegis.proxy.app.AegisProxy")
    def test_tools_call_success(self, mock_cls: AsyncMock, config: ProxyConfig) -> None:
        mock_proxy = AsyncMock()
        mock_proxy.authenticate.return_value = True
        mock_proxy.handle_tool_call.return_value = ProxyResult(
            allowed=True,
            data={"content": "file data"},
            trace_id="mcp-trace",
        )
        mock_cls.return_value = mock_proxy

        app = create_app(config)
        client = TestClient(app)

        resp = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "/tmp"}},
                "id": 42,
            },
        )
        data = resp.json()
        assert data["jsonrpc"] == "2.0"
        assert data["result"] == {"content": "file data"}
        assert data["id"] == 42

    @patch("aegis.proxy.app.AegisProxy")
    def test_tools_call_blocked(self, mock_cls: AsyncMock, config: ProxyConfig) -> None:
        mock_proxy = AsyncMock()
        mock_proxy.authenticate.return_value = True
        mock_proxy.handle_tool_call.return_value = ProxyResult(
            allowed=False,
            reason="Gap too high",
            trace_id="mcp-block",
        )
        mock_cls.return_value = mock_proxy

        app = create_app(config)
        client = TestClient(app)

        resp = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "drop_table", "arguments": {}},
                "id": 7,
            },
        )
        data = resp.json()
        assert data["error"]["code"] == -32000
        assert "Gap too high" in data["error"]["message"]
