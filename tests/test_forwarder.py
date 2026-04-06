"""Tests for proxy forwarders (McpHttpForwarder, McpSseForwarder, RestForwarder)."""

from __future__ import annotations

import pytest

from aegis.proxy.forwarder import (
    ForwardResult,
    McpHttpForwarder,
    McpSseForwarder,
    RestForwarder,
    get_forwarder,
)

# ---------------------------------------------------------------------------
# ForwardResult
# ---------------------------------------------------------------------------


class TestForwardResult:
    def test_success_result(self) -> None:
        r = ForwardResult(success=True, data={"key": "val"}, latency_ms=12.5)
        assert r.success is True
        assert r.data == {"key": "val"}
        assert r.error == ""

    def test_failure_result(self) -> None:
        r = ForwardResult(success=False, error="connection refused")
        assert r.success is False
        assert r.error == "connection refused"

    def test_defaults(self) -> None:
        r = ForwardResult(success=True)
        assert r.status_code == 200
        assert r.latency_ms == 0.0


# ---------------------------------------------------------------------------
# get_forwarder
# ---------------------------------------------------------------------------


class TestGetForwarder:
    def test_mcp_http(self) -> None:
        f = get_forwarder("mcp-http")
        assert isinstance(f, McpHttpForwarder)

    def test_mcp_sse(self) -> None:
        f = get_forwarder("mcp-sse")
        assert isinstance(f, McpSseForwarder)

    def test_rest(self) -> None:
        f = get_forwarder("rest")
        assert isinstance(f, RestForwarder)

    def test_unknown_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown protocol"):
            get_forwarder("grpc")


# ---------------------------------------------------------------------------
# McpHttpForwarder — unit tests with mocked httpx
# ---------------------------------------------------------------------------


class TestMcpHttpForwarder:
    @pytest.mark.asyncio
    async def test_success_response(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Simulate successful JSON-RPC response."""
        import sys

        class FakeResp:
            status_code = 200
            text = '{"jsonrpc":"2.0","result":{"content":"hello"},"id":1}'

            def json(self):
                return {"jsonrpc": "2.0", "result": {"content": "hello"}, "id": 1}

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            async def post(self, url, json=None, headers=None):
                return FakeResp()

        fake_httpx = type("httpx", (), {"AsyncClient": lambda *a, **kw: FakeClient()})()
        monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

        fwd = McpHttpForwarder()
        result = await fwd.forward(
            url="http://localhost:9000",
            tool_name="read_file",
            arguments={"path": "/tmp/test"},
        )
        assert result.success is True
        assert result.data == {"content": "hello"}
        assert result.latency_ms >= 0

    @pytest.mark.asyncio
    async def test_http_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Simulate HTTP error response."""
        import sys

        class FakeResp:
            status_code = 500
            text = "Internal Server Error"

            def json(self):
                return {}

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            async def post(self, url, json=None, headers=None):
                return FakeResp()

        fake_httpx = type("httpx", (), {"AsyncClient": lambda *a, **kw: FakeClient()})()
        monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

        fwd = McpHttpForwarder()
        result = await fwd.forward(
            url="http://localhost:9000",
            tool_name="read",
            arguments={},
        )
        assert result.success is False
        assert result.status_code == 500
        assert "500" in result.error


# ---------------------------------------------------------------------------
# RestForwarder
# ---------------------------------------------------------------------------


class TestRestForwarder:
    @pytest.mark.asyncio
    async def test_success_response(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys

        class FakeResp:
            status_code = 200
            text = '{"result": "ok"}'

            def json(self):
                return {"result": "ok"}

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            async def post(self, url, json=None, headers=None):
                return FakeResp()

        fake_httpx = type("httpx", (), {"AsyncClient": lambda *a, **kw: FakeClient()})()
        monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

        fwd = RestForwarder()
        result = await fwd.forward(
            url="http://localhost:8080/api",
            tool_name="search",
            arguments={"q": "test"},
        )
        assert result.success is True
        assert result.data == {"result": "ok"}
