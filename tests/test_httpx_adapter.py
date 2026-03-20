"""Tests for the httpx REST API adapter."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aegis.core.action import Action
from aegis.core.result import ResultStatus


@pytest.fixture
def mock_response():
    """Create a mock httpx response."""
    resp = MagicMock()
    resp.status_code = 200
    resp.is_success = True
    resp.headers = {"content-type": "application/json"}
    resp.json.return_value = {"id": 1, "name": "Alice"}
    resp.text = '{"id": 1, "name": "Alice"}'
    return resp


@pytest.fixture
def mock_error_response():
    """Create a mock error httpx response."""
    resp = MagicMock()
    resp.status_code = 404
    resp.is_success = False
    resp.headers = {"content-type": "application/json"}
    resp.json.return_value = {"error": "Not found"}
    resp.text = '{"error": "Not found"}'
    return resp


class TestHttpxExecutor:
    """Tests for HttpxExecutor."""

    @pytest.mark.asyncio
    async def test_get_request(self, mock_response):
        with patch.dict("sys.modules", {"httpx": MagicMock()}):
            from aegis.adapters.httpx_adapter import HttpxExecutor

            executor = HttpxExecutor(base_url="https://api.example.com")

            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_response)
            executor._client = mock_client

            action = Action("get", "/users/1")
            result = await executor.execute(action)

            assert result.status == ResultStatus.SUCCESS
            assert result.data["status_code"] == 200
            assert result.data["body"] == {"id": 1, "name": "Alice"}
            mock_client.request.assert_called_once()

    @pytest.mark.asyncio
    async def test_post_request(self, mock_response):
        with patch.dict("sys.modules", {"httpx": MagicMock()}):
            from aegis.adapters.httpx_adapter import HttpxExecutor

            executor = HttpxExecutor(base_url="https://api.example.com")

            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_response)
            executor._client = mock_client

            action = Action("post", "/users", params={"json": {"name": "Bob"}})
            result = await executor.execute(action)

            assert result.status == ResultStatus.SUCCESS
            mock_client.request.assert_called_once_with(
                "POST",
                "/users",
                json={"name": "Bob"},
                data=None,
                headers=None,
                params=None,
                timeout=None,
            )

    @pytest.mark.asyncio
    async def test_error_response(self, mock_error_response):
        with patch.dict("sys.modules", {"httpx": MagicMock()}):
            from aegis.adapters.httpx_adapter import HttpxExecutor

            executor = HttpxExecutor(base_url="https://api.example.com")

            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_error_response)
            executor._client = mock_client

            action = Action("get", "/users/999")
            result = await executor.execute(action)

            assert result.status == ResultStatus.FAILED
            assert result.data["status_code"] == 404
            assert result.error == "HTTP 404"

    @pytest.mark.asyncio
    async def test_unknown_method(self):
        with patch.dict("sys.modules", {"httpx": MagicMock()}):
            from aegis.adapters.httpx_adapter import HttpxExecutor

            executor = HttpxExecutor()

            mock_client = AsyncMock()
            executor._client = mock_client

            action = Action("foobar", "/test")
            result = await executor.execute(action)

            assert result.status == ResultStatus.FAILED
            assert "Unknown HTTP method" in result.error

    @pytest.mark.asyncio
    async def test_verify_success(self, mock_response):
        with patch.dict("sys.modules", {"httpx": MagicMock()}):
            from aegis.adapters.httpx_adapter import HttpxExecutor
            from aegis.core.result import Result

            executor = HttpxExecutor()
            action = Action("get", "/test")
            result = Result(
                action=action,
                status=ResultStatus.SUCCESS,
                data={"status_code": 200},
                completed_at=datetime.now(UTC),
            )
            assert await executor.verify(action, result) is True

    @pytest.mark.asyncio
    async def test_verify_failure(self):
        with patch.dict("sys.modules", {"httpx": MagicMock()}):
            from aegis.adapters.httpx_adapter import HttpxExecutor
            from aegis.core.result import Result

            executor = HttpxExecutor()
            action = Action("get", "/test")
            result = Result(
                action=action,
                status=ResultStatus.SUCCESS,
                data={"status_code": 500},
                completed_at=datetime.now(UTC),
            )
            assert await executor.verify(action, result) is False

    def test_import_guard(self):
        """HttpxExecutor should raise ImportError when httpx is not installed."""
        import sys

        # Temporarily hide httpx
        httpx_module = sys.modules.pop("httpx", None)
        sys.modules["httpx"] = None  # type: ignore[assignment]
        try:
            from aegis.adapters.httpx_adapter import _require_httpx

            with pytest.raises(ImportError, match="httpx"):
                _require_httpx()
        finally:
            if httpx_module:
                sys.modules["httpx"] = httpx_module
            else:
                sys.modules.pop("httpx", None)
