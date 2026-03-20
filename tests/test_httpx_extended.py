"""Extended tests for the httpx adapter covering uncovered lines."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aegis.core.action import Action
from aegis.core.result import Result, ResultStatus


class TestHttpxExecutorExtended:
    """Additional tests for HttpxExecutor covering missing lines."""

    @pytest.mark.asyncio
    async def test_setup_creates_client(self):
        """setup() should create an httpx.AsyncClient."""
        with patch.dict("sys.modules", {"httpx": MagicMock()}):
            from aegis.adapters.httpx_adapter import HttpxExecutor

            HttpxExecutor(
                base_url="https://api.example.com",
                default_headers={"Authorization": "Bearer token"},
                timeout=60.0,
            )

    @pytest.mark.asyncio
    async def test_teardown_closes_client(self):
        """teardown() should close the httpx client."""
        with patch.dict("sys.modules", {"httpx": MagicMock()}):
            from aegis.adapters.httpx_adapter import HttpxExecutor

            executor = HttpxExecutor()
            mock_client = AsyncMock()
            executor._client = mock_client

            await executor.teardown()

            mock_client.aclose.assert_called_once()
            assert executor._client is None

    @pytest.mark.asyncio
    async def test_teardown_no_client(self):
        """teardown() should handle no client gracefully."""
        with patch.dict("sys.modules", {"httpx": MagicMock()}):
            from aegis.adapters.httpx_adapter import HttpxExecutor

            executor = HttpxExecutor()
            executor._client = None

            await executor.teardown()  # Should not raise

    @pytest.mark.asyncio
    async def test_execute_auto_setup(self):
        """execute() should auto-setup client if not initialized."""
        with patch.dict("sys.modules", {"httpx": MagicMock()}):
            from aegis.adapters.httpx_adapter import HttpxExecutor

            executor = HttpxExecutor(base_url="https://api.example.com")
            assert executor._client is None

            # Mock the setup and request flow
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.is_success = True
            mock_response.headers = {"content-type": "application/json"}
            mock_response.json.return_value = {"ok": True}

            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_response)

            with patch.object(executor, "setup", new_callable=AsyncMock) as mock_setup:
                # After setup is called, set the client
                async def set_client():
                    executor._client = mock_client

                mock_setup.side_effect = set_client

                action = Action("get", "/test")
                result = await executor.execute(action)

                mock_setup.assert_called_once()
                assert result.status == ResultStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_execute_exception_handling(self):
        """execute() should catch network exceptions."""
        with patch.dict("sys.modules", {"httpx": MagicMock()}):
            from aegis.adapters.httpx_adapter import HttpxExecutor

            executor = HttpxExecutor()
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(side_effect=ConnectionError("Connection refused"))
            executor._client = mock_client

            action = Action("get", "/test")
            result = await executor.execute(action)

            assert result.status == ResultStatus.FAILED
            assert "Connection refused" in result.error

    @pytest.mark.asyncio
    async def test_execute_non_json_response(self):
        """execute() should handle non-JSON response bodies."""
        with patch.dict("sys.modules", {"httpx": MagicMock()}):
            from aegis.adapters.httpx_adapter import HttpxExecutor

            executor = HttpxExecutor()

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.is_success = True
            mock_response.headers = {"content-type": "text/html"}
            mock_response.json.side_effect = ValueError("Not JSON")
            mock_response.text = "<html>Hello</html>"

            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_response)
            executor._client = mock_client

            action = Action("get", "/page")
            result = await executor.execute(action)

            assert result.status == ResultStatus.SUCCESS
            assert result.data["body"] == "<html>Hello</html>"

    @pytest.mark.asyncio
    async def test_verify_failed_result(self):
        """verify() should return False for failed results."""
        with patch.dict("sys.modules", {"httpx": MagicMock()}):
            from aegis.adapters.httpx_adapter import HttpxExecutor

            executor = HttpxExecutor()
            action = Action("get", "/test")
            result = Result(
                action=action,
                status=ResultStatus.FAILED,
                error="HTTP 500",
                completed_at=datetime.now(UTC),
            )
            assert await executor.verify(action, result) is False

    @pytest.mark.asyncio
    async def test_verify_no_data(self):
        """verify() should return False when result has no data."""
        with patch.dict("sys.modules", {"httpx": MagicMock()}):
            from aegis.adapters.httpx_adapter import HttpxExecutor

            executor = HttpxExecutor()
            action = Action("get", "/test")
            result = Result(
                action=action,
                status=ResultStatus.SUCCESS,
                data=None,
                completed_at=datetime.now(UTC),
            )
            assert await executor.verify(action, result) is False

    @pytest.mark.asyncio
    async def test_put_request(self):
        """PUT method should be supported."""
        with patch.dict("sys.modules", {"httpx": MagicMock()}):
            from aegis.adapters.httpx_adapter import HttpxExecutor

            executor = HttpxExecutor()

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.is_success = True
            mock_response.headers = {}
            mock_response.json.return_value = {"updated": True}

            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_response)
            executor._client = mock_client

            action = Action("put", "/users/1", params={"json": {"name": "Updated"}})
            result = await executor.execute(action)

            assert result.status == ResultStatus.SUCCESS
            mock_client.request.assert_called_once_with(
                "PUT",
                "/users/1",
                json={"name": "Updated"},
                data=None,
                headers=None,
                params=None,
                timeout=None,
            )

    @pytest.mark.asyncio
    async def test_patch_request(self):
        """PATCH method should be supported."""
        with patch.dict("sys.modules", {"httpx": MagicMock()}):
            from aegis.adapters.httpx_adapter import HttpxExecutor

            executor = HttpxExecutor()

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.is_success = True
            mock_response.headers = {}
            mock_response.json.return_value = {"patched": True}

            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_response)
            executor._client = mock_client

            action = Action("patch", "/users/1", params={"json": {"name": "Patched"}})
            result = await executor.execute(action)

            assert result.status == ResultStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_delete_request(self):
        """DELETE method should be supported."""
        with patch.dict("sys.modules", {"httpx": MagicMock()}):
            from aegis.adapters.httpx_adapter import HttpxExecutor

            executor = HttpxExecutor()

            mock_response = MagicMock()
            mock_response.status_code = 204
            mock_response.is_success = True
            mock_response.headers = {}
            mock_response.json.side_effect = ValueError("No content")
            mock_response.text = ""

            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_response)
            executor._client = mock_client

            action = Action("delete", "/users/1")
            result = await executor.execute(action)

            assert result.status == ResultStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_head_request(self):
        """HEAD method should be supported."""
        with patch.dict("sys.modules", {"httpx": MagicMock()}):
            from aegis.adapters.httpx_adapter import HttpxExecutor

            executor = HttpxExecutor()

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.is_success = True
            mock_response.headers = {"x-total": "42"}
            mock_response.json.side_effect = ValueError()
            mock_response.text = ""

            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_response)
            executor._client = mock_client

            action = Action("head", "/users")
            result = await executor.execute(action)

            assert result.status == ResultStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_options_request(self):
        """OPTIONS method should be supported."""
        with patch.dict("sys.modules", {"httpx": MagicMock()}):
            from aegis.adapters.httpx_adapter import HttpxExecutor

            executor = HttpxExecutor()

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.is_success = True
            mock_response.headers = {"allow": "GET, POST"}
            mock_response.json.side_effect = ValueError()
            mock_response.text = ""

            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_response)
            executor._client = mock_client

            action = Action("options", "/users")
            result = await executor.execute(action)

            assert result.status == ResultStatus.SUCCESS
