"""Tests for the Playwright browser executor adapter."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from aegis.core.action import Action
from aegis.core.result import ResultStatus


class TestPlaywrightExecutor:
    """Tests for PlaywrightExecutor with mocked Playwright."""

    def _make_executor(self):
        """Create a PlaywrightExecutor instance."""
        from aegis.adapters.playwright import PlaywrightExecutor

        return PlaywrightExecutor(headless=True, browser_type="chromium")

    def _setup_executor_with_mock_browser(self):
        """Create an executor with a mock browser and page."""
        executor = self._make_executor()

        mock_page = AsyncMock()
        mock_page.is_closed.return_value = False
        mock_browser = AsyncMock()
        mock_browser.new_page = AsyncMock(return_value=mock_page)

        executor._browser = mock_browser
        executor._page = mock_page

        return executor, mock_page, mock_browser

    def test_constructor_stores_config(self):
        """Constructor should store headless and browser_type config."""
        executor = self._make_executor()
        assert executor._headless is True
        assert executor._browser_type == "chromium"
        assert executor._pw is None
        assert executor._browser is None
        assert executor._page is None

    def test_constructor_firefox(self):
        """Constructor should accept different browser types."""
        from aegis.adapters.playwright import PlaywrightExecutor

        executor = PlaywrightExecutor(headless=False, browser_type="firefox")
        assert executor._headless is False
        assert executor._browser_type == "firefox"

    @pytest.mark.asyncio
    async def test_teardown_closes_resources(self):
        """teardown() should close browser and stop Playwright."""
        executor = self._make_executor()

        mock_browser = AsyncMock()
        mock_pw = AsyncMock()

        executor._browser = mock_browser
        executor._pw = mock_pw
        executor._page = AsyncMock()

        await executor.teardown()

        mock_browser.close.assert_called_once()
        mock_pw.stop.assert_called_once()
        assert executor._browser is None
        assert executor._pw is None
        assert executor._page is None

    @pytest.mark.asyncio
    async def test_teardown_without_resources(self):
        """teardown() should handle None resources gracefully."""
        executor = self._make_executor()
        executor._browser = None
        executor._pw = None
        executor._page = None

        await executor.teardown()  # Should not raise

    @pytest.mark.asyncio
    async def test_execute_without_browser_raises(self):
        """execute() without setup should raise RuntimeError."""
        executor = self._make_executor()
        action = Action("navigate", "test", params={"url": "https://example.com"})

        with pytest.raises(RuntimeError, match="not set up"):
            await executor.execute(action)

    @pytest.mark.asyncio
    async def test_execute_navigate(self):
        """navigate action should call page.goto."""
        executor, mock_page, _ = self._setup_executor_with_mock_browser()

        mock_response = MagicMock()
        mock_response.status = 200
        mock_page.goto = AsyncMock(return_value=mock_response)

        action = Action("navigate", "test", params={"url": "https://example.com"})
        result = await executor.execute(action)

        assert result.status == ResultStatus.SUCCESS
        assert result.data["url"] == "https://example.com"
        assert result.data["status"] == 200
        mock_page.goto.assert_called_once_with("https://example.com")

    @pytest.mark.asyncio
    async def test_execute_navigate_no_response(self):
        """navigate should handle None response."""
        executor, mock_page, _ = self._setup_executor_with_mock_browser()

        mock_page.goto = AsyncMock(return_value=None)

        action = Action("navigate", "test", params={"url": "https://example.com"})
        result = await executor.execute(action)

        assert result.status == ResultStatus.SUCCESS
        assert result.data["status"] is None

    @pytest.mark.asyncio
    async def test_execute_click(self):
        """click action should call page.click."""
        executor, mock_page, _ = self._setup_executor_with_mock_browser()

        mock_page.click = AsyncMock()

        action = Action("click", "test", params={"selector": "#submit"})
        result = await executor.execute(action)

        assert result.status == ResultStatus.SUCCESS
        assert result.data["selector"] == "#submit"
        mock_page.click.assert_called_once_with("#submit")

    @pytest.mark.asyncio
    async def test_execute_fill(self):
        """fill action should call page.fill."""
        executor, mock_page, _ = self._setup_executor_with_mock_browser()

        mock_page.fill = AsyncMock()

        action = Action("fill", "test", params={"selector": "#email", "value": "test@test.com"})
        result = await executor.execute(action)

        assert result.status == ResultStatus.SUCCESS
        assert result.data["selector"] == "#email"
        assert result.data["value"] == "test@test.com"
        mock_page.fill.assert_called_once_with("#email", "test@test.com")

    @pytest.mark.asyncio
    async def test_execute_read(self):
        """read action should call page.text_content."""
        executor, mock_page, _ = self._setup_executor_with_mock_browser()

        mock_page.text_content = AsyncMock(return_value="Hello World")

        action = Action("read", "test", params={"selector": ".content"})
        result = await executor.execute(action)

        assert result.status == ResultStatus.SUCCESS
        assert result.data["selector"] == ".content"
        assert result.data["text"] == "Hello World"

    @pytest.mark.asyncio
    async def test_execute_screenshot(self):
        """screenshot action should call page.screenshot with resolved path."""
        executor, mock_page, _ = self._setup_executor_with_mock_browser()

        mock_page.screenshot = AsyncMock()

        action = Action("screenshot", "test", params={"path": "/tmp/screen.png"})
        result = await executor.execute(action)

        assert result.status == ResultStatus.SUCCESS
        assert result.data["path"].endswith("/tmp/screen.png")
        mock_page.screenshot.assert_called_once_with(path=result.data["path"])

    @pytest.mark.asyncio
    async def test_execute_screenshot_default_path(self):
        """screenshot with no path should use default."""
        executor, mock_page, _ = self._setup_executor_with_mock_browser()

        mock_page.screenshot = AsyncMock()

        action = Action("screenshot", "test", params={})
        result = await executor.execute(action)

        assert result.status == ResultStatus.SUCCESS
        # Default resolves to absolute path
        assert result.data["path"].endswith("screenshot.png")

    @pytest.mark.asyncio
    async def test_execute_screenshot_path_traversal_blocked(self):
        """screenshot with path traversal should be rejected."""
        executor, mock_page, _ = self._setup_executor_with_mock_browser()

        mock_page.screenshot = AsyncMock()

        action = Action("screenshot", "test", params={"path": "../../etc/passwd.png"})
        result = await executor.execute(action)

        assert result.status == ResultStatus.FAILED
        assert "traversal" in result.error.lower()
        mock_page.screenshot.assert_not_called()

    @pytest.mark.asyncio
    async def test_execute_screenshot_dotdot_in_middle_blocked(self):
        """screenshot with .. in middle of path should be rejected."""
        executor, mock_page, _ = self._setup_executor_with_mock_browser()

        mock_page.screenshot = AsyncMock()

        action = Action("screenshot", "test", params={"path": "/tmp/safe/../../../etc/out.png"})
        result = await executor.execute(action)

        assert result.status == ResultStatus.FAILED
        assert "traversal" in result.error.lower()
        mock_page.screenshot.assert_not_called()

    @pytest.mark.asyncio
    async def test_execute_unsupported_action(self):
        """Unsupported action types should return FAILED."""
        executor, _, _ = self._setup_executor_with_mock_browser()

        action = Action("unsupported", "test", params={})
        result = await executor.execute(action)

        assert result.status == ResultStatus.FAILED
        assert "Unsupported action type" in result.error

    @pytest.mark.asyncio
    async def test_execute_handler_exception(self):
        """Exceptions in handlers should be caught and return FAILED."""
        executor, mock_page, _ = self._setup_executor_with_mock_browser()

        mock_page.goto = AsyncMock(side_effect=Exception("Network error"))

        action = Action("navigate", "test", params={"url": "https://example.com"})
        result = await executor.execute(action)

        assert result.status == ResultStatus.FAILED
        assert "Network error" in result.error

    @pytest.mark.asyncio
    async def test_ensure_page_creates_new_page(self):
        """_ensure_page should create a new page if none exists."""
        executor = self._make_executor()

        mock_page = AsyncMock()
        mock_browser = AsyncMock()
        mock_browser.new_page = AsyncMock(return_value=mock_page)

        executor._browser = mock_browser
        executor._page = None

        page = await executor._ensure_page()

        assert page is mock_page
        mock_browser.new_page.assert_called_once()

    @pytest.mark.asyncio
    async def test_ensure_page_creates_new_when_closed(self):
        """_ensure_page should create a new page if the current one is closed."""
        executor = self._make_executor()

        old_page = MagicMock()
        old_page.is_closed.return_value = True

        new_page = AsyncMock()
        mock_browser = AsyncMock()
        mock_browser.new_page = AsyncMock(return_value=new_page)

        executor._browser = mock_browser
        executor._page = old_page

        page = await executor._ensure_page()

        assert page is new_page
        mock_browser.new_page.assert_called_once()

    @pytest.mark.asyncio
    async def test_ensure_page_reuses_existing(self):
        """_ensure_page should reuse an open page."""
        executor = self._make_executor()

        existing_page = MagicMock()
        existing_page.is_closed.return_value = False

        mock_browser = AsyncMock()
        executor._browser = mock_browser
        executor._page = existing_page

        page = await executor._ensure_page()

        assert page is existing_page
        mock_browser.new_page.assert_not_called()

    def test_playwright_import_guard(self):
        """_require_playwright should raise ImportError if playwright is missing."""
        import sys

        pw_module = sys.modules.pop("playwright", None)
        sys.modules["playwright"] = None  # type: ignore[assignment]
        try:
            from aegis.adapters.playwright import _require_playwright

            with pytest.raises(ImportError, match="Playwright"):
                _require_playwright()
        finally:
            if pw_module:
                sys.modules["playwright"] = pw_module
            else:
                sys.modules.pop("playwright", None)
