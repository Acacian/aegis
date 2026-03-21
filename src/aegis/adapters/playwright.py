"""Playwright browser executor."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aegis.adapters.base import BaseExecutor
from aegis.core.action import Action
from aegis.core.result import Result, ResultStatus

if TYPE_CHECKING:
    from playwright.async_api import Browser, Page, Playwright


def _require_playwright() -> None:
    """Raise a helpful error if playwright is not installed."""
    try:
        import playwright  # noqa: F401
    except ImportError:
        raise ImportError(
            "Playwright is required for PlaywrightExecutor. "
            "Install it with: pip install 'aegis[playwright]'"
        ) from None


class PlaywrightExecutor(BaseExecutor):
    """Executes browser-based actions via Playwright.

    Supported action types:
        - navigate: Go to a URL. params: ``{"url": str}``
        - click: Click an element. params: ``{"selector": str}``
        - fill: Fill an input. params: ``{"selector": str, "value": str}``
        - read: Extract text content. params: ``{"selector": str}``
        - screenshot: Take a screenshot. params: ``{"path": str}`` (optional)

    Args:
        headless: Whether to run the browser in headless mode.
        browser_type: Which browser engine to use (chromium, firefox, webkit).
    """

    def __init__(
        self,
        *,
        headless: bool = True,
        browser_type: str = "chromium",
    ) -> None:
        self._headless = headless
        self._browser_type = browser_type
        self._pw: Playwright | None = None
        self._browser: Browser | None = None
        self._page: Page | None = None

    async def setup(self) -> None:
        """Launch the browser."""
        _require_playwright()
        from playwright.async_api import async_playwright

        self._pw = await async_playwright().start()
        launcher = getattr(self._pw, self._browser_type)
        self._browser = await launcher.launch(headless=self._headless)

    async def teardown(self) -> None:
        """Close the browser and stop Playwright."""
        if self._browser:
            await self._browser.close()
        if self._pw:
            await self._pw.stop()
        self._page = None
        self._browser = None
        self._pw = None

    async def execute(self, action: Action) -> Result:
        """Execute a browser action."""
        if not self._browser:
            raise RuntimeError("Executor not set up. Call setup() first or use Runtime.")

        dispatch: dict[str, Any] = {
            "navigate": self._do_navigate,
            "click": self._do_click,
            "fill": self._do_fill,
            "read": self._do_read,
            "screenshot": self._do_screenshot,
        }

        handler = dispatch.get(action.type)
        if not handler:
            return Result(
                action=action,
                status=ResultStatus.FAILED,
                error=f"Unsupported action type for Playwright: {action.type}",
                completed_at=datetime.now(UTC),
            )

        try:
            data = await handler(action)
            return Result(
                action=action,
                status=ResultStatus.SUCCESS,
                data=data,
                completed_at=datetime.now(UTC),
            )
        except Exception as e:
            return Result(
                action=action,
                status=ResultStatus.FAILED,
                error=str(e),
                completed_at=datetime.now(UTC),
            )

    # -- Page management -------------------------------------------------

    async def _ensure_page(self) -> Page:
        """Return the current page, creating one if needed."""
        assert self._browser is not None
        if self._page is None or self._page.is_closed():
            self._page = await self._browser.new_page()
        return self._page

    # -- Action handlers -------------------------------------------------

    async def _do_navigate(self, action: Action) -> dict[str, Any]:
        page = await self._ensure_page()
        url = action.params["url"]
        response = await page.goto(url)
        return {"url": url, "status": response.status if response else None}

    async def _do_click(self, action: Action) -> dict[str, Any]:
        page = await self._ensure_page()
        selector = action.params["selector"]
        await page.click(selector)
        return {"selector": selector}

    async def _do_fill(self, action: Action) -> dict[str, Any]:
        page = await self._ensure_page()
        selector = action.params["selector"]
        value = action.params["value"]
        await page.fill(selector, value)
        return {"selector": selector, "value": value}

    async def _do_read(self, action: Action) -> dict[str, Any]:
        page = await self._ensure_page()
        selector = action.params["selector"]
        text = await page.text_content(selector)
        return {"selector": selector, "text": text}

    async def _do_screenshot(self, action: Action) -> dict[str, Any]:
        page = await self._ensure_page()
        raw_path = action.params.get("path", "screenshot.png")
        resolved = Path(raw_path).resolve()
        allowed_dir = Path.cwd().resolve()
        if ".." in Path(raw_path).parts or not str(resolved).startswith(str(allowed_dir)):
            raise ValueError(f"Path traversal not allowed: {raw_path}")
        await page.screenshot(path=str(resolved))
        return {"path": str(resolved)}
