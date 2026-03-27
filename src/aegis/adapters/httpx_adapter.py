"""httpx-based REST API adapter.

Executes actions as HTTP requests, mapping action types to HTTP methods.

Example::

    executor = HttpxExecutor(base_url="https://api.example.com")
    runtime = Runtime(executor=executor, policy=Policy.from_yaml("policy.yaml"))

    plan = runtime.plan([
        Action("get", target="/users", params={"headers": {"Authorization": "Bearer ..."}}),
        Action("post", target="/users", params={"json": {"name": "Alice"}}),
    ])
    results = await runtime.execute(plan)
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from aegis.adapters.base import BaseExecutor
from aegis.core.action import Action
from aegis.core.result import Result, ResultStatus

logger = logging.getLogger(__name__)

_METHOD_MAP = {
    "get": "GET",
    "post": "POST",
    "put": "PUT",
    "patch": "PATCH",
    "delete": "DELETE",
    "head": "HEAD",
    "options": "OPTIONS",
}


def _is_private_ip(hostname: str) -> bool:
    """Check whether *hostname* resolves to a private/reserved IP address."""
    try:
        addr = ipaddress.ip_address(hostname)
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local
    except ValueError:
        pass
    # hostname is not a literal IP — resolve it
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        for _family, _type, _proto, _canonname, sockaddr in infos:
            addr = ipaddress.ip_address(sockaddr[0])
            if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
                return True
    except socket.gaierror:
        pass
    return False


def _require_httpx() -> None:
    try:
        import httpx  # noqa: F401
    except ImportError as e:
        msg = "httpx is required for HttpxExecutor. Install with: pip install 'agent-aegis[httpx]'"
        raise ImportError(msg) from e


class HttpxExecutor(BaseExecutor):
    """Execute actions as HTTP requests using httpx.

    The action ``type`` is mapped to an HTTP method (get, post, put, patch, delete).
    The action ``target`` is used as the URL path (appended to ``base_url``).

    Supported ``params`` keys:
        - ``json``: JSON body for POST/PUT/PATCH
        - ``data``: Form data body
        - ``headers``: Additional request headers
        - ``query``: Query parameters
        - ``timeout``: Per-request timeout in seconds

    Args:
        base_url: Base URL prepended to action targets.
        default_headers: Headers sent with every request.
        timeout: Default timeout in seconds.
    """

    def __init__(
        self,
        base_url: str = "",
        default_headers: dict[str, str] | None = None,
        timeout: float = 30.0,
    ) -> None:
        _require_httpx()
        self._base_url = base_url.rstrip("/")
        self._default_headers = default_headers or {}
        self._timeout = timeout
        self._client: Any = None

    async def setup(self) -> None:
        """Create the httpx async client."""
        import httpx

        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers=self._default_headers,
            timeout=self._timeout,
        )

    async def teardown(self) -> None:
        """Close the httpx async client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def execute(self, action: Action) -> Result:
        """Execute an HTTP request based on the action."""
        if self._client is None:
            await self.setup()

        method = _METHOD_MAP.get(action.type.lower())
        if not method:
            return Result(
                action=action,
                status=ResultStatus.FAILED,
                error=f"Unknown HTTP method for action type: {action.type}",
                completed_at=datetime.now(UTC),
            )

        url = action.target
        params = action.params

        # SSRF guard: when no base_url is configured, the target is a full URL
        # and we must reject requests to private/internal networks.
        if not self._base_url:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            if _is_private_ip(hostname):
                raise ValueError(
                    f"Requests to private/internal IP addresses are blocked: {hostname}"
                )

        assert self._client is not None

        try:
            import httpx

            response: httpx.Response = await self._client.request(
                method,
                url,
                json=params.get("json"),
                data=params.get("data"),
                headers=params.get("headers"),
                params=params.get("query"),
                timeout=params.get("timeout"),
            )

            data: dict[str, Any] = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
            }

            # Try to parse JSON response
            try:
                data["body"] = response.json()
            except (ValueError, TypeError):
                data["body"] = response.text

            status = ResultStatus.SUCCESS if response.is_success else ResultStatus.FAILED
            error = None if response.is_success else f"HTTP {response.status_code}"

            return Result(
                action=action,
                status=status,
                data=data,
                error=error,
                completed_at=datetime.now(UTC),
            )

        except Exception as e:
            return Result(
                action=action,
                status=ResultStatus.FAILED,
                error=str(e),
                completed_at=datetime.now(UTC),
            )

    async def verify(self, action: Action, result: Result) -> bool:
        """Verify HTTP response is successful (2xx status code)."""
        if not result.ok or not result.data:
            return False
        status_code: int = result.data.get("status_code", 0)
        return 200 <= status_code < 300
