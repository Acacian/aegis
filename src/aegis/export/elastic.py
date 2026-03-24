"""Elasticsearch exporter for AGEF events.

Indexes AGEF-compliant events into Elasticsearch using only stdlib
(``urllib.request``).  Supports single-document indexing and the
``_bulk`` API for batch operations.

Example::

    exporter = ElasticsearchExporter(
        es_url="https://es.example.com:9200",
        index="aegis-agef",
        api_key="base64-encoded-api-key",
    )
    exporter.send(agef_event)
"""

from __future__ import annotations

import base64
import json
import logging
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)


class ElasticsearchExporter:
    """Export AGEF events to Elasticsearch.

    Supports API-key auth, basic auth (username/password), or no auth.

    Args:
        es_url: Base URL of the Elasticsearch cluster
            (e.g. ``https://es.example.com:9200``).
        index: Target index name.
        api_key: Elasticsearch API key (Base64-encoded ``id:api_key``).
        username: Basic-auth username.
        password: Basic-auth password.
        timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        es_url: str,
        *,
        index: str = "aegis-agef",
        api_key: str | None = None,
        username: str | None = None,
        password: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._es_url = es_url.rstrip("/")
        self._index = index
        self._api_key = api_key
        self._username = username
        self._password = password
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send(self, agef_event: dict[str, Any]) -> None:
        """Index a single AGEF event into Elasticsearch.

        Uses ``POST /<index>/_doc`` with the ``event_id`` as the
        document ``_id`` for idempotent upserts.
        """
        doc_id = agef_event.get("event_id", "")
        url = f"{self._es_url}/{self._index}/_doc/{doc_id}"
        body = json.dumps(agef_event, default=str)
        self._request(url, body)

    def send_batch(self, events: list[dict[str, Any]]) -> None:
        """Bulk index AGEF events using the ``_bulk`` API.

        Each event is indexed with its ``event_id`` as the document
        ``_id``.
        """
        if not events:
            return
        lines: list[str] = []
        for ev in events:
            meta = {"index": {"_index": self._index, "_id": ev.get("event_id", "")}}
            lines.append(json.dumps(meta, default=str))
            lines.append(json.dumps(ev, default=str))
        # _bulk body must end with a newline
        body = "\n".join(lines) + "\n"
        url = f"{self._es_url}/_bulk"
        self._request(url, body)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        """Build authentication headers."""
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"ApiKey {self._api_key}"
        elif self._username and self._password:
            creds = base64.b64encode(f"{self._username}:{self._password}".encode()).decode()
            headers["Authorization"] = f"Basic {creds}"
        return headers

    def _request(self, url: str, body: str) -> None:
        """Send an HTTP request to Elasticsearch."""
        req = urllib.request.Request(
            url,
            data=body.encode("utf-8"),
            headers=self._auth_headers(),
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                resp.read()
        except urllib.error.URLError:
            logger.warning("Failed to send event(s) to Elasticsearch at %s", url, exc_info=True)
