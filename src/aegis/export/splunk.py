"""Splunk HEC (HTTP Event Collector) exporter for AGEF events.

Sends AGEF-compliant events to a Splunk HEC endpoint using only stdlib
(``urllib.request``).  Supports single and batch event submission.

Example::

    exporter = SplunkHECExporter(
        hec_url="https://splunk.example.com:8088",
        token="your-hec-token",
        index="agent_governance",
    )
    exporter.send(agef_event)
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)


class SplunkHECExporter:
    """Export AGEF events to Splunk via the HTTP Event Collector.

    Args:
        hec_url: Base URL of the Splunk HEC endpoint
            (e.g. ``https://splunk.example.com:8088``).
        token: HEC authentication token.
        index: Splunk index to write to.
        source: ``source`` metadata field.
        sourcetype: ``sourcetype`` metadata field.
        timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        hec_url: str,
        token: str,
        *,
        index: str = "main",
        source: str = "aegis",
        sourcetype: str = "agef",
        timeout: float = 10.0,
    ) -> None:
        self._hec_url = hec_url.rstrip("/")
        self._token = token
        self._index = index
        self._source = source
        self._sourcetype = sourcetype
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send(self, agef_event: dict[str, Any]) -> None:
        """Send a single AGEF event to Splunk HEC.

        Wraps the event in the Splunk HEC JSON envelope and POSTs to
        ``/services/collector/event``.
        """
        payload = self._wrap_event(agef_event)
        self._post(json.dumps(payload, default=str))

    def send_batch(self, events: list[dict[str, Any]]) -> None:
        """Send multiple AGEF events to Splunk HEC in one request.

        Splunk HEC accepts newline-delimited JSON objects on the
        ``/services/collector/event`` endpoint.
        """
        if not events:
            return
        lines = [json.dumps(self._wrap_event(ev), default=str) for ev in events]
        self._post("\n".join(lines))

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _wrap_event(self, agef_event: dict[str, Any]) -> dict[str, Any]:
        """Wrap an AGEF event in a Splunk HEC JSON envelope."""
        return {
            "index": self._index,
            "source": self._source,
            "sourcetype": self._sourcetype,
            "event": agef_event,
        }

    def _post(self, body: str) -> None:
        """POST *body* to the HEC endpoint."""
        url = f"{self._hec_url}/services/collector/event"
        req = urllib.request.Request(
            url,
            data=body.encode("utf-8"),
            headers={
                "Authorization": f"Splunk {self._token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                resp.read()
        except urllib.error.URLError:
            logger.warning("Failed to send event(s) to Splunk HEC at %s", url, exc_info=True)
