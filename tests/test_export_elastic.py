"""Tests for the Elasticsearch exporter."""

from __future__ import annotations

import base64
import json
from typing import Any
from unittest.mock import MagicMock, patch

from aegis.export.elastic import ElasticsearchExporter


def _sample_agef_event(**overrides: object) -> dict[str, Any]:
    """Build a minimal AGEF event dict for testing."""
    base: dict[str, Any] = {
        "agef_version": "1.0.0",
        "event_id": "test-uuid-001",
        "timestamp": "2026-03-24T10:30:00+00:00",
        "event_type": "policy_decision",
        "action": {"type": "db_query", "target": "salesforce"},
        "decision": {"outcome": "allowed", "risk_level": "LOW"},
    }
    base.update(overrides)
    return base


def _make_exporter(**kwargs: Any) -> ElasticsearchExporter:
    return ElasticsearchExporter(
        es_url="https://es.example.com:9200",
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Document format
# ---------------------------------------------------------------------------


class TestDocumentFormat:
    @patch("aegis.export.elastic.urllib.request.urlopen")
    def test_single_document_url(self, mock_urlopen: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        exporter = _make_exporter(index="aegis-agef")
        exporter.send(_sample_agef_event(event_id="ev-123"))

        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "https://es.example.com:9200/aegis-agef/_doc/ev-123"
        body = json.loads(req.data.decode("utf-8"))
        assert body["agef_version"] == "1.0.0"
        assert body["event_id"] == "ev-123"

    @patch("aegis.export.elastic.urllib.request.urlopen")
    def test_single_document_content_type(self, mock_urlopen: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        exporter = _make_exporter()
        exporter.send(_sample_agef_event())

        req = mock_urlopen.call_args[0][0]
        assert req.get_header("Content-type") == "application/json"


# ---------------------------------------------------------------------------
# Bulk API format
# ---------------------------------------------------------------------------


class TestBulkFormat:
    @patch("aegis.export.elastic.urllib.request.urlopen")
    def test_bulk_payload_format(self, mock_urlopen: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        exporter = _make_exporter(index="my-index")
        events = [
            _sample_agef_event(event_id="id-1"),
            _sample_agef_event(event_id="id-2"),
        ]
        exporter.send_batch(events)

        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "https://es.example.com:9200/_bulk"

        raw = req.data.decode("utf-8")
        # _bulk body must end with a newline
        assert raw.endswith("\n")

        lines = raw.strip().split("\n")
        # 2 events -> 4 lines (meta + doc for each)
        assert len(lines) == 4

        # First pair: meta + doc
        meta1 = json.loads(lines[0])
        assert meta1["index"]["_index"] == "my-index"
        assert meta1["index"]["_id"] == "id-1"
        doc1 = json.loads(lines[1])
        assert doc1["event_id"] == "id-1"

        # Second pair
        meta2 = json.loads(lines[2])
        assert meta2["index"]["_id"] == "id-2"
        doc2 = json.loads(lines[3])
        assert doc2["event_id"] == "id-2"

    @patch("aegis.export.elastic.urllib.request.urlopen")
    def test_batch_empty_is_noop(self, mock_urlopen: MagicMock) -> None:
        exporter = _make_exporter()
        exporter.send_batch([])
        mock_urlopen.assert_not_called()


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


class TestAuthentication:
    def test_api_key_auth_header(self) -> None:
        exporter = _make_exporter(api_key="my-encoded-key")
        headers = exporter._auth_headers()
        assert headers["Authorization"] == "ApiKey my-encoded-key"

    def test_basic_auth_header(self) -> None:
        exporter = _make_exporter(username="elastic", password="secret")
        headers = exporter._auth_headers()
        expected = base64.b64encode(b"elastic:secret").decode()
        assert headers["Authorization"] == f"Basic {expected}"

    def test_no_auth_header(self) -> None:
        exporter = _make_exporter()
        headers = exporter._auth_headers()
        assert "Authorization" not in headers

    def test_api_key_takes_precedence_over_basic(self) -> None:
        exporter = _make_exporter(
            api_key="my-key",
            username="elastic",
            password="secret",
        )
        headers = exporter._auth_headers()
        assert headers["Authorization"].startswith("ApiKey")


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    @patch("aegis.export.elastic.urllib.request.urlopen")
    def test_send_failure_does_not_raise(self, mock_urlopen: MagicMock) -> None:
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("connection refused")

        exporter = _make_exporter()
        # Should not raise
        exporter.send(_sample_agef_event())

    def test_trailing_slash_stripped_from_url(self) -> None:
        exporter = ElasticsearchExporter(es_url="https://es.example.com:9200/")
        assert exporter._es_url == "https://es.example.com:9200"
