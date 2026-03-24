"""Tests for the Splunk HEC exporter."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

from aegis.export.splunk import SplunkHECExporter


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


def _make_exporter(**kwargs: Any) -> SplunkHECExporter:
    return SplunkHECExporter(
        hec_url="https://splunk.example.com:8088",
        token="test-token-123",
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Payload format
# ---------------------------------------------------------------------------


class TestPayloadFormat:
    def test_single_event_envelope(self) -> None:
        exporter = _make_exporter(index="governance", source="aegis", sourcetype="agef")
        payload = exporter._wrap_event(_sample_agef_event())

        assert payload["index"] == "governance"
        assert payload["source"] == "aegis"
        assert payload["sourcetype"] == "agef"
        assert payload["event"]["agef_version"] == "1.0.0"
        assert payload["event"]["event_type"] == "policy_decision"

    def test_default_metadata(self) -> None:
        exporter = _make_exporter()
        payload = exporter._wrap_event(_sample_agef_event())
        assert payload["index"] == "main"
        assert payload["source"] == "aegis"
        assert payload["sourcetype"] == "agef"


# ---------------------------------------------------------------------------
# HTTP calls (mocked)
# ---------------------------------------------------------------------------


class TestHTTPCalls:
    @patch("aegis.export.splunk.urllib.request.urlopen")
    def test_send_posts_to_hec_endpoint(self, mock_urlopen: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        exporter = _make_exporter()
        exporter.send(_sample_agef_event())

        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "https://splunk.example.com:8088/services/collector/event"
        assert req.get_header("Authorization") == "Splunk test-token-123"
        assert req.get_header("Content-type") == "application/json"

        body = json.loads(req.data.decode("utf-8"))
        assert body["event"]["agef_version"] == "1.0.0"

    @patch("aegis.export.splunk.urllib.request.urlopen")
    def test_send_batch_newline_delimited(self, mock_urlopen: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        exporter = _make_exporter()
        events = [
            _sample_agef_event(event_id="id-1"),
            _sample_agef_event(event_id="id-2"),
            _sample_agef_event(event_id="id-3"),
        ]
        exporter.send_batch(events)

        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        raw = req.data.decode("utf-8")
        lines = raw.split("\n")
        assert len(lines) == 3
        for line in lines:
            parsed = json.loads(line)
            assert "event" in parsed
            assert parsed["event"]["agef_version"] == "1.0.0"

    @patch("aegis.export.splunk.urllib.request.urlopen")
    def test_send_batch_empty_is_noop(self, mock_urlopen: MagicMock) -> None:
        exporter = _make_exporter()
        exporter.send_batch([])
        mock_urlopen.assert_not_called()

    @patch("aegis.export.splunk.urllib.request.urlopen")
    def test_send_failure_does_not_raise(self, mock_urlopen: MagicMock) -> None:
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("connection refused")

        exporter = _make_exporter()
        # Should not raise
        exporter.send(_sample_agef_event())

    def test_trailing_slash_stripped_from_url(self) -> None:
        exporter = SplunkHECExporter(
            hec_url="https://splunk.example.com:8088/",
            token="tok",
        )
        assert exporter._hec_url == "https://splunk.example.com:8088"
