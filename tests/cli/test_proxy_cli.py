"""Tests for ``aegis proxy`` CLI command."""

from __future__ import annotations

import pytest

from aegis.cli.main import main


class TestProxyCLI:
    def test_proxy_no_upstream_exits_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        """aegis proxy without --upstream or --config should fail."""
        with pytest.raises(SystemExit) as exc_info:
            main(["proxy", "--mode", "permissive"])
        assert exc_info.value.code == 1
        err = capsys.readouterr().err
        assert "upstream" in err.lower() or "config" in err.lower()

    def test_proxy_help(self, capsys: pytest.CaptureFixture[str]) -> None:
        """aegis proxy --help should work."""
        with pytest.raises(SystemExit) as exc_info:
            main(["proxy", "--help"])
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "proxy" in out.lower()
