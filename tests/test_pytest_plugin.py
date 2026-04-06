"""Tests for the pytest-aegis plugin."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis.pytest_plugin import pytest_addoption, pytest_collection_finish, pytest_report_header


class FakeOption:
    """Minimal mock for pytest config option access."""

    def __init__(self, **kwargs: object) -> None:
        self._opts = kwargs

    def getoption(self, name: str, default: object = None) -> object:
        return self._opts.get(name, default)


class FakeConfig:
    def __init__(self, **kwargs: object) -> None:
        self._option = FakeOption(**kwargs)
        self.stash: dict[object, object] = {}

    def getoption(self, name: str, default: object = None) -> object:
        return self._option.getoption(name, default)


class FakeSession:
    def __init__(self, **kwargs: object) -> None:
        self.config = FakeConfig(**kwargs)


class TestPluginOptions:
    def test_addoption_registers_flags(self) -> None:
        """pytest_addoption should register aegis flags."""
        registered: list[str] = []

        class FakeGroup:
            def addoption(self, *args: object, **kwargs: object) -> None:
                registered.append(str(args[0]))

        class FakeParser:
            def getgroup(self, name: str, description: str = "") -> FakeGroup:
                return FakeGroup()

        pytest_addoption(FakeParser())  # type: ignore[arg-type]
        assert "--aegis-scan" in registered
        assert "--aegis-threshold" in registered
        assert "--aegis-scan-dir" in registered


class TestPluginScan:
    def test_noop_when_disabled(self) -> None:
        """Plugin does nothing when --aegis-scan is not set."""
        session = FakeSession(aegis_scan=False)
        # Should return without error
        pytest_collection_finish(session)  # type: ignore[arg-type]

    def test_scan_runs_on_clean_dir(self, tmp_path: Path) -> None:
        """Clean directory (no AI calls) produces no failure."""
        (tmp_path / "clean.py").write_text("x = 1\n")
        session = FakeSession(
            aegis_scan=True,
            aegis_threshold="F",
            aegis_scan_dir=str(tmp_path),
        )
        # Should not raise
        pytest_collection_finish(session)  # type: ignore[arg-type]

    def test_scan_detects_ungoverned_calls(self, tmp_path: Path) -> None:
        """Directory with ungoverned calls triggers finding."""
        (tmp_path / "agent.py").write_text(
            "from openai import OpenAI\n"
            "client = OpenAI()\n"
            "client.chat.completions.create(model='gpt-4', tools=[{'type': 'function'}])\n"
        )
        session = FakeSession(
            aegis_scan=True,
            aegis_threshold="A",
            aegis_scan_dir=str(tmp_path),
        )
        with pytest.raises(pytest.fail.Exception, match="ungoverned"):
            pytest_collection_finish(session)  # type: ignore[arg-type]

    def test_threshold_f_never_fails(self, tmp_path: Path) -> None:
        """Threshold F means scan runs but never fails."""
        (tmp_path / "agent.py").write_text("import subprocess\nsubprocess.run(['echo'])\n")
        session = FakeSession(
            aegis_scan=True,
            aegis_threshold="F",
            aegis_scan_dir=str(tmp_path),
        )
        # F threshold should never fail
        pytest_collection_finish(session)  # type: ignore[arg-type]


class TestPluginHeader:
    def test_header_when_enabled(self) -> None:
        config = FakeConfig(aegis_scan=True, aegis_threshold="C")
        lines = pytest_report_header(config)  # type: ignore[arg-type]
        assert any("aegis: scan enabled" in ln for ln in lines)

    def test_no_header_when_disabled(self) -> None:
        config = FakeConfig(aegis_scan=False)
        lines = pytest_report_header(config)  # type: ignore[arg-type]
        assert lines == []
