"""Tests for aegis.server.cli — aegis-server entry point."""

from __future__ import annotations

from aegis.server.cli import _find_config, main


def test_version(capsys):
    main(["--version"])
    out = capsys.readouterr().out
    assert "aegis-server" in out


def test_init_creates_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    main(["--init"])
    config_file = tmp_path / "aegis-server.yaml"
    assert config_file.exists()
    content = config_file.read_text()
    assert "server:" in content
    assert "audit:" in content
    assert "agents:" in content


def test_init_refuses_overwrite(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "aegis-server.yaml").write_text("existing")
    import pytest

    with pytest.raises(SystemExit):
        main(["--init"])


def test_find_config_returns_none(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert _find_config() is None


def test_find_config_finds_yaml(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "aegis-server.yaml").write_text("server:\n  port: 8000")
    assert _find_config() == "aegis-server.yaml"
