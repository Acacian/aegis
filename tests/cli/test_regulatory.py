"""Tests for ``aegis regulatory`` CLI command."""

from __future__ import annotations

import json

import pytest

from aegis.cli.main import main

# ---------------------------------------------------------------------------
# Table output
# ---------------------------------------------------------------------------


def test_regulatory_eu_ai_act_table(capsys: pytest.CaptureFixture[str]) -> None:
    """Table output for a single framework includes coverage and gaps."""
    main(["regulatory", "--framework", "eu-ai-act"])
    out = capsys.readouterr().out

    assert "EU AI Act" in out
    assert "Coverage Score:" in out
    assert "%" in out


def test_regulatory_all_frameworks_table(capsys: pytest.CaptureFixture[str]) -> None:
    """--framework all runs every framework."""
    main(["regulatory", "--framework", "all"])
    out = capsys.readouterr().out

    assert "EU AI Act" in out
    assert "NIST AI RMF" in out
    assert "SOC2" in out
    assert "ISO 42001" in out


def test_regulatory_default_is_all(capsys: pytest.CaptureFixture[str]) -> None:
    """No --framework flag defaults to all."""
    main(["regulatory"])
    out = capsys.readouterr().out

    assert "EU AI Act" in out
    assert "SOC2" in out


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


def test_regulatory_json_output(capsys: pytest.CaptureFixture[str]) -> None:
    """JSON output for all frameworks is valid JSON."""
    main(["regulatory", "--format", "json"])
    out = capsys.readouterr().out

    data = json.loads(out)
    assert isinstance(data, list)
    assert len(data) == 4  # four frameworks
    for entry in data:
        assert "framework" in entry
        assert "summary" in entry
        assert "coverage_score" in entry["summary"]


def test_regulatory_json_single_framework(capsys: pytest.CaptureFixture[str]) -> None:
    """JSON output for a single framework is a dict (not a list)."""
    main(["regulatory", "--framework", "soc2", "--format", "json"])
    out = capsys.readouterr().out

    data = json.loads(out)
    assert isinstance(data, dict)
    assert "summary" in data
    assert "coverage_score" in data["summary"]


# ---------------------------------------------------------------------------
# Markdown output
# ---------------------------------------------------------------------------


def test_regulatory_markdown_output(capsys: pytest.CaptureFixture[str]) -> None:
    """Markdown output contains report headers."""
    main(["regulatory", "--framework", "nist", "--format", "markdown"])
    out = capsys.readouterr().out

    assert "# Compliance Gap Analysis" in out
    assert "## Executive Summary" in out
    assert "Coverage Score" in out


def test_regulatory_markdown_all(capsys: pytest.CaptureFixture[str]) -> None:
    """Markdown output for all frameworks produces multiple reports."""
    main(["regulatory", "--format", "markdown"])
    out = capsys.readouterr().out

    # Should have at least 4 top-level headings (one per framework)
    assert out.count("# Compliance Gap Analysis") >= 4


# ---------------------------------------------------------------------------
# Features filtering
# ---------------------------------------------------------------------------


def test_regulatory_features_filter(capsys: pytest.CaptureFixture[str]) -> None:
    """Limiting features reduces coverage."""
    # Full features
    main(["regulatory", "--framework", "eu-ai-act", "--format", "json"])
    full_out = capsys.readouterr().out
    full_data = json.loads(full_out)
    full_score = full_data["summary"]["coverage_score"]

    # Limited features
    main(
        [
            "regulatory",
            "--framework",
            "eu-ai-act",
            "--format",
            "json",
            "--features",
            "policy_engine,audit_logging",
        ]
    )
    limited_out = capsys.readouterr().out
    limited_data = json.loads(limited_out)
    limited_score = limited_data["summary"]["coverage_score"]

    assert limited_score <= full_score


def test_regulatory_features_in_table(capsys: pytest.CaptureFixture[str]) -> None:
    """Features flag works with table output."""
    main(
        [
            "regulatory",
            "--framework",
            "eu-ai-act",
            "--features",
            "policy_engine,audit_logging",
        ]
    )
    out = capsys.readouterr().out

    assert "EU AI Act" in out
    assert "Coverage Score:" in out
