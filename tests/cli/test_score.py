"""Tests for ``aegis score`` CLI command and scoring logic."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from aegis.cli.main import main
from aegis.cli.score import (
    ScoreResult,
    _to_grade,
    calculate_score,
)

# ---------------------------------------------------------------------------
# Grade mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (100, "A+"),
        (95, "A+"),
        (90, "A+"),
        (89, "A"),
        (80, "A"),
        (79, "B"),
        (70, "B"),
        (69, "C"),
        (60, "C"),
        (59, "D"),
        (50, "D"),
        (49, "F"),
        (0, "F"),
    ],
)
def test_grade_mapping(score: int, expected: str) -> None:
    assert _to_grade(score) == expected


# ---------------------------------------------------------------------------
# Scoring logic
# ---------------------------------------------------------------------------

_COMPREHENSIVE_POLICY = textwrap.dedent("""\
    version: "1"
    defaults:
      risk_level: high
      approval: approve
    rules:
      - name: read_auto
        match: { type: "read*" }
        risk_level: low
        approval: auto
      - name: get_auto
        match: { type: "get*" }
        risk_level: low
        approval: auto
      - name: list_auto
        match: { type: "list*" }
        risk_level: low
        approval: auto
      - name: write_approve
        match: { type: "write*" }
        risk_level: medium
        approval: approve
      - name: update_approve
        match: { type: "update*" }
        risk_level: medium
        approval: approve
      - name: create_approve
        match: { type: "create*" }
        risk_level: medium
        approval: approve
      - name: bulk_high
        match: { type: "bulk_*" }
        risk_level: high
        approval: approve
      - name: delete_block
        match: { type: "delete*" }
        risk_level: critical
        approval: block
      - name: drop_block
        match: { type: "drop*" }
        risk_level: critical
        approval: block
      - name: after_hours
        match: { type: "deploy*" }
        conditions:
          time_after: "18:00"
        risk_level: critical
        approval: block
""")


def test_comprehensive_policy_scores_high(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(_COMPREHENSIVE_POLICY)
    result = calculate_score(policy_file)

    assert result.total >= 80
    assert result.grade in ("A", "A+")
    assert result.rule_count == 10


_MINIMAL_POLICY = textwrap.dedent("""\
    version: "1"
    defaults:
      risk_level: low
      approval: auto
    rules: []
""")


def test_minimal_policy_scores_low(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(_MINIMAL_POLICY)
    result = calculate_score(policy_file)

    assert result.total < 50
    assert result.grade == "F"
    assert result.rule_count == 0


_MEDIUM_POLICY = textwrap.dedent("""\
    version: "1"
    defaults:
      risk_level: medium
      approval: approve
    rules:
      - name: read_auto
        match: { type: "read*" }
        risk_level: low
        approval: auto
      - name: delete_block
        match: { type: "delete*" }
        risk_level: critical
        approval: block
""")


def test_medium_policy_mid_range(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(_MEDIUM_POLICY)
    result = calculate_score(policy_file)

    assert 40 <= result.total <= 80
    assert result.rule_count == 2


# ---------------------------------------------------------------------------
# Badge / URL generation
# ---------------------------------------------------------------------------


def test_badge_url_format(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(_COMPREHENSIVE_POLICY)
    result = calculate_score(policy_file)

    assert "img.shields.io/badge" in result.badge_url
    # Grade may be URL-encoded (e.g. A+ -> A%2B), so check decoded URL
    import urllib.parse

    decoded = urllib.parse.unquote(result.badge_url)
    assert result.grade in decoded
    assert result.badge_color in result.badge_url


def test_badge_markdown(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(_COMPREHENSIVE_POLICY)
    result = calculate_score(policy_file)

    assert "[![Aegis Governance]" in result.badge_markdown
    assert "github.com/Acacian/aegis" in result.badge_markdown


@pytest.mark.parametrize(
    ("grade", "expected_color"),
    [
        ("A+", "brightgreen"),
        ("A", "brightgreen"),
        ("B", "green"),
        ("C", "yellow"),
        ("D", "orange"),
        ("F", "red"),
    ],
)
def test_badge_color(grade: str, expected_color: str) -> None:
    result = ScoreResult(total=0, grade=grade, breakdown=[], rule_count=0)
    assert result.badge_color == expected_color


# ---------------------------------------------------------------------------
# Breakdown details
# ---------------------------------------------------------------------------


def test_destructive_block_detected(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(_COMPREHENSIVE_POLICY)
    result = calculate_score(policy_file)

    destructive = next(b for b in result.breakdown if "Destructive" in b.label)
    assert destructive.passed is True
    assert destructive.points == 20


def test_time_conditions_detected(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(_COMPREHENSIVE_POLICY)
    result = calculate_score(policy_file)

    time_cond = next(b for b in result.breakdown if "Time" in b.label)
    assert time_cond.passed is True
    assert time_cond.points == 10


def test_approval_gates_detected(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(_COMPREHENSIVE_POLICY)
    result = calculate_score(policy_file)

    approval = next(b for b in result.breakdown if "approval" in b.label.lower())
    assert approval.passed is True
    assert approval.points == 15


def test_risk_levels_detected(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(_COMPREHENSIVE_POLICY)
    result = calculate_score(policy_file)

    risk = next(b for b in result.breakdown if "risk" in b.label.lower())
    assert risk.passed is True
    assert risk.points == 10


def test_rule_count_bonus(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(_COMPREHENSIVE_POLICY)
    result = calculate_score(policy_file)

    rc = next(b for b in result.breakdown if "rules" in b.label.lower())
    assert rc.passed is True
    assert rc.points == 10  # 10 rules -> +10


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def test_score_table_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(_COMPREHENSIVE_POLICY)
    main(["score", str(policy_file)])
    out = capsys.readouterr().out

    assert "Aegis Governance Score:" in out
    assert "Badge:" in out
    assert "Markdown:" in out
    assert "https://img.shields.io/badge/" in out


def test_score_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(_COMPREHENSIVE_POLICY)
    main(["score", str(policy_file), "--format", "json"])
    out = capsys.readouterr().out

    data = json.loads(out)
    assert "score" in data
    assert "grade" in data
    assert "breakdown" in data
    assert isinstance(data["breakdown"], list)
    assert "badge_url" in data
    assert "badge_markdown" in data
    assert data["score"] >= 0
    assert data["score"] <= 100


def test_score_file_not_found(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["score", "/nonexistent/policy.yaml"])
    err = capsys.readouterr().err
    assert "File not found" in err


def test_score_deterministic(tmp_path: Path) -> None:
    """Score must be deterministic across multiple runs."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(_COMPREHENSIVE_POLICY)
    r1 = calculate_score(policy_file)
    r2 = calculate_score(policy_file)
    assert r1.total == r2.total
    assert r1.grade == r2.grade
