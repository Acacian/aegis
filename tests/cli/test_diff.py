"""Tests for ``aegis diff`` CLI command."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from aegis.cli.main import main

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_OLD_POLICY = textwrap.dedent("""\
    version: "1"
    defaults:
      risk_level: low
      approval: auto
    rules:
      - name: read_ops
        match: { type: "read*" }
        risk_level: low
        approval: auto
      - name: write_crm
        match: { type: "write*", target: "crm" }
        risk_level: medium
        approval: auto
      - name: old_legacy
        match: { type: "legacy_*" }
        risk_level: low
        approval: auto
""")

_NEW_POLICY = textwrap.dedent("""\
    version: "1"
    defaults:
      risk_level: medium
      approval: approve
    rules:
      - name: read_ops
        match: { type: "read*" }
        risk_level: low
        approval: auto
      - name: write_crm
        match: { type: "write*", target: "crm" }
        risk_level: medium
        approval: approve
      - name: strict_delete
        match: { type: "delete_*" }
        risk_level: critical
        approval: block
      - name: review_bulk
        match: { type: "bulk_*" }
        risk_level: high
        approval: approve
""")

_IDENTICAL_POLICY = textwrap.dedent("""\
    version: "1"
    defaults:
      risk_level: low
      approval: auto
    rules:
      - name: read_ops
        match: { type: "read*" }
        risk_level: low
        approval: auto
""")


@pytest.fixture()
def policy_files(tmp_path: Path) -> tuple[Path, Path]:
    """Create old and new policy files, return their paths."""
    old = tmp_path / "old.yaml"
    new = tmp_path / "new.yaml"
    old.write_text(_OLD_POLICY)
    new.write_text(_NEW_POLICY)
    return old, new


@pytest.fixture()
def actions_file(tmp_path: Path) -> Path:
    """Create a JSONL actions file for replay tests."""
    actions_path = tmp_path / "actions.jsonl"
    lines = [
        json.dumps({"type": "read", "target": "crm"}),
        json.dumps({"type": "write", "target": "crm"}),
        json.dumps({"type": "delete_user", "target": "db"}),
        json.dumps({"type": "legacy_op", "target": "sys"}),
        json.dumps({"type": "bulk_update", "target": "warehouse"}),
    ]
    actions_path.write_text("\n".join(lines) + "\n")
    return actions_path


# ---------------------------------------------------------------------------
# Table format tests
# ---------------------------------------------------------------------------


class TestDiffTableOutput:
    """Verify the table (default) output format."""

    def test_shows_header(
        self,
        policy_files: tuple[Path, Path],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        old, new = policy_files
        main(["diff", str(old), str(new)])
        out = capsys.readouterr().out

        assert "Policy Diff:" in out
        assert "old.yaml" in out
        assert "new.yaml" in out

    def test_shows_defaults_changed(
        self,
        policy_files: tuple[Path, Path],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        old, new = policy_files
        main(["diff", str(old), str(new)])
        out = capsys.readouterr().out

        assert "Defaults changed:" in out
        assert "risk_level" in out
        assert "low" in out and "medium" in out

    def test_shows_added_rules(
        self,
        policy_files: tuple[Path, Path],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        old, new = policy_files
        main(["diff", str(old), str(new)])
        out = capsys.readouterr().out

        assert "Rules added (+2):" in out
        assert "strict_delete" in out
        assert "review_bulk" in out

    def test_shows_removed_rules(
        self,
        policy_files: tuple[Path, Path],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        old, new = policy_files
        main(["diff", str(old), str(new)])
        out = capsys.readouterr().out

        assert "Rules removed (-1):" in out
        assert "old_legacy" in out

    def test_shows_modified_rules(
        self,
        policy_files: tuple[Path, Path],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        old, new = policy_files
        main(["diff", str(old), str(new)])
        out = capsys.readouterr().out

        assert "Rules modified (1):" in out
        assert "write_crm" in out
        assert "approval" in out

    def test_shows_summary(
        self,
        policy_files: tuple[Path, Path],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        old, new = policy_files
        main(["diff", str(old), str(new)])
        out = capsys.readouterr().out

        assert "Summary:" in out

    def test_no_changes_message(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        p1 = tmp_path / "a.yaml"
        p2 = tmp_path / "b.yaml"
        p1.write_text(_IDENTICAL_POLICY)
        p2.write_text(_IDENTICAL_POLICY)

        main(["diff", str(p1), str(p2)])
        out = capsys.readouterr().out

        assert "No changes detected." in out


# ---------------------------------------------------------------------------
# Replay / impact tests
# ---------------------------------------------------------------------------


class TestDiffReplay:
    """Verify the --replay flag behavior."""

    def test_replay_shows_impact(
        self,
        policy_files: tuple[Path, Path],
        actions_file: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        old, new = policy_files
        main(["diff", str(old), str(new), "--replay", str(actions_file)])
        out = capsys.readouterr().out

        assert "Impact on" in out
        assert "recorded actions:" in out

    def test_replay_shows_blocked_warning(
        self,
        policy_files: tuple[Path, Path],
        actions_file: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        old, new = policy_files
        main(["diff", str(old), str(new), "--replay", str(actions_file)])
        out = capsys.readouterr().out

        assert "BLOCKED" in out

    def test_replay_file_not_found(
        self,
        policy_files: tuple[Path, Path],
    ) -> None:
        old, new = policy_files
        with pytest.raises(SystemExit):
            main(["diff", str(old), str(new), "--replay", "/nonexistent/actions.jsonl"])


# ---------------------------------------------------------------------------
# JSON format tests
# ---------------------------------------------------------------------------


class TestDiffJsonOutput:
    """Verify the JSON output format."""

    def test_json_structure(
        self,
        policy_files: tuple[Path, Path],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        old, new = policy_files
        main(["diff", str(old), str(new), "--format", "json"])
        out = capsys.readouterr().out

        data = json.loads(out)
        assert "rules_added" in data
        assert "rules_removed" in data
        assert "rules_modified" in data
        assert "defaults_changed" in data
        assert "impact_summary" in data

    def test_json_added_rules(
        self,
        policy_files: tuple[Path, Path],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        old, new = policy_files
        main(["diff", str(old), str(new), "--format", "json"])
        data = json.loads(capsys.readouterr().out)

        added_names = [r["rule_name"] for r in data["rules_added"]]
        assert "strict_delete" in added_names
        assert "review_bulk" in added_names

    def test_json_with_replay(
        self,
        policy_files: tuple[Path, Path],
        actions_file: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        old, new = policy_files
        main(["diff", str(old), str(new), "--replay", str(actions_file), "--format", "json"])
        data = json.loads(capsys.readouterr().out)

        assert "impact" in data
        assert isinstance(data["impact"], list)
        assert len(data["impact"]) == 5

        # Each entry has expected keys
        for entry in data["impact"]:
            assert "action_type" in entry
            assert "target" in entry
            assert "old_decision" in entry
            assert "new_decision" in entry
            assert "change" in entry

    def test_json_defaults_changed(
        self,
        policy_files: tuple[Path, Path],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        old, new = policy_files
        main(["diff", str(old), str(new), "--format", "json"])
        data = json.loads(capsys.readouterr().out)

        dc = data["defaults_changed"]
        assert dc["risk_level"]["old"] == "low"
        assert dc["risk_level"]["new"] == "medium"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestDiffErrors:
    """Verify error handling."""

    def test_old_file_not_found(self, tmp_path: Path) -> None:
        new = tmp_path / "new.yaml"
        new.write_text(_NEW_POLICY)

        with pytest.raises(SystemExit):
            main(["diff", "/nonexistent/old.yaml", str(new)])

    def test_new_file_not_found(self, tmp_path: Path) -> None:
        old = tmp_path / "old.yaml"
        old.write_text(_OLD_POLICY)

        with pytest.raises(SystemExit):
            main(["diff", str(old), "/nonexistent/new.yaml"])

    def test_invalid_old_policy(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        old = tmp_path / "old.yaml"
        new = tmp_path / "new.yaml"
        old.write_text("not a valid policy: [")
        new.write_text(_NEW_POLICY)

        with pytest.raises(SystemExit):
            main(["diff", str(old), str(new)])
        err = capsys.readouterr().err
        assert "Failed to load old policy" in err
