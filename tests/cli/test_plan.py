"""Tests for ``aegis plan`` CLI command."""

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


@pytest.fixture()
def policy_files(tmp_path: Path) -> tuple[Path, Path]:
    old = tmp_path / "current.yaml"
    new = tmp_path / "proposed.yaml"
    old.write_text(_OLD_POLICY)
    new.write_text(_NEW_POLICY)
    return old, new


@pytest.fixture()
def replay_file(tmp_path: Path) -> Path:
    """Create a JSONL replay file with audit-style entries."""
    path = tmp_path / "audit.jsonl"
    lines = [
        json.dumps(
            {
                "action_type": "read",
                "action_target": "crm",
                "agent_id": "agent-1",
                "timestamp": "2026-03-28T10:00:00",
                "approval": "auto",
            }
        ),
        json.dumps(
            {
                "action_type": "write",
                "action_target": "crm",
                "agent_id": "agent-1",
                "timestamp": "2026-03-28T10:01:00",
                "approval": "auto",
            }
        ),
        json.dumps(
            {
                "action_type": "delete_user",
                "action_target": "db",
                "agent_id": "agent-2",
                "timestamp": "2026-03-28T10:02:00",
                "approval": "auto",
            }
        ),
        json.dumps(
            {
                "action_type": "legacy_op",
                "action_target": "sys",
                "agent_id": "agent-1",
                "timestamp": "2026-03-28T10:03:00",
                "approval": "auto",
            }
        ),
    ]
    path.write_text("\n".join(lines) + "\n")
    return path


@pytest.fixture()
def actions_file(tmp_path: Path) -> Path:
    """Create a JSONL actions file (simple format for --replay)."""
    path = tmp_path / "actions.jsonl"
    lines = [
        json.dumps({"type": "read", "target": "crm"}),
        json.dumps({"type": "write", "target": "crm"}),
        json.dumps({"type": "delete_user", "target": "db"}),
    ]
    path.write_text("\n".join(lines) + "\n")
    return path


# ---------------------------------------------------------------------------
# Table output tests
# ---------------------------------------------------------------------------


class TestPlanTableOutput:
    def test_shows_header(
        self,
        policy_files: tuple[Path, Path],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        old, new = policy_files
        main(["plan", str(old), str(new)])
        out = capsys.readouterr().out

        assert "Aegis Policy Plan" in out
        assert "Current:" in out
        assert "Proposed:" in out

    def test_shows_added_rules(
        self,
        policy_files: tuple[Path, Path],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        old, new = policy_files
        main(["plan", str(old), str(new)])
        out = capsys.readouterr().out

        assert "strict_delete" in out
        assert "review_bulk" in out

    def test_shows_removed_rules(
        self,
        policy_files: tuple[Path, Path],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        old, new = policy_files
        main(["plan", str(old), str(new)])
        out = capsys.readouterr().out

        assert "old_legacy" in out

    def test_shows_modified_rules(
        self,
        policy_files: tuple[Path, Path],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        old, new = policy_files
        main(["plan", str(old), str(new)])
        out = capsys.readouterr().out

        assert "write_crm" in out

    def test_shows_plan_summary(
        self,
        policy_files: tuple[Path, Path],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        old, new = policy_files
        main(["plan", str(old), str(new)])
        out = capsys.readouterr().out

        assert "Plan:" in out
        assert "to add" in out
        assert "to remove" in out

    def test_no_changes(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        p = tmp_path / "same.yaml"
        p.write_text(_OLD_POLICY)
        main(["plan", str(p), str(p)])
        out = capsys.readouterr().out

        assert "No changes" in out


# ---------------------------------------------------------------------------
# Replay tests
# ---------------------------------------------------------------------------


class TestPlanReplay:
    def test_replay_shows_impact(
        self,
        policy_files: tuple[Path, Path],
        replay_file: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        old, new = policy_files
        main(["plan", str(old), str(new), "--replay", str(replay_file)])
        out = capsys.readouterr().out

        assert "historical action" in out
        assert "NEWLY BLOCKED" in out

    def test_replay_shows_changed_actions(
        self,
        policy_files: tuple[Path, Path],
        replay_file: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        old, new = policy_files
        main(["plan", str(old), str(new), "--replay", str(replay_file)])
        out = capsys.readouterr().out

        assert "Changed actions:" in out
        assert "delete_user" in out

    def test_replay_file_not_found(
        self,
        policy_files: tuple[Path, Path],
    ) -> None:
        old, new = policy_files
        with pytest.raises(SystemExit):
            main(["plan", str(old), str(new), "--replay", "/nonexistent.jsonl"])

    def test_warning_for_blocked(
        self,
        policy_files: tuple[Path, Path],
        replay_file: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        old, new = policy_files
        main(["plan", str(old), str(new), "--replay", str(replay_file)])
        out = capsys.readouterr().out

        assert "WARNING" in out
        assert "BLOCKED" in out


# ---------------------------------------------------------------------------
# CI mode tests
# ---------------------------------------------------------------------------


class TestPlanCI:
    def test_ci_exits_1_on_blocked(
        self,
        policy_files: tuple[Path, Path],
        replay_file: Path,
    ) -> None:
        old, new = policy_files
        with pytest.raises(SystemExit) as exc_info:
            main(["plan", str(old), str(new), "--replay", str(replay_file), "--ci"])
        assert exc_info.value.code == 1

    def test_ci_exits_0_no_blocked(
        self,
        tmp_path: Path,
    ) -> None:
        """When no actions are newly blocked, CI mode should not exit 1."""
        old = tmp_path / "old.yaml"
        new = tmp_path / "new.yaml"
        old.write_text(_OLD_POLICY)
        # New policy only loosens — promotes write to auto
        new.write_text(
            textwrap.dedent("""\
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
                risk_level: low
                approval: auto
              - name: old_legacy
                match: { type: "legacy_*" }
                risk_level: low
                approval: auto
        """)
        )

        replay = tmp_path / "r.jsonl"
        replay.write_text(
            json.dumps(
                {
                    "action_type": "write",
                    "action_target": "crm",
                    "agent_id": "a1",
                    "timestamp": "2026-03-28T10:00:00",
                    "approval": "auto",
                }
            )
            + "\n"
        )

        # Should NOT raise SystemExit
        main(["plan", str(old), str(new), "--replay", str(replay), "--ci"])


# ---------------------------------------------------------------------------
# JSON output tests
# ---------------------------------------------------------------------------


class TestPlanJsonOutput:
    def test_json_structure(
        self,
        policy_files: tuple[Path, Path],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        old, new = policy_files
        main(["plan", str(old), str(new), "--format", "json"])
        data = json.loads(capsys.readouterr().out)

        assert "rules_added" in data
        assert "rules_removed" in data
        assert "rules_modified" in data
        assert "defaults_changed" in data
        assert "summary" in data

    def test_json_with_replay(
        self,
        policy_files: tuple[Path, Path],
        replay_file: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        old, new = policy_files
        main(["plan", str(old), str(new), "--replay", str(replay_file), "--format", "json"])
        data = json.loads(capsys.readouterr().out)

        assert "replay" in data
        assert data["replay"]["total_events"] == 4
        assert data["replay"]["newly_blocked"] >= 1
        assert "impact" in data

    def test_json_no_replay(
        self,
        policy_files: tuple[Path, Path],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        old, new = policy_files
        main(["plan", str(old), str(new), "--format", "json"])
        data = json.loads(capsys.readouterr().out)

        assert "replay" not in data
        assert "impact" not in data


# ---------------------------------------------------------------------------
# Demo mode tests
# ---------------------------------------------------------------------------


class TestPlanDemo:
    def test_demo_runs_without_files(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """--demo should work with no positional arguments at all."""
        main(["plan", "--demo"])
        out = capsys.readouterr().out

        assert "Demo: previewing impact of policy changes" in out
        assert "Aegis Policy Plan" in out
        assert "current-policy (demo)" in out
        assert "proposed-policy (demo)" in out
        # Should show rule changes and replay impact
        assert "Rule changes:" in out
        assert "historical action" in out

    def test_demo_shows_blocked_warning(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """--demo should show the NEWLY BLOCKED warning for write@production."""
        main(["plan", "--demo"])
        out = capsys.readouterr().out

        assert "NEWLY BLOCKED" in out
        assert "WARNING" in out
        assert "BLOCKED" in out

    def test_demo_json_output(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """--demo --format json should produce valid JSON with replay data."""
        main(["plan", "--demo", "--format", "json"])
        data = json.loads(capsys.readouterr().out)

        assert "rules_added" in data
        assert "rules_removed" in data
        assert "rules_modified" in data
        assert "replay" in data
        assert data["replay"]["newly_blocked"] >= 1
        assert "impact" in data
        # Verify the write@production action is newly blocked
        blocked = [
            e
            for e in data["impact"]
            if e["new_decision"] == "block" and e["old_decision"] != "block"
        ]
        assert len(blocked) >= 1


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestPlanErrors:
    def test_old_file_not_found(self, tmp_path: Path) -> None:
        new = tmp_path / "new.yaml"
        new.write_text(_NEW_POLICY)
        with pytest.raises(SystemExit):
            main(["plan", "/nonexistent.yaml", str(new)])

    def test_new_file_not_found(self, tmp_path: Path) -> None:
        old = tmp_path / "old.yaml"
        old.write_text(_OLD_POLICY)
        with pytest.raises(SystemExit):
            main(["plan", str(old), "/nonexistent.yaml"])

    def test_invalid_policy(self, tmp_path: Path) -> None:
        old = tmp_path / "old.yaml"
        new = tmp_path / "new.yaml"
        old.write_text("not valid yaml: [")
        new.write_text(_NEW_POLICY)
        with pytest.raises(SystemExit):
            main(["plan", str(old), str(new)])

    def test_audit_db_not_found(
        self,
        policy_files: tuple[Path, Path],
    ) -> None:
        old, new = policy_files
        with pytest.raises(SystemExit):
            main(["plan", str(old), str(new), "--audit-db", "/nonexistent.db"])
