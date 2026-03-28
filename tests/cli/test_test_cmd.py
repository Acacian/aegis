"""Tests for ``aegis test`` CLI command."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from aegis.cli.main import main

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_POLICY = textwrap.dedent("""\
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
        approval: approve
      - name: delete_block
        match: { type: "delete*" }
        risk_level: critical
        approval: block
""")

_PASSING_SUITE = textwrap.dedent("""\
    name: basic tests
    tests:
      - action: {type: read, target: crm}
        expected_decision: auto
        expected_risk_level: low
        description: Read ops auto-approve
      - action: {type: write, target: crm}
        expected_decision: approve
        expected_risk_level: medium
        description: Write CRM needs approval
      - action: {type: delete, target: db}
        expected_decision: block
        expected_risk_level: critical
        description: Delete always blocked
""")

_FAILING_SUITE = textwrap.dedent("""\
    name: intentional failures
    tests:
      - action: {type: read, target: crm}
        expected_decision: auto
        description: Read should pass
      - action: {type: write, target: crm}
        expected_decision: auto
        description: This should fail - write requires approve not auto
      - action: {type: delete, target: db}
        expected_decision: auto
        description: This should fail - delete is blocked not auto
""")

_STRICTER_POLICY = textwrap.dedent("""\
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
        risk_level: high
        approval: block
      - name: delete_block
        match: { type: "delete*" }
        risk_level: critical
        approval: block
""")


@pytest.fixture()
def policy_file(tmp_path: Path) -> Path:
    p = tmp_path / "policy.yaml"
    p.write_text(_POLICY)
    return p


@pytest.fixture()
def passing_suite(tmp_path: Path) -> Path:
    p = tmp_path / "passing.yaml"
    p.write_text(_PASSING_SUITE)
    return p


@pytest.fixture()
def failing_suite(tmp_path: Path) -> Path:
    p = tmp_path / "failing.yaml"
    p.write_text(_FAILING_SUITE)
    return p


@pytest.fixture()
def stricter_policy(tmp_path: Path) -> Path:
    p = tmp_path / "stricter.yaml"
    p.write_text(_STRICTER_POLICY)
    return p


# ---------------------------------------------------------------------------
# Passing tests
# ---------------------------------------------------------------------------


class TestPassingTests:
    def test_all_pass(
        self,
        policy_file: Path,
        passing_suite: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        main(["test", str(policy_file), str(passing_suite)])
        out = capsys.readouterr().out

        assert "PASS" in out
        assert "FAIL" not in out
        assert "ALL PASSED" in out

    def test_shows_descriptions(
        self,
        policy_file: Path,
        passing_suite: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        main(["test", str(policy_file), str(passing_suite)])
        out = capsys.readouterr().out

        assert "Read ops auto-approve" in out
        assert "Write CRM needs approval" in out
        assert "Delete always blocked" in out

    def test_exit_0_on_pass(
        self,
        policy_file: Path,
        passing_suite: Path,
    ) -> None:
        # Should not raise SystemExit
        main(["test", str(policy_file), str(passing_suite)])


# ---------------------------------------------------------------------------
# Failing tests
# ---------------------------------------------------------------------------


class TestFailingTests:
    def test_shows_failures(
        self,
        policy_file: Path,
        failing_suite: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(["test", str(policy_file), str(failing_suite)])
        assert exc_info.value.code == 1

        out = capsys.readouterr().out
        assert "FAIL" in out
        assert "FAILED" in out

    def test_exit_1_on_failure(
        self,
        policy_file: Path,
        failing_suite: Path,
    ) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(["test", str(policy_file), str(failing_suite)])
        assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# Generate tests
# ---------------------------------------------------------------------------


class TestGenerate:
    def test_generate_to_stdout(
        self,
        policy_file: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        main(["test", str(policy_file), "--generate"])
        out = capsys.readouterr().out

        assert "read_ops" in out or "read*" in out
        assert "write_crm" in out or "write*" in out
        assert "delete_block" in out or "delete*" in out

    def test_generate_to_file(
        self,
        policy_file: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        out_file = tmp_path / "generated.yaml"
        main(["test", str(policy_file), "--generate", "--generate-output", str(out_file)])

        assert out_file.exists()
        content = out_file.read_text()
        assert "read" in content
        assert "auto" in content

    def test_generated_suite_passes(
        self,
        policy_file: Path,
        tmp_path: Path,
    ) -> None:
        """Generated suite should pass against its source policy."""
        out_file = tmp_path / "gen.yaml"
        main(["test", str(policy_file), "--generate", "--generate-output", str(out_file)])
        # Now run it — should pass
        main(["test", str(policy_file), str(out_file)])


# ---------------------------------------------------------------------------
# Regression tests
# ---------------------------------------------------------------------------


class TestRegression:
    def test_detects_regression(
        self,
        policy_file: Path,
        stricter_policy: Path,
        passing_suite: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with pytest.raises(SystemExit):
            main(
                [
                    "test",
                    str(stricter_policy),
                    str(passing_suite),
                    "--regression",
                    str(policy_file),
                ]
            )
        out = capsys.readouterr().out

        assert "Regression" in out or "REGR" in out

    def test_regression_no_changes(
        self,
        policy_file: Path,
        passing_suite: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Same policy compared to itself — no regressions."""
        main(
            [
                "test",
                str(policy_file),
                str(passing_suite),
                "--regression",
                str(policy_file),
            ]
        )
        out = capsys.readouterr().out

        assert "ALL PASSED" in out


# ---------------------------------------------------------------------------
# JSON output tests
# ---------------------------------------------------------------------------


class TestJsonOutput:
    def test_json_structure(
        self,
        policy_file: Path,
        passing_suite: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        main(["test", str(policy_file), str(passing_suite), "--format", "json"])
        data = json.loads(capsys.readouterr().out)

        assert data["total"] == 3
        assert data["passed"] == 3
        assert data["failed"] == 0
        assert data["all_passed"] is True
        assert len(data["results"]) == 3

    def test_json_failure(
        self,
        policy_file: Path,
        failing_suite: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with pytest.raises(SystemExit):
            main(["test", str(policy_file), str(failing_suite), "--format", "json"])
        data = json.loads(capsys.readouterr().out)

        assert data["all_passed"] is False
        assert data["failed"] == 2

    def test_regression_json(
        self,
        policy_file: Path,
        stricter_policy: Path,
        passing_suite: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with pytest.raises(SystemExit):
            main(
                [
                    "test",
                    str(stricter_policy),
                    str(passing_suite),
                    "--regression",
                    str(policy_file),
                    "--format",
                    "json",
                ]
            )
        data = json.loads(capsys.readouterr().out)

        assert "regressions" in data
        assert len(data["regressions"]) >= 1


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrors:
    def test_policy_not_found(self) -> None:
        with pytest.raises(SystemExit):
            main(["test", "/nonexistent.yaml", "suite.yaml"])

    def test_suite_not_found(self, policy_file: Path) -> None:
        with pytest.raises(SystemExit):
            main(["test", str(policy_file), "/nonexistent.yaml"])

    def test_no_suite_no_generate(
        self,
        policy_file: Path,
    ) -> None:
        with pytest.raises(SystemExit):
            main(["test", str(policy_file)])

    def test_empty_suite(
        self,
        policy_file: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        empty = tmp_path / "empty.yaml"
        empty.write_text("name: empty\ntests: []\n")
        main(["test", str(policy_file), str(empty)])
        out = capsys.readouterr().out
        assert "empty" in out.lower()
