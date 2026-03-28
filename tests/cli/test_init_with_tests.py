"""Tests for ``aegis init --with-tests`` CLI flag."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from aegis.cli.main import main
from aegis.core.policy import Policy
from aegis.core.policy_test_suite import PolicyTestSuite

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_init(tmp_path: Path, *extra_args: str) -> None:
    """Run ``aegis init`` inside *tmp_path* with optional extra flags."""
    import os

    prev = os.getcwd()
    try:
        os.chdir(tmp_path)
        main(["init", *extra_args])
    finally:
        os.chdir(prev)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestInitCreatesOnlyPolicy:
    """Without --with-tests, only the policy file is created."""

    def test_no_test_file(self, tmp_path: Path) -> None:
        _run_init(tmp_path, "-o", str(tmp_path / "policy.yaml"))
        assert (tmp_path / "policy.yaml").exists()
        assert not (tmp_path / "tests.yaml").exists()


class TestInitWithTestsCreatesBothFiles:
    """With --with-tests, both policy.yaml and tests.yaml are created."""

    def test_both_files_exist(self, tmp_path: Path) -> None:
        policy_path = tmp_path / "policy.yaml"
        test_path = tmp_path / "tests.yaml"
        _run_init(
            tmp_path,
            "-o",
            str(policy_path),
            "--with-tests",
            "--test-output",
            str(test_path),
        )
        assert policy_path.exists()
        assert test_path.exists()

    def test_test_file_is_valid_yaml(self, tmp_path: Path) -> None:
        policy_path = tmp_path / "policy.yaml"
        test_path = tmp_path / "tests.yaml"
        _run_init(
            tmp_path,
            "-o",
            str(policy_path),
            "--with-tests",
            "--test-output",
            str(test_path),
        )
        data = yaml.safe_load(test_path.read_text())
        assert isinstance(data, dict)
        assert "name" in data
        assert "tests" in data
        assert len(data["tests"]) > 0

    def test_confirmation_message(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        policy_path = tmp_path / "policy.yaml"
        test_path = tmp_path / "tests.yaml"
        _run_init(
            tmp_path,
            "-o",
            str(policy_path),
            "--with-tests",
            "--test-output",
            str(test_path),
        )
        captured = capsys.readouterr()
        assert "Generated" in captured.out
        assert str(policy_path) in captured.out
        assert str(test_path) in captured.out


class TestInitWithTestsCustomOutput:
    """--test-output lets the user pick a custom file name."""

    def test_custom_name(self, tmp_path: Path) -> None:
        policy_path = tmp_path / "policy.yaml"
        custom = tmp_path / "my_tests.yaml"
        _run_init(
            tmp_path,
            "-o",
            str(policy_path),
            "--with-tests",
            "--test-output",
            str(custom),
        )
        assert custom.exists()
        assert not (tmp_path / "tests.yaml").exists()

    def test_default_name(self, tmp_path: Path) -> None:
        """Without --test-output the default is tests.yaml."""
        policy_path = tmp_path / "policy.yaml"
        _run_init(tmp_path, "-o", str(policy_path), "--with-tests")
        assert Path("tests.yaml").exists() or (tmp_path / "tests.yaml").exists()


class TestGeneratedTestsPassAgainstPolicy:
    """Round-trip: init -> load -> test -> all pass."""

    def test_round_trip(self, tmp_path: Path) -> None:
        policy_path = tmp_path / "policy.yaml"
        test_path = tmp_path / "tests.yaml"
        _run_init(
            tmp_path,
            "-o",
            str(policy_path),
            "--with-tests",
            "--test-output",
            str(test_path),
        )

        policy = Policy.from_yaml(policy_path)
        suite = PolicyTestSuite.load_from_yaml(test_path)
        result = suite.run(policy)

        assert result.all_passed, f"{result.failed}/{result.total} tests failed: " + "; ".join(
            r.message for r in result.results if not r.passed
        )
