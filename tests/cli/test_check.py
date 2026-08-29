"""Tests for ``aegis check drift`` — offline tool distribution drift CLI.

Covers:
- stable / midband / collapse classification
- normalized delta arithmetic
- baseline comparison
- --strict exit code behavior
- --json output schema
- privacy invariant: tool_args / cot_text / user_message in the trace must
  never appear in the CLI output even when --json is requested
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.cli.main import main

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Sentinel strings that MUST never leak into CLI output (privacy invariant).
_PII_ARGS = "SECRET_USER_ID_DO_NOT_LEAK"
_PII_COT = "INTERNAL_REASONING_DO_NOT_LEAK"
_PII_PROMPT = "USER_PROMPT_DO_NOT_LEAK"


def _write_trace(path: Path, tools: list[str]) -> Path:
    """Write a JSONL trace file. Each row contains the tool name AND PII fields
    that the CLI must never read or echo back."""
    with path.open("w") as fh:
        for name in tools:
            row = {
                "tool_name": name,
                # The next three fields are the privacy bait. Aegis must NEVER
                # touch them.
                "tool_args": {"hidden": _PII_ARGS},
                "cot_text": _PII_COT,
                "user_message": _PII_PROMPT,
            }
            fh.write(json.dumps(row) + "\n")
    return path


def _write_baseline(path: Path, normalized_delta_mean: float) -> Path:
    payload = {
        "name": "test-baseline",
        "normalized_delta_mean": normalized_delta_mean,
        "collapse_rate_pct": 28.1,
        "n": 178,
    }
    path.write_text(json.dumps(payload))
    return path


# ---------------------------------------------------------------------------
# Mode classification: stable / midband / collapse
# ---------------------------------------------------------------------------


class TestModeClassification:
    def test_collapse_full(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Four distinct tools → one tool four times = log(4) collapse."""
        trace = _write_trace(
            tmp_path / "collapse.jsonl",
            ["a", "b", "c", "d", "z", "z", "z", "z"],
        )
        with pytest.raises(SystemExit) as exc:
            main(["check", "drift", "--trace", str(trace), "--json"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        report = json.loads(out)
        assert report["mode"] == "collapse"
        assert report["tool_calls"] == 8
        # log(4) ≈ 1.3863
        assert report["entropy_early"] == pytest.approx(1.3863, abs=1e-3)
        assert report["entropy_late"] == 0.0
        assert report["entropy_delta"] == pytest.approx(1.3863, abs=1e-3)
        assert report["normalized_delta"] == pytest.approx(1.0, abs=1e-3)

    def test_stable_perfectly_uniform(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Same tool distribution early and late = zero drift."""
        trace = _write_trace(
            tmp_path / "stable.jsonl",
            ["a", "b", "c", "d", "a", "b", "c", "d"],
        )
        with pytest.raises(SystemExit) as exc:
            main(["check", "drift", "--trace", str(trace), "--json"])
        assert exc.value.code == 0
        report = json.loads(capsys.readouterr().out)
        assert report["mode"] == "stable"
        assert report["entropy_delta"] == pytest.approx(0.0, abs=1e-9)
        assert report["normalized_delta"] == pytest.approx(0.0, abs=1e-9)

    def test_midband_partial_narrowing(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """4 distinct → 2 distinct = drift in (0.10, 0.30) midband range.

        early entropy = log(4) ≈ 1.386
        late entropy = log(2) ≈ 0.693  (a,a,b,b)
        delta ≈ 0.693 → midband.
        """
        trace = _write_trace(
            tmp_path / "midband.jsonl",
            ["a", "b", "c", "d", "a", "a", "b", "b"],
        )
        with pytest.raises(SystemExit) as exc:
            main(["check", "drift", "--trace", str(trace), "--json"])
        assert exc.value.code == 0
        report = json.loads(capsys.readouterr().out)
        # 4→2 unique tools is technically beyond midband; verify it lands in
        # collapse since delta ≈ 0.693 > 0.30. Adjust expectation accordingly.
        assert report["mode"] == "collapse"
        assert report["entropy_delta"] == pytest.approx(0.6931, abs=1e-3)

    def test_midband_actual(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A trace whose delta lands strictly inside (0.10, 0.30).

        early = (a,b,c,c)  → entropy = -(2*0.25*log(0.25) + 0.5*log(0.5)) ≈ 1.04
        late  = (a,b,b,b)  → entropy = -(0.25*log(0.25) + 0.75*log(0.75)) ≈ 0.56
        delta ≈ 0.48 → still collapse.

        For a true midband, use a tighter pair:
        early = (a,a,b,c) ≈ 1.04
        late  = (a,a,a,b) ≈ 0.56
        delta ≈ 0.48 → also collapse.

        It's hard to land cleanly in (0.10, 0.30) with W=4 because individual
        bit moves are coarse. Test the midband path via a 16-call trace.
        """
        # W=8 → max entropy = log(8) ≈ 2.079
        # early: 8 distinct tools → entropy ≈ 2.079
        # late:  7 unique tools, one doubled → entropy ≈ 1.91
        #   ( -(7*0.125*log(0.125) + 0.25*log(0.25)) )
        # delta ≈ 0.17 → midband.
        trace = _write_trace(
            tmp_path / "midband_real.jsonl",
            [
                "a",
                "b",
                "c",
                "d",
                "e",
                "f",
                "g",
                "h",  # early window W=8
                "a",
                "b",
                "c",
                "d",
                "e",
                "f",
                "g",
                "g",  # late window W=8
            ],
        )
        with pytest.raises(SystemExit) as exc:
            main(
                [
                    "check",
                    "drift",
                    "--trace",
                    str(trace),
                    "--window",
                    "8",
                    "--json",
                ]
            )
        assert exc.value.code == 0
        report = json.loads(capsys.readouterr().out)
        assert report["mode"] == "midband"
        assert 0.10 < report["entropy_delta"] < 0.30


# ---------------------------------------------------------------------------
# Privacy invariant — the most important guarantee
# ---------------------------------------------------------------------------


class TestPrivacyInvariant:
    def test_pii_never_leaks_in_human_output(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        trace = _write_trace(
            tmp_path / "trace.jsonl",
            ["a", "b", "c", "d", "z", "z", "z", "z"],
        )
        with pytest.raises(SystemExit):
            main(["check", "drift", "--trace", str(trace)])
        captured = capsys.readouterr()
        full_output = captured.out + captured.err
        assert _PII_ARGS not in full_output
        assert _PII_COT not in full_output
        assert _PII_PROMPT not in full_output

    def test_pii_never_leaks_in_json_output(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        trace = _write_trace(
            tmp_path / "trace.jsonl",
            ["a", "b", "c", "d", "z", "z", "z", "z"],
        )
        with pytest.raises(SystemExit):
            main(["check", "drift", "--trace", str(trace), "--json"])
        captured = capsys.readouterr()
        full_output = captured.out + captured.err
        assert _PII_ARGS not in full_output
        assert _PII_COT not in full_output
        assert _PII_PROMPT not in full_output

    def test_pii_never_leaks_with_baseline(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        trace = _write_trace(
            tmp_path / "trace.jsonl",
            ["a", "b", "c", "d", "z", "z", "z", "z"],
        )
        baseline = _write_baseline(tmp_path / "baseline.json", 0.029)
        with pytest.raises(SystemExit):
            main(
                [
                    "check",
                    "drift",
                    "--trace",
                    str(trace),
                    "--baseline",
                    str(baseline),
                    "--json",
                ]
            )
        captured = capsys.readouterr()
        full_output = captured.out + captured.err
        assert _PII_ARGS not in full_output
        assert _PII_COT not in full_output
        assert _PII_PROMPT not in full_output


# ---------------------------------------------------------------------------
# Baseline comparison
# ---------------------------------------------------------------------------


class TestBaselineComparison:
    def test_above_baseline_verdict(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        trace = _write_trace(
            tmp_path / "trace.jsonl",
            ["a", "b", "c", "d", "z", "z", "z", "z"],  # collapse, norm=1.0
        )
        baseline = _write_baseline(tmp_path / "base.json", 0.029)
        with pytest.raises(SystemExit):
            main(
                [
                    "check",
                    "drift",
                    "--trace",
                    str(trace),
                    "--baseline",
                    str(baseline),
                    "--json",
                ]
            )
        report = json.loads(capsys.readouterr().out)
        bc = report["baseline_comparison"]
        assert bc["baseline_normalized_delta_mean"] == 0.029
        assert bc["baseline_n"] == 178
        assert bc["verdict"] == "above_baseline"
        assert bc["delta_vs_baseline"] == pytest.approx(1.0 - 0.029, abs=1e-3)

    def test_at_or_below_baseline_verdict(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        trace = _write_trace(
            tmp_path / "trace.jsonl",
            ["a", "b", "c", "d", "a", "b", "c", "d"],  # stable, norm=0.0
        )
        baseline = _write_baseline(tmp_path / "base.json", 0.5)
        with pytest.raises(SystemExit):
            main(
                [
                    "check",
                    "drift",
                    "--trace",
                    str(trace),
                    "--baseline",
                    str(baseline),
                    "--json",
                ]
            )
        report = json.loads(capsys.readouterr().out)
        assert report["baseline_comparison"]["verdict"] == "at_or_below_baseline"


# ---------------------------------------------------------------------------
# --strict exit code
# ---------------------------------------------------------------------------


class TestStrictMode:
    def test_strict_collapse_exits_1(
        self,
        tmp_path: Path,
    ) -> None:
        trace = _write_trace(
            tmp_path / "trace.jsonl",
            ["a", "b", "c", "d", "z", "z", "z", "z"],
        )
        with pytest.raises(SystemExit) as exc:
            main(["check", "drift", "--trace", str(trace), "--strict"])
        assert exc.value.code == 1

    def test_strict_stable_exits_0(
        self,
        tmp_path: Path,
    ) -> None:
        trace = _write_trace(
            tmp_path / "trace.jsonl",
            ["a", "b", "c", "d", "a", "b", "c", "d"],
        )
        with pytest.raises(SystemExit) as exc:
            main(["check", "drift", "--trace", str(trace), "--strict"])
        assert exc.value.code == 0

    def test_no_strict_collapse_exits_0(
        self,
        tmp_path: Path,
    ) -> None:
        trace = _write_trace(
            tmp_path / "trace.jsonl",
            ["a", "b", "c", "d", "z", "z", "z", "z"],
        )
        with pytest.raises(SystemExit) as exc:
            main(["check", "drift", "--trace", str(trace)])
        assert exc.value.code == 0


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


class TestErrors:
    def test_missing_trace_file(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["check", "drift", "--trace", str(tmp_path / "nope.jsonl")])
        assert exc.value.code == 2
        assert "not found" in capsys.readouterr().err

    def test_too_few_calls(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # window=4 needs >=8 calls; give it 5
        trace = _write_trace(
            tmp_path / "short.jsonl",
            ["a", "b", "c", "d", "e"],
        )
        with pytest.raises(SystemExit) as exc:
            main(["check", "drift", "--trace", str(trace), "--json"])
        assert exc.value.code == 0  # not strict, so no exit-1
        report = json.loads(capsys.readouterr().out)
        assert "error" in report
        assert "5 tool calls" in report["error"]

    def test_malformed_jsonl_skipped(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        trace = tmp_path / "mixed.jsonl"
        with trace.open("w") as fh:
            fh.write(json.dumps({"tool_name": "a"}) + "\n")
            fh.write("this is not json\n")
            fh.write(json.dumps({"tool_name": "b"}) + "\n")
            fh.write(json.dumps({"tool_name": "c"}) + "\n")
            fh.write(json.dumps({"tool_name": "d"}) + "\n")
            fh.write(json.dumps({"tool_name": "z"}) + "\n")
            fh.write(json.dumps({"tool_name": "z"}) + "\n")
            fh.write(json.dumps({"tool_name": "z"}) + "\n")
            fh.write(json.dumps({"tool_name": "z"}) + "\n")
        with pytest.raises(SystemExit) as exc:
            main(["check", "drift", "--trace", str(trace), "--json"])
        assert exc.value.code == 0
        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert report["tool_calls"] == 8  # malformed line skipped
        assert "skipping malformed" in captured.err


# ---------------------------------------------------------------------------
# aegis check policy — issue #26
# ---------------------------------------------------------------------------

_POLICY_YAML = """\
version: "1"
defaults:
  risk_level: medium
  approval: approve
rules:
  - name: read_safe
    match:
      type: read
    risk_level: low
    approval: auto
  - name: no_deletes
    match:
      type: delete
    risk_level: critical
    approval: block
  - name: bulk_ops
    match:
      type: bulk_update
    risk_level: high
    approval: approve
"""


def _write_policy(path: Path) -> Path:
    path.write_text(_POLICY_YAML)
    return path


class TestCheckPolicy:
    def test_reports_risk_mode_and_rule_per_action(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        policy = _write_policy(tmp_path / "policy.yaml")
        with pytest.raises(SystemExit) as exc:
            main(["check", "policy", str(policy), "read:crm", "delete:db", "bulk_update:crm"])
        assert exc.value.code == 0

        out = capsys.readouterr().out
        assert "read:crm" in out
        assert "LOW" in out and "auto" in out and "read_safe" in out
        assert "CRITICAL" in out and "block" in out and "no_deletes" in out
        assert "HIGH" in out and "approve" in out and "bulk_ops" in out

    def test_columns_align(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The arrow lines up regardless of action-name length."""
        policy = _write_policy(tmp_path / "policy.yaml")
        with pytest.raises(SystemExit):
            main(["check", "policy", str(policy), "read:crm", "bulk_update:crm"])
        lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
        assert len({ln.index("→") for ln in lines}) == 1

    def test_bare_type_means_every_target(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        policy = _write_policy(tmp_path / "policy.yaml")
        with pytest.raises(SystemExit):
            main(["check", "policy", str(policy), "delete"])
        assert "delete:*" in capsys.readouterr().out

    def test_unmatched_action_falls_through_to_defaults(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        policy = _write_policy(tmp_path / "policy.yaml")
        with pytest.raises(SystemExit):
            main(["check", "policy", str(policy), "frobnicate:thing"])
        out = capsys.readouterr().out
        assert "MEDIUM" in out
        assert "<default>" in out

    def test_json_output_schema(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        policy = _write_policy(tmp_path / "policy.yaml")
        with pytest.raises(SystemExit):
            main(["check", "policy", str(policy), "read:crm", "delete:db", "--json"])
        payload = json.loads(capsys.readouterr().out)

        assert payload["rules"] == 3
        assert [r["action"] for r in payload["results"]] == ["read:crm", "delete:db"]
        assert payload["results"][0] == {
            "action": "read:crm",
            "risk": "LOW",
            "approval": "auto",
            "rule": "read_safe",
            "allowed": True,
        }
        assert payload["summary"] == {
            "total": 2,
            "blocked": 1,
            "approval_required": 0,
            "auto": 1,
        }

    def test_strict_blocked_exits_1(self, tmp_path: Path) -> None:
        policy = _write_policy(tmp_path / "policy.yaml")
        with pytest.raises(SystemExit) as exc:
            main(["check", "policy", str(policy), "read:crm", "delete:db", "--strict"])
        assert exc.value.code == 1

    def test_strict_approval_exits_2(self, tmp_path: Path) -> None:
        policy = _write_policy(tmp_path / "policy.yaml")
        with pytest.raises(SystemExit) as exc:
            main(["check", "policy", str(policy), "read:crm", "bulk_update:crm", "--strict"])
        assert exc.value.code == 2

    def test_strict_all_auto_exits_0(self, tmp_path: Path) -> None:
        policy = _write_policy(tmp_path / "policy.yaml")
        with pytest.raises(SystemExit) as exc:
            main(["check", "policy", str(policy), "read:crm", "--strict"])
        assert exc.value.code == 0

    def test_without_strict_blocked_still_exits_0(self, tmp_path: Path) -> None:
        """Reporting mode: the gate only bites under --strict."""
        policy = _write_policy(tmp_path / "policy.yaml")
        with pytest.raises(SystemExit) as exc:
            main(["check", "policy", str(policy), "delete:db"])
        assert exc.value.code == 0

    def test_missing_policy_file(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["check", "policy", str(tmp_path / "nope.yaml"), "read:crm"])
        assert exc.value.code == 2
        assert "not found" in capsys.readouterr().err

    def test_malformed_policy_file(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("rules: [this is: not: valid")
        with pytest.raises(SystemExit) as exc:
            main(["check", "policy", str(bad), "read:crm"])
        assert exc.value.code == 2
        assert "failed to load policy" in capsys.readouterr().err

    def test_bare_check_still_reports_usage(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """`aegis check` with no sub-subcommand lists both kinds."""
        with pytest.raises(SystemExit) as exc:
            main(["check"])
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "check drift" in err
        assert "check policy" in err
