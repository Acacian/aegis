"""Tests for ``aegis scan`` CLI command and scanner module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.cli.main import main
from aegis.cli.scan import (
    Finding,
    _grade,
    _grade_meets_threshold,
    format_json,
    format_report,
    format_sarif,
    run_scan,
    scan_directory,
    scan_file,
    suggest_rules,
)

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _write(tmp_path: Path, name: str, code: str) -> Path:
    """Write *code* to *tmp_path/name* and return the path."""
    p = tmp_path / name
    p.write_text(code)
    return p


# ---------------------------------------------------------------------------
# scan_file unit tests — LangChain
# ---------------------------------------------------------------------------


class TestLangChainDetection:
    def test_tool_decorator(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
from langchain_core.tools import tool

@tool
def search_web(query: str) -> str:
    return "results"
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].category == "LangChain"
        assert "@tool" in findings[0].detail
        assert "search_web" in findings[0].detail

    def test_basetool_subclass_ungoverned(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "tools.py",
            """\
from langchain_core.tools import BaseTool

class MyTool(BaseTool):
    name = "my_tool"
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].category == "LangChain"
        assert "BaseTool" in findings[0].detail

    def test_basetool_with_governed_ignored(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "tools.py",
            """\
from langchain_core.tools import BaseTool
from langchain_aegis import GovernedTool

class MyTool(BaseTool, GovernedTool):
    name = "my_tool"
""",
        )
        findings = scan_file(f)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# scan_file unit tests — OpenAI
# ---------------------------------------------------------------------------


class TestOpenAIDetection:
    def test_chat_completions_with_tools(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "ai.py",
            """\
import openai

client = openai.OpenAI()
client.chat.completions.create(model="gpt-4", tools=[{"type": "function"}])
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].category == "OpenAI"

    def test_chat_completions_without_tools_clean(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "ai.py",
            """\
import openai

client = openai.OpenAI()
client.chat.completions.create(model="gpt-4", messages=[])
""",
        )
        findings = scan_file(f)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# scan_file unit tests — Anthropic
# ---------------------------------------------------------------------------


class TestAnthropicDetection:
    def test_messages_create_with_tools(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "ai.py",
            """\
import anthropic

client = anthropic.Anthropic()
client.messages.create(model="claude-3", tools=[{"name": "t"}])
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].category == "Anthropic"

    def test_messages_create_without_tools_clean(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "ai.py",
            """\
import anthropic

client = anthropic.Anthropic()
client.messages.create(model="claude-3", messages=[])
""",
        )
        findings = scan_file(f)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# scan_file unit tests — subprocess / os
# ---------------------------------------------------------------------------


class TestSubprocessDetection:
    def test_subprocess_run(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
import subprocess
subprocess.run(["ls", "-la"])
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].category == "subprocess"
        assert "subprocess.run" in findings[0].detail

    def test_subprocess_popen(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
import subprocess
subprocess.Popen(["echo", "hi"])
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert "Popen" in findings[0].detail

    def test_os_system(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
import os
os.system("rm -rf /tmp/test")
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert "os.system" in findings[0].detail

    def test_os_exec(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
import os
os.execvp("python", ["python", "script.py"])
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert "os.execvp" in findings[0].detail

    def test_bare_import_run(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
from subprocess import run
run(["ls"])
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert "subprocess.run" in findings[0].detail


# ---------------------------------------------------------------------------
# scan_file unit tests — HTTP
# ---------------------------------------------------------------------------


class TestHTTPDetection:
    def test_requests_post(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
import requests
requests.post("https://api.example.com/action", json={})
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].category == "HTTP"

    def test_httpx_post(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
import httpx
httpx.post("https://api.example.com/action", json={})
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].category == "HTTP"


# ---------------------------------------------------------------------------
# scan_file unit tests — MCP
# ---------------------------------------------------------------------------


class TestMCPDetection:
    def test_mcp_tool_decorator(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "server.py",
            """\
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")

@mcp.tool()
def search(query: str) -> str:
    return "results"
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].category == "MCP"
        assert "search" in findings[0].detail


# ---------------------------------------------------------------------------
# Clean file — no findings
# ---------------------------------------------------------------------------


class TestCleanFiles:
    def test_plain_python(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "clean.py",
            """\
def add(a, b):
    return a + b

print(add(1, 2))
""",
        )
        findings = scan_file(f)
        assert len(findings) == 0

    def test_syntax_error_skipped(self, tmp_path: Path) -> None:
        f = _write(tmp_path, "broken.py", "def (oops\n")
        findings = scan_file(f)
        assert len(findings) == 0

    def test_nonexistent_file(self) -> None:
        findings = scan_file("/nonexistent/path/agent.py")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# scan_directory
# ---------------------------------------------------------------------------


class TestScanDirectory:
    def test_recursive_scan(self, tmp_path: Path) -> None:
        sub = tmp_path / "pkg"
        sub.mkdir()
        _write(sub, "agent.py", "import subprocess\nsubprocess.run(['ls'])\n")
        _write(tmp_path, "clean.py", "x = 1\n")

        file_count, findings = scan_directory(tmp_path)
        assert file_count == 2
        assert len(findings) == 1

    def test_skips_hidden_dirs(self, tmp_path: Path) -> None:
        hidden = tmp_path / ".hidden"
        hidden.mkdir()
        _write(hidden, "agent.py", "import subprocess\nsubprocess.run(['ls'])\n")

        file_count, findings = scan_directory(tmp_path)
        assert file_count == 0
        assert len(findings) == 0

    def test_skips_pycache(self, tmp_path: Path) -> None:
        cache = tmp_path / "__pycache__"
        cache.mkdir()
        _write(cache, "agent.cpython-311.py", "import subprocess\nsubprocess.run(['ls'])\n")

        file_count, findings = scan_directory(tmp_path)
        assert file_count == 0
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# format_report
# ---------------------------------------------------------------------------


class TestFormatReport:
    def test_clean_report(self) -> None:
        report = format_report(10, [])
        assert "Governance Score: A" in report
        assert "No ungoverned tool calls found" in report
        assert "acacian.github.io/aegis" in report

    def test_findings_report(self) -> None:
        findings = [
            Finding(file="/project/src/agent.py", line=15, category="LangChain", detail="@tool"),
            Finding(file="/project/src/agent.py", line=32, category="subprocess", detail="run"),
        ]
        report = format_report(10, findings, directory="/project")
        assert "Found 2 ungoverned tool call(s)" in report
        assert "Governance Score:" in report
        assert "Next steps:" in report

    def test_owasp_risk_in_report(self) -> None:
        findings = [
            Finding(
                file="/project/agent.py",
                line=10,
                category="OpenAI",
                detail="tools=",
                owasp_risk="ASI02: Tool Misuse & Exploitation",
            ),
        ]
        report = format_report(1, findings, directory="/project")
        assert "ASI02" in report
        assert "Tool Misuse & Exploitation" in report
        assert "OWASP Agentic Top 10 Risks:" in report

    def test_owasp_summary_counts(self) -> None:
        findings = [
            Finding(
                file="/p/a.py",
                line=1,
                category="OpenAI",
                detail="x",
                owasp_risk="ASI02: Tool Misuse & Exploitation",
            ),
            Finding(
                file="/p/a.py",
                line=2,
                category="LangChain",
                detail="y",
                owasp_risk="ASI02: Tool Misuse & Exploitation",
            ),
            Finding(
                file="/p/a.py",
                line=3,
                category="subprocess",
                detail="z",
                owasp_risk="ASI08: Uncontrolled Code Execution",
            ),
        ]
        report = format_report(1, findings, directory="/p")
        assert "ASI02: Tool Misuse & Exploitation: 2 finding(s)" in report
        assert "ASI08: Uncontrolled Code Execution: 1 finding(s)" in report


# ---------------------------------------------------------------------------
# Grade calculation
# ---------------------------------------------------------------------------


class TestGrading:
    def test_grade_a(self) -> None:
        assert _grade(0) == "A"

    def test_grade_b(self) -> None:
        assert _grade(1) == "B"

    def test_grade_c(self) -> None:
        assert _grade(3) == "C"

    def test_grade_d(self) -> None:
        assert _grade(6) == "D"

    def test_grade_f(self) -> None:
        assert _grade(7) == "F"
        assert _grade(100) == "F"


# ---------------------------------------------------------------------------
# CLI integration — ``aegis scan``
# ---------------------------------------------------------------------------


class TestCLIScan:
    def test_scan_clean_directory(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _write(tmp_path, "clean.py", "x = 1\n")
        with pytest.raises(SystemExit) as exc_info:
            main(["scan", str(tmp_path)])
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "Governance Score: A" in out

    def test_scan_dirty_directory(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _write(tmp_path, "agent.py", "import subprocess\nsubprocess.run(['ls'])\n")
        with pytest.raises(SystemExit) as exc_info:
            main(["scan", str(tmp_path)])
        assert exc_info.value.code == 1
        out = capsys.readouterr().out
        assert "ungoverned" in out

    def test_scan_nonexistent_directory(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(["scan", "/nonexistent/path"])
        assert exc_info.value.code == 1

    def test_scan_defaults_to_cwd(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Ensure ``aegis scan`` (no args) doesn't crash."""
        with pytest.raises(SystemExit):
            main(["scan"])
        # It should produce output either way
        out = capsys.readouterr().out
        assert "Aegis Governance Scan" in out


# ---------------------------------------------------------------------------
# Multiple findings in one file
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# OWASP mapping auto-population
# ---------------------------------------------------------------------------


class TestOWASPMapping:
    def test_openai_gets_asi02(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "ai.py",
            """\
import openai
client = openai.OpenAI()
client.chat.completions.create(model="gpt-4", tools=[{"type": "function"}])
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].owasp_risk == "ASI02: Tool Misuse & Exploitation"

    def test_subprocess_gets_asi08(self, tmp_path: Path) -> None:
        f = _write(tmp_path, "a.py", "import subprocess\nsubprocess.run(['ls'])\n")
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].owasp_risk == "ASI08: Uncontrolled Code Execution"

    def test_mcp_gets_asi04(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "s.py",
            """\
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("demo")

@mcp.tool()
def search(query: str) -> str:
    return "results"
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].owasp_risk == "ASI04: Supply Chain Vulnerabilities"

    def test_http_gets_asi07(self, tmp_path: Path) -> None:
        f = _write(tmp_path, "a.py", "import requests\nrequests.post('http://x')\n")
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].owasp_risk == "ASI07: Data Leakage & Exfiltration"

    def test_clean_file_no_owasp(self, tmp_path: Path) -> None:
        f = _write(tmp_path, "clean.py", "x = 1\n")
        findings = scan_file(f)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Multiple findings in one file
# ---------------------------------------------------------------------------


class TestMultipleFindings:
    def test_mixed_patterns(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
import subprocess
import os
import requests

subprocess.run(["ls"])
os.system("echo hi")
requests.post("https://example.com")
""",
        )
        findings = scan_file(f)
        assert len(findings) == 3
        categories = {f.category for f in findings}
        assert categories == {"subprocess", "HTTP"}


# ---------------------------------------------------------------------------
# NEW: --format json
# ---------------------------------------------------------------------------


class TestFormatJSON:
    def test_json_output_structure(self) -> None:
        findings = [
            Finding(
                file="/p/agent.py",
                line=10,
                category="OpenAI",
                detail="tools=",
                owasp_risk="ASI02: Tool Misuse & Exploitation",
                fix="Wrap with aegis: import aegis; aegis.auto_instrument()",
            ),
        ]
        output = format_json(1, findings, directory="/p")
        data = json.loads(output)
        assert data["tool"] == "aegis-scan"
        assert data["files_scanned"] == 1
        assert data["findings_count"] == 1
        assert data["grade"] == "B"
        assert len(data["findings"]) == 1
        assert data["findings"][0]["file"] == "/p/agent.py"
        assert data["findings"][0]["fix"] != ""

    def test_json_empty_findings(self) -> None:
        output = format_json(5, [])
        data = json.loads(output)
        assert data["grade"] == "A"
        assert data["findings_count"] == 0
        assert data["findings"] == []

    def test_json_owasp_summary(self) -> None:
        findings = [
            Finding(file="/p/a.py", line=1, category="OpenAI", detail="x", owasp_risk="ASI02: T"),
            Finding(
                file="/p/a.py", line=2, category="subprocess", detail="y", owasp_risk="ASI08: U"
            ),
        ]
        output = format_json(1, findings, directory="/p")
        data = json.loads(output)
        assert "ASI02: T" in data["owasp_summary"]
        assert "ASI08: U" in data["owasp_summary"]


# ---------------------------------------------------------------------------
# NEW: --format sarif
# ---------------------------------------------------------------------------


class TestFormatSARIF:
    def test_sarif_valid_structure(self) -> None:
        findings = [
            Finding(
                file="/p/agent.py",
                line=10,
                category="OpenAI",
                detail="tools=",
                owasp_risk="ASI02: Tool Misuse & Exploitation",
                fix="Wrap with aegis",
            ),
        ]
        output = format_sarif(1, findings, directory="/p")
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "aegis-scan"
        assert len(run["tool"]["driver"]["rules"]) == 1
        assert len(run["results"]) == 1

    def test_sarif_result_location(self) -> None:
        findings = [
            Finding(file="/p/src/agent.py", line=15, category="LangChain", detail="@tool"),
        ]
        output = format_sarif(1, findings, directory="/p")
        data = json.loads(output)
        loc = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/agent.py"
        assert loc["region"]["startLine"] == 15

    def test_sarif_deduplicates_rules(self) -> None:
        findings = [
            Finding(file="/p/a.py", line=1, category="OpenAI", detail="x", owasp_risk="ASI02: T"),
            Finding(file="/p/b.py", line=2, category="OpenAI", detail="y", owasp_risk="ASI02: T"),
        ]
        output = format_sarif(2, findings, directory="/p")
        data = json.loads(output)
        assert len(data["runs"][0]["tool"]["driver"]["rules"]) == 1
        assert len(data["runs"][0]["results"]) == 2

    def test_sarif_empty_findings(self) -> None:
        output = format_sarif(5, [])
        data = json.loads(output)
        assert data["runs"][0]["results"] == []

    def test_sarif_fix_in_help(self) -> None:
        findings = [
            Finding(file="/p/a.py", line=1, category="OpenAI", detail="x", fix="Do this"),
        ]
        output = format_sarif(1, findings, directory="/p")
        data = json.loads(output)
        rule = data["runs"][0]["tool"]["driver"]["rules"][0]
        assert "help" in rule
        assert "Do this" in rule["help"]["text"]


# ---------------------------------------------------------------------------
# NEW: --threshold
# ---------------------------------------------------------------------------


class TestThreshold:
    def test_grade_meets_threshold(self) -> None:
        assert _grade_meets_threshold("A", "A") is True
        assert _grade_meets_threshold("A", "C") is True
        assert _grade_meets_threshold("B", "A") is False
        assert _grade_meets_threshold("F", "D") is False
        assert _grade_meets_threshold("D", "F") is True

    def test_threshold_pass(self, tmp_path: Path) -> None:
        _write(tmp_path, "clean.py", "x = 1\n")
        exit_code = run_scan(str(tmp_path), threshold="A")
        assert exit_code == 0

    def test_threshold_fail(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _write(tmp_path, "agent.py", "import subprocess\nsubprocess.run(['ls'])\n")
        exit_code = run_scan(str(tmp_path), threshold="A")
        assert exit_code == 1
        err = capsys.readouterr().err
        assert "does not meet threshold" in err

    def test_threshold_pass_with_findings(self, tmp_path: Path) -> None:
        _write(tmp_path, "agent.py", "import subprocess\nsubprocess.run(['ls'])\n")
        exit_code = run_scan(str(tmp_path), threshold="F")
        assert exit_code == 0


# ---------------------------------------------------------------------------
# NEW: # aegis: ignore pragma
# ---------------------------------------------------------------------------


class TestIgnorePragma:
    def test_ignore_pragma_skips_finding(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "agent.py",
            """\
import subprocess
subprocess.run(["ls"])  # aegis: ignore
""",
        )
        _, findings = scan_directory(tmp_path)
        assert len(findings) == 0

    def test_ignore_pragma_no_space(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "agent.py",
            """\
import subprocess
subprocess.run(["ls"])  # aegis:ignore
""",
        )
        _, findings = scan_directory(tmp_path)
        assert len(findings) == 0

    def test_without_pragma_still_found(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "agent.py",
            """\
import subprocess
subprocess.run(["ls"])
""",
        )
        _, findings = scan_directory(tmp_path)
        assert len(findings) == 1

    def test_pragma_on_different_line_no_effect(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "agent.py",
            """\
import subprocess
# aegis: ignore
subprocess.run(["ls"])
""",
        )
        _, findings = scan_directory(tmp_path)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# NEW: .aegisscanignore
# ---------------------------------------------------------------------------


class TestAegisscanignore:
    def test_ignore_file_pattern(self, tmp_path: Path) -> None:
        tests_dir = tmp_path / "tests"
        tests_dir.mkdir()
        _write(tests_dir, "test_agent.py", "import subprocess\nsubprocess.run(['ls'])\n")
        _write(tmp_path, "agent.py", "import subprocess\nsubprocess.run(['ls'])\n")
        (tmp_path / ".aegisscanignore").write_text("tests/\n")

        _, findings = scan_directory(tmp_path)
        assert len(findings) == 1
        assert "tests" not in findings[0].file

    def test_ignore_glob_pattern(self, tmp_path: Path) -> None:
        _write(tmp_path, "test_foo.py", "import subprocess\nsubprocess.run(['ls'])\n")
        _write(tmp_path, "agent.py", "import subprocess\nsubprocess.run(['ls'])\n")
        (tmp_path / ".aegisscanignore").write_text("test_*.py\n")

        _, findings = scan_directory(tmp_path)
        assert len(findings) == 1

    def test_ignore_comments_and_blank_lines(self, tmp_path: Path) -> None:
        _write(tmp_path, "agent.py", "import subprocess\nsubprocess.run(['ls'])\n")
        (tmp_path / ".aegisscanignore").write_text("# comment\n\n  \n")

        _, findings = scan_directory(tmp_path)
        assert len(findings) == 1

    def test_no_ignore_file(self, tmp_path: Path) -> None:
        _write(tmp_path, "agent.py", "import subprocess\nsubprocess.run(['ls'])\n")
        _, findings = scan_directory(tmp_path)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# NEW: quickfix suggestions
# ---------------------------------------------------------------------------


class TestQuickfixSuggestions:
    def test_fix_in_finding(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "ai.py",
            """\
import openai
client = openai.OpenAI()
client.chat.completions.create(model="gpt-4", tools=[{"type": "function"}])
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].fix != ""
        assert "auto_instrument" in findings[0].fix

    def test_fix_in_text_output(self) -> None:
        findings = [
            Finding(
                file="/p/a.py",
                line=1,
                category="OpenAI",
                detail="tools=",
                fix="Wrap with aegis: import aegis; aegis.auto_instrument()",
            ),
        ]
        report = format_report(1, findings, directory="/p", show_fixes=True)
        assert "\u2192" in report
        assert "auto_instrument" in report

    def test_fix_hidden_when_disabled(self) -> None:
        findings = [
            Finding(file="/p/a.py", line=1, category="OpenAI", detail="tools=", fix="Do X"),
        ]
        report = format_report(1, findings, directory="/p", show_fixes=False)
        assert "\u2192" not in report

    def test_subprocess_fix(self, tmp_path: Path) -> None:
        f = _write(tmp_path, "a.py", "import subprocess\nsubprocess.run(['ls'])\n")
        findings = scan_file(f)
        assert "sandbox" in findings[0].fix.lower()


# ---------------------------------------------------------------------------
# NEW: suggest-rules
# ---------------------------------------------------------------------------


class TestSuggestRules:
    def test_suggest_from_findings(self) -> None:
        findings = [
            Finding(file="/p/a.py", line=1, category="OpenAI", detail="x"),
            Finding(file="/p/a.py", line=2, category="subprocess", detail="y"),
        ]
        output = suggest_rules(findings)
        assert "version:" in output
        assert "rules:" in output
        assert "openai_function_call_governance" in output
        assert "block_shell_execution" in output

    def test_suggest_empty(self) -> None:
        output = suggest_rules([])
        assert "clean" in output.lower()

    def test_suggest_deduplicates(self) -> None:
        findings = [
            Finding(file="/p/a.py", line=1, category="OpenAI", detail="x"),
            Finding(file="/p/b.py", line=2, category="OpenAI", detail="y"),
        ]
        output = suggest_rules(findings)
        assert output.count("openai_function_call_governance") == 1


# ---------------------------------------------------------------------------
# NEW: CLI integration for new flags
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# NEW: Framework detection — CrewAI
# ---------------------------------------------------------------------------


class TestCrewAIDetection:
    def test_crew_instantiation(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
from crewai import Crew
crew = Crew(agents=[], tasks=[])
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].category == "CrewAI"
        assert "Crew()" in findings[0].detail

    def test_crew_not_from_crewai_clean(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
from mylib import Crew
crew = Crew()
""",
        )
        findings = scan_file(f)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# NEW: Framework detection — LiteLLM
# ---------------------------------------------------------------------------


class TestLiteLLMDetection:
    def test_litellm_completion(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
import litellm
litellm.completion(model="gpt-4", messages=[])
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].category == "LiteLLM"

    def test_litellm_acompletion(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
import litellm
litellm.acompletion(model="gpt-4", messages=[])
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].category == "LiteLLM"

    def test_litellm_bare_import(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
from litellm import completion
completion(model="gpt-4", messages=[])
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].category == "LiteLLM"


# ---------------------------------------------------------------------------
# NEW: Framework detection — LlamaIndex
# ---------------------------------------------------------------------------


class TestLlamaIndexDetection:
    def test_llamaindex_query(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
from llama_index.core import VectorStoreIndex
index = VectorStoreIndex.from_documents(docs)
engine = index.as_query_engine()
engine.query("what is X?")
""",
        )
        # engine.query won't match because 'engine' isn't resolved to llama_index
        # But direct import usage will
        findings = scan_file(f)
        assert len(findings) == 0  # can't resolve engine

    def test_llamaindex_direct_import(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
import llama_index.core as li
li.chat("hello")
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].category == "LlamaIndex"


# ---------------------------------------------------------------------------
# NEW: Framework detection — Google GenAI / Gemini
# ---------------------------------------------------------------------------


class TestGoogleGenAIDetection:
    def test_generate_content(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
import google.generativeai as genai
model = genai.GenerativeModel("gemini-pro")
model.generate_content("hello")
""",
        )
        # model.generate_content — 'model' not resolved to google
        findings = scan_file(f)
        assert len(findings) == 0  # can't resolve local var

    def test_genai_generate_content_resolved(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
import google.generativeai as genai
genai.generate_content("hello")
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].category == "Google GenAI"

    def test_generative_model_bare(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
from google.generativeai import GenerativeModel
m = GenerativeModel("gemini-pro")
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].category == "Google GenAI"
        assert "GenerativeModel()" in findings[0].detail


# ---------------------------------------------------------------------------
# NEW: Framework detection — PydanticAI
# ---------------------------------------------------------------------------


class TestPydanticAIDetection:
    def test_agent_instantiation(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
from pydantic_ai import Agent
agent = Agent("openai:gpt-4")
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].category == "PydanticAI"
        assert "Agent()" in findings[0].detail

    def test_agent_run(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
from pydantic_ai import Agent
agent = Agent("openai:gpt-4")
agent.run_sync("hello")
""",
        )
        findings = scan_file(f)
        # Agent() bare + agent.run_sync won't match (agent not resolved)
        assert any(f.category == "PydanticAI" for f in findings)

    def test_agent_tool_decorator(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
from pydantic_ai import Agent
agent = Agent("openai:gpt-4")

@agent.tool
def search(query: str) -> str:
    return "results"
""",
        )
        findings = scan_file(f)
        # Should detect both Agent() and @agent.tool
        cats = [f.category for f in findings]
        assert "PydanticAI" in cats

    def test_agent_not_from_pydantic_ai_clean(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
from mylib import Agent
a = Agent()
""",
        )
        findings = scan_file(f)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# NEW: Framework detection — OpenAI Agents SDK
# ---------------------------------------------------------------------------


class TestOpenAIAgentsDetection:
    def test_agent_instantiation(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
from openai.agents import Agent
agent = Agent(name="helper", model="gpt-4")
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].category == "OpenAI Agents"

    def test_tool_decorator(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
from openai.agents import tool

@tool
def search_web(query: str) -> str:
    return "results"
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].category == "OpenAI Agents"

    def test_runner_run(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
from openai.agents import Runner
Runner.run(agent, "hello")
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].category == "OpenAI Agents"


# ---------------------------------------------------------------------------
# NEW: Framework detection — Instructor
# ---------------------------------------------------------------------------


class TestInstructorDetection:
    def test_from_openai(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
from instructor import from_openai
client = from_openai(openai_client)
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].category == "Instructor"
        assert "from_openai" in findings[0].detail

    def test_from_anthropic(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
from instructor import from_anthropic
client = from_anthropic(anthropic_client)
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].category == "Instructor"

    def test_not_from_instructor_clean(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
from mylib import from_openai
client = from_openai(x)
""",
        )
        findings = scan_file(f)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# NEW: Framework detection — DSPy
# ---------------------------------------------------------------------------


class TestDSPyDetection:
    def test_dspy_module_subclass(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
import dspy

class MyRAG(dspy.Module):
    def forward(self, question):
        return self.generate(question)
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].category == "DSPy"
        assert "MyRAG" in findings[0].detail

    def test_bare_module_from_dspy(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
from dspy import Module

class MyPipeline(Module):
    pass
""",
        )
        findings = scan_file(f)
        assert len(findings) == 1
        assert findings[0].category == "DSPy"

    def test_module_not_from_dspy_clean(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            "agent.py",
            """\
from torch.nn import Module

class MyNet(Module):
    pass
""",
        )
        findings = scan_file(f)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# NEW: suggest_rules handles new categories
# ---------------------------------------------------------------------------


class TestSuggestRulesNewCategories:
    def test_suggest_crewai(self) -> None:
        findings = [Finding(file="/p/a.py", line=1, category="CrewAI", detail="x")]
        output = suggest_rules(findings)
        assert "crewai_governance" in output

    def test_suggest_litellm(self) -> None:
        findings = [Finding(file="/p/a.py", line=1, category="LiteLLM", detail="x")]
        output = suggest_rules(findings)
        assert "litellm_governance" in output

    def test_suggest_pydanticai(self) -> None:
        findings = [Finding(file="/p/a.py", line=1, category="PydanticAI", detail="x")]
        output = suggest_rules(findings)
        assert "pydanticai_governance" in output

    def test_suggest_openai_agents(self) -> None:
        findings = [
            Finding(file="/p/a.py", line=1, category="OpenAI Agents", detail="x"),
        ]
        output = suggest_rules(findings)
        assert "openai_agents_governance" in output

    def test_suggest_dspy(self) -> None:
        findings = [Finding(file="/p/a.py", line=1, category="DSPy", detail="x")]
        output = suggest_rules(findings)
        assert "dspy_governance" in output


class TestCLIScanNewFlags:
    def test_scan_json_format(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _write(tmp_path, "agent.py", "import subprocess\nsubprocess.run(['ls'])\n")
        with pytest.raises(SystemExit):
            main(["scan", str(tmp_path), "--format", "json"])
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["tool"] == "aegis-scan"
        assert data["findings_count"] == 1

    def test_scan_sarif_format(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _write(tmp_path, "agent.py", "import subprocess\nsubprocess.run(['ls'])\n")
        with pytest.raises(SystemExit):
            main(["scan", str(tmp_path), "--format", "sarif"])
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["version"] == "2.1.0"

    def test_scan_suggest_format(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _write(tmp_path, "agent.py", "import subprocess\nsubprocess.run(['ls'])\n")
        with pytest.raises(SystemExit):
            main(["scan", str(tmp_path), "--format", "suggest"])
        out = capsys.readouterr().out
        assert "rules:" in out

    def test_scan_threshold_cli(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _write(tmp_path, "agent.py", "import subprocess\nsubprocess.run(['ls'])\n")
        with pytest.raises(SystemExit) as exc_info:
            main(["scan", str(tmp_path), "--threshold", "A"])
        assert exc_info.value.code == 1

    def test_scan_no_fixes_flag(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _write(tmp_path, "agent.py", "import subprocess\nsubprocess.run(['ls'])\n")
        with pytest.raises(SystemExit):
            main(["scan", str(tmp_path), "--no-fixes"])
        out = capsys.readouterr().out
        assert "\u2192" not in out
