"""Tests for ``aegis scan`` CLI command and scanner module."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis.cli.main import main
from aegis.cli.scan import Finding, format_report, scan_directory, scan_file

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
        assert "pip install agent-aegis" in report

    def test_findings_report(self) -> None:
        findings = [
            Finding(file="/project/src/agent.py", line=15, category="LangChain", detail="@tool"),
            Finding(file="/project/src/agent.py", line=32, category="subprocess", detail="run"),
        ]
        report = format_report(10, findings, directory="/project")
        assert "Found 2 ungoverned tool call(s)" in report
        assert "Governance Score:" in report
        assert "pip install agent-aegis" in report


# ---------------------------------------------------------------------------
# Grade calculation
# ---------------------------------------------------------------------------


class TestGrading:
    def test_grade_a(self) -> None:
        from aegis.cli.scan import _grade

        assert _grade(0) == "A"

    def test_grade_b(self) -> None:
        from aegis.cli.scan import _grade

        assert _grade(1) == "B"

    def test_grade_c(self) -> None:
        from aegis.cli.scan import _grade

        assert _grade(3) == "C"

    def test_grade_d(self) -> None:
        from aegis.cli.scan import _grade

        assert _grade(6) == "D"

    def test_grade_f(self) -> None:
        from aegis.cli.scan import _grade

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
