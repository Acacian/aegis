"""Static detection of dangerous code patterns before execution.

Addresses OWASP Agentic AI Threat ASI05 (Unexpected Code Execution /
Remote Code Execution).  Scans code *before* any interpreter runs,
flagging shell injection, code injection, filesystem destruction,
network exfiltration, privilege escalation, and unsafe deserialization.

Uses :mod:`ast` for structural Python analysis and compiled regexes for
non-Python / surface-level pattern matching.

Pure Python, no external dependencies.  Thread-safe, deterministic,
sub-millisecond.

References:
    OWASP Agentic AI -- ASI05: Unexpected Code Execution.
    https://genai.owasp.org/threats/asi05-unexpected-code-execution/
    CWE-94: Improper Control of Generation of Code ('Code Injection').
    https://cwe.mitre.org/data/definitions/94.html

Example::

    gate = CodeExecSafetyGate()
    result = gate.check("import os; os.system('rm -rf /')")
    assert not result.passed
    assert result.action == "block"
"""

from __future__ import annotations

import ast
import re
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(StrEnum):
    """Finding severity level."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Category(StrEnum):
    """Detection category for dangerous code patterns."""

    SHELL_INJECTION = "shell_injection"
    CODE_INJECTION = "code_injection"
    FILE_SYSTEM_DANGER = "file_system_danger"
    NETWORK_EXFILTRATION = "network_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DESERIALIZATION = "deserialization"


class ExecAction(StrEnum):
    """Action to take when a dangerous pattern is detected."""

    BLOCK = "block"
    WARN = "warn"
    LOG = "log"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CodeExecFinding:
    """A single dangerous-code detection result."""

    category: Category
    severity: Severity
    pattern_name: str
    matched_text: str
    line_number: int
    description: str


@dataclass(frozen=True)
class CodeExecResult:
    """Aggregate result of a code-execution safety check."""

    passed: bool
    findings: tuple[CodeExecFinding, ...] = ()
    severity: str = ""
    action: str = "allow"


# ---------------------------------------------------------------------------
# Regex-based patterns  (name, severity, regex, description)
# ---------------------------------------------------------------------------

_P = tuple[str, Severity, re.Pattern[str], str]


def _c(n: str, s: Severity, p: str, d: str) -> _P:
    return (n, s, re.compile(p), d)


_S = Severity
_SHELL: list[_P] = [
    _c("os_system", _S.CRITICAL, r"\bos\.system\s*\(", "os.system() shell execution"),
    _c(
        "subprocess_call",
        _S.CRITICAL,
        r"\bsubprocess\.(?:call|run|Popen|check_output|check_call|getoutput|getstatusoutput)\s*\(",
        "subprocess module executes external processes",
    ),
    _c("os_popen", _S.CRITICAL, r"\bos\.popen\s*\(", "os.popen() shell pipe"),
    _c("backtick_exec", _S.HIGH, r"`[^`]+`", "Backtick execution pattern"),
    _c(
        "os_exec_family",
        _S.CRITICAL,
        r"\bos\.exec(?:l|le|lp|lpe|v|ve|vp|vpe)\s*\(",
        "os.exec*() replaces process",
    ),
]
_CODE_INJ: list[_P] = [
    _c("eval_call", _S.CRITICAL, r"\beval\s*\(", "eval() arbitrary expression"),
    _c("exec_call", _S.CRITICAL, r"\bexec\s*\(", "exec() arbitrary code"),
    _c("compile_call", _S.HIGH, r"\bcompile\s*\(", "compile() code objects"),
    _c("dunder_import", _S.HIGH, r"\b__import__\s*\(", "__import__() dynamic import"),
]
_FS: list[_P] = [
    _c("os_remove", _S.HIGH, r"\bos\.(?:remove|unlink)\s*\(", "os.remove()/unlink() deletes"),
    _c("shutil_rmtree", _S.CRITICAL, r"\bshutil\.rmtree\s*\(", "shutil.rmtree() recursive delete"),
    _c("pathlib_unlink", _S.HIGH, r"\.unlink\s*\(", "Path.unlink() deletes files"),
    _c(
        "open_write_sensitive",
        _S.HIGH,
        r"""\bopen\s*\([^)]*(?:/etc/|/root/|~|\.\./)[^)]*,\s*['"][wa]""",
        "Writing to sensitive paths",
    ),
]
_NET: list[_P] = [
    _c(
        "urllib_request",
        _S.MEDIUM,
        r"\burllib\.request\.(?:urlopen|urlretrieve|Request)\s*\(",
        "urllib exfiltration risk",
    ),
    _c(
        "requests_post",
        _S.HIGH,
        r"\brequests\.(?:post|put|patch|delete)\s*\(",
        "requests sending data externally",
    ),
    _c(
        "httpx_post",
        _S.HIGH,
        r"\bhttpx\.(?:post|put|patch|delete)\s*\(",
        "httpx sending data externally",
    ),
    _c(
        "socket_connect",
        _S.HIGH,
        r"\bsocket\.(?:socket|create_connection)\s*\(",
        "Raw socket connection",
    ),
]
_PRIV: list[_P] = [
    _c(
        "os_setuid",
        _S.CRITICAL,
        r"\bos\.set(?:uid|gid|euid|egid|reuid|regid)\s*\(",
        "os.setuid() privilege change",
    ),
    _c("os_chmod", _S.HIGH, r"\bos\.chmod\s*\(", "os.chmod() permission change"),
    _c("ctypes_usage", _S.HIGH, r"\bctypes\.\w+", "ctypes arbitrary C calls"),
    _c("os_kill", _S.HIGH, r"\bos\.kill\s*\(", "os.kill() process signal"),
]
_DESER: list[_P] = [
    _c(
        "pickle_loads",
        _S.CRITICAL,
        r"\bpickle\.(?:loads?|Unpickler)\s*\(",
        "pickle deserialization executes code",
    ),
    _c(
        "yaml_unsafe_load",
        _S.CRITICAL,
        r"\byaml\.(?:load|unsafe_load)\s*\(",
        "yaml.load() without SafeLoader",
    ),
    _c("marshal_loads", _S.HIGH, r"\bmarshal\.loads?\s*\(", "marshal deserialization"),
    _c("shelve_open", _S.HIGH, r"\bshelve\.open\s*\(", "shelve uses pickle internally"),
]

_ALL_REGEX: list[tuple[Category, list[_P]]] = [
    (Category.SHELL_INJECTION, _SHELL),
    (Category.CODE_INJECTION, _CODE_INJ),
    (Category.FILE_SYSTEM_DANGER, _FS),
    (Category.NETWORK_EXFILTRATION, _NET),
    (Category.PRIVILEGE_ESCALATION, _PRIV),
    (Category.DESERIALIZATION, _DESER),
]

# ---------------------------------------------------------------------------
# AST dangerous-call definitions
# (module_or_empty, func) -> (category, severity, description)
# ---------------------------------------------------------------------------

_C, _Sv = Category, Severity  # short aliases for table
_AST_CALLS: dict[tuple[str, str], tuple[Category, Severity, str]] = {
    ("os", "system"): (_C.SHELL_INJECTION, _Sv.CRITICAL, "os.system() shell execution"),
    ("os", "popen"): (_C.SHELL_INJECTION, _Sv.CRITICAL, "os.popen() shell pipe"),
    ("subprocess", "call"): (_C.SHELL_INJECTION, _Sv.CRITICAL, "subprocess.call()"),
    ("subprocess", "run"): (_C.SHELL_INJECTION, _Sv.CRITICAL, "subprocess.run()"),
    ("subprocess", "Popen"): (_C.SHELL_INJECTION, _Sv.CRITICAL, "subprocess.Popen()"),
    ("subprocess", "check_output"): (_C.SHELL_INJECTION, _Sv.CRITICAL, "subprocess.check_output"),
    ("subprocess", "check_call"): (_C.SHELL_INJECTION, _Sv.CRITICAL, "subprocess.check_call()"),
    ("", "eval"): (_C.CODE_INJECTION, _Sv.CRITICAL, "eval() arbitrary expression"),
    ("", "exec"): (_C.CODE_INJECTION, _Sv.CRITICAL, "exec() arbitrary code"),
    ("", "compile"): (_C.CODE_INJECTION, _Sv.HIGH, "compile() code object creation"),
    ("", "__import__"): (_C.CODE_INJECTION, _Sv.HIGH, "__import__() dynamic import"),
    ("os", "remove"): (_C.FILE_SYSTEM_DANGER, _Sv.HIGH, "os.remove() file deletion"),
    ("os", "unlink"): (_C.FILE_SYSTEM_DANGER, _Sv.HIGH, "os.unlink() file deletion"),
    ("shutil", "rmtree"): (
        _C.FILE_SYSTEM_DANGER,
        _Sv.CRITICAL,
        "shutil.rmtree() recursive delete",
    ),
    ("os", "setuid"): (_C.PRIVILEGE_ESCALATION, _Sv.CRITICAL, "os.setuid() privilege change"),
    ("os", "setgid"): (_C.PRIVILEGE_ESCALATION, _Sv.CRITICAL, "os.setgid() privilege change"),
    ("os", "chmod"): (_C.PRIVILEGE_ESCALATION, _Sv.HIGH, "os.chmod() permission change"),
    ("os", "kill"): (_C.PRIVILEGE_ESCALATION, _Sv.HIGH, "os.kill() process signal"),
    ("pickle", "loads"): (_C.DESERIALIZATION, _Sv.CRITICAL, "pickle.loads() unsafe deser"),
    ("pickle", "load"): (_C.DESERIALIZATION, _Sv.CRITICAL, "pickle.load() unsafe deser"),
    ("yaml", "load"): (_C.DESERIALIZATION, _Sv.CRITICAL, "yaml.load() unsafe deser"),
    ("yaml", "unsafe_load"): (_C.DESERIALIZATION, _Sv.CRITICAL, "yaml.unsafe_load()"),
    ("marshal", "loads"): (_C.DESERIALIZATION, _Sv.HIGH, "marshal.loads() deserialization"),
    ("marshal", "load"): (_C.DESERIALIZATION, _Sv.HIGH, "marshal.load() deserialization"),
    ("requests", "post"): (_C.NETWORK_EXFILTRATION, _Sv.HIGH, "requests.post() data exfil"),
    ("requests", "put"): (_C.NETWORK_EXFILTRATION, _Sv.HIGH, "requests.put() data exfil"),
    ("httpx", "post"): (_C.NETWORK_EXFILTRATION, _Sv.HIGH, "httpx.post() data exfil"),
    ("httpx", "put"): (_C.NETWORK_EXFILTRATION, _Sv.HIGH, "httpx.put() data exfil"),
}

# Dangerous import base modules
_DANGEROUS_IMPORTS: dict[str, tuple[Category, Severity, str]] = {
    "ctypes": (_C.PRIVILEGE_ESCALATION, _Sv.HIGH, "ctypes enables arbitrary C calls"),
    "pickle": (_C.DESERIALIZATION, _Sv.CRITICAL, "pickle module -- deserialization risk"),
    "marshal": (_C.DESERIALIZATION, _Sv.HIGH, "marshal module -- deserialization risk"),
    "shelve": (_C.DESERIALIZATION, _Sv.HIGH, "shelve module -- uses pickle internally"),
}

# Fast pre-screen keywords for regex path.
_PRESCREEN: tuple[str, ...] = (
    "os.",
    "subprocess",
    "eval",
    "exec",
    "compile",
    "__import__",
    "shutil",
    "pickle",
    "yaml",
    "marshal",
    "shelve",
    "requests.",
    "httpx.",
    "urllib",
    "socket.",
    "ctypes",
    "chmod",
    "setuid",
    "kill",
    "open(",
    "unlink",
    "rmtree",
    "popen",
    "`",
)

_SEV_ORD: dict[str, int] = {_Sv.LOW: 1, _Sv.MEDIUM: 2, _Sv.HIGH: 3, _Sv.CRITICAL: 4}
_SENS_THR: dict[str, int] = {"low": 1, "medium": 2, "high": 3}

# ---------------------------------------------------------------------------
# AST visitor
# ---------------------------------------------------------------------------


class _DangerousCallVisitor(ast.NodeVisitor):
    """Walk an AST looking for calls to known-dangerous functions."""

    def __init__(self, min_sev: int, allowlist: frozenset[str]) -> None:
        self.findings: list[CodeExecFinding] = []
        self._min = min_sev
        self._al = allowlist

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        key: tuple[str, str] | None = None
        text = ""
        func = node.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            key = (func.value.id, func.attr)
            text = f"{func.value.id}.{func.attr}()"
        elif isinstance(func, ast.Name):
            key = ("", func.id)
            text = f"{func.id}()"
        if key and key in _AST_CALLS:
            cat, sev, desc = _AST_CALLS[key]
            pname = f"ast_{key[0]}_{key[1]}" if key[0] else f"ast_{key[1]}"
            allowed = (
                key[1] in self._al
                or (key[0] and key[0] in self._al)
                or text in self._al
                or pname in self._al
            )
            if not allowed and _SEV_ORD.get(sev, 0) >= self._min:
                self.findings.append(
                    CodeExecFinding(cat, sev, pname, text, getattr(node, "lineno", 0), desc)
                )
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            self._chk_import(alias.name, getattr(node, "lineno", 0))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        if node.module:
            self._chk_import(node.module, getattr(node, "lineno", 0))
        self.generic_visit(node)

    def _chk_import(self, mod: str, ln: int) -> None:
        if mod in self._al:
            return
        base = mod.split(".")[0]
        if base in self._al:
            return
        if base in _DANGEROUS_IMPORTS:
            cat, sev, desc = _DANGEROUS_IMPORTS[base]
            if _SEV_ORD.get(sev, 0) >= self._min:
                self.findings.append(
                    CodeExecFinding(cat, sev, f"ast_import_{base}", f"import {mod}", ln, desc)
                )


# ---------------------------------------------------------------------------
# Main gate
# ---------------------------------------------------------------------------


class CodeExecSafetyGate:
    """Static analysis gate for code about to be executed.

    Combines AST-based analysis (for valid Python) with regex pattern
    matching (for any text, including non-Python snippets).

    Args:
        action: ``"block"`` (default), ``"warn"``, or ``"log"``.
        sensitivity: ``"low"``, ``"medium"`` (default), or ``"high"``.
        allowlist: Pattern/function names to exempt from detection.
    """

    def __init__(
        self,
        *,
        action: str = "block",
        sensitivity: str = "medium",
        allowlist: Sequence[str] | None = None,
    ) -> None:
        self._action = ExecAction(action)
        self._sensitivity = sensitivity
        self._allowlist: frozenset[str] = frozenset(allowlist or ())
        self._min_severity = _SENS_THR.get(sensitivity, 2)
        self._lock = threading.Lock()

    def check(self, code: str) -> CodeExecResult:
        """Check *code* for dangerous patterns (AST + regex)."""
        if not code or not code.strip():
            return CodeExecResult(passed=True)
        findings = self.check_ast(code) + self.check_patterns(code)
        seen: set[tuple[str, int]] = set()
        unique: list[CodeExecFinding] = []
        for f in findings:
            k = (f.pattern_name, f.line_number)
            if k not in seen:
                seen.add(k)
                unique.append(f)
        if not unique:
            return CodeExecResult(passed=True)
        worst = max(unique, key=lambda f: _SEV_ORD.get(f.severity, 0))
        return CodeExecResult(False, tuple(unique), worst.severity, self._action)

    def check_ast(self, code: str) -> list[CodeExecFinding]:
        """AST-based analysis for Python code."""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return []
        v = _DangerousCallVisitor(self._min_severity, self._allowlist)
        v.visit(tree)
        return v.findings

    def check_patterns(self, code: str) -> list[CodeExecFinding]:
        """Regex-based pattern matching for dangerous code."""
        if not self._prescreen(code):
            return []
        findings: list[CodeExecFinding] = []
        offsets = _line_offsets(code)
        for category, patterns in _ALL_REGEX:
            for name, severity, regex, desc in patterns:
                if _SEV_ORD.get(severity, 0) < self._min_severity:
                    continue
                prefixed = f"regex_{name}"
                if name in self._allowlist or prefixed in self._allowlist:
                    continue
                if any(name.startswith(e) or name.startswith(f"{e}_") for e in self._allowlist):
                    continue
                for m in regex.finditer(code):
                    ln = _off2line(m.start(), offsets)
                    findings.append(
                        CodeExecFinding(category, severity, prefixed, m.group(0), ln, desc)
                    )
        return findings

    @staticmethod
    def _prescreen(code: str) -> bool:
        lower = code.lower()
        return any(kw in lower for kw in _PRESCREEN)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _line_offsets(code: str) -> list[int]:
    offsets = [0]
    for i, ch in enumerate(code):
        if ch == "\n":
            offsets.append(i + 1)
    return offsets


def _off2line(offset: int, lo: list[int]) -> int:
    a, b = 0, len(lo) - 1
    while a <= b:
        mid = (a + b) // 2
        if lo[mid] <= offset:
            a = mid + 1
        else:
            b = mid - 1
    return a
