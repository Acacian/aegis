"""Static scanner for ungoverned AI agent tool calls.

Walks Python files, uses ``ast`` to detect patterns that indicate
tool/function calls without Aegis governance wrappers.
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Finding:
    """A single ungoverned tool-call detected by the scanner."""

    file: str
    line: int
    category: str
    detail: str


# ---------------------------------------------------------------------------
# Grade thresholds
# ---------------------------------------------------------------------------

_GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (0, "A"),
    (1, "B"),
    (3, "C"),
    (6, "D"),
    # anything above 6 -> F
]


def _grade(count: int) -> str:
    """Return a letter grade for *count* ungoverned calls."""
    result = "F"
    for threshold, letter in _GRADE_THRESHOLDS:
        if count <= threshold:
            return letter
        result = letter
    return "F" if count > _GRADE_THRESHOLDS[-1][0] else result


# ---------------------------------------------------------------------------
# AST visitors
# ---------------------------------------------------------------------------


class _ToolCallVisitor(ast.NodeVisitor):
    """Walk an AST and collect :class:`Finding` instances."""

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.findings: list[Finding] = []
        # Track imports so we can resolve names later.
        self._imports: dict[str, str] = {}  # alias -> dotted module

    # -- helpers ------------------------------------------------------------

    def _add(self, node: ast.AST, category: str, detail: str) -> None:
        self.findings.append(
            Finding(
                file=self.filepath,
                line=getattr(node, "lineno", 0),
                category=category,
                detail=detail,
            )
        )

    @staticmethod
    def _dotted_name(node: ast.expr) -> str:
        """Best-effort dotted name for an attribute chain."""
        parts: list[str] = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        parts.reverse()
        return ".".join(parts)

    # -- import tracking ----------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            name = alias.asname or alias.name
            self._imports[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        module = node.module or ""
        for alias in node.names:
            name = alias.asname or alias.name
            self._imports[name] = f"{module}.{alias.name}" if module else alias.name
        self.generic_visit(node)

    # -- decorator detection ------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._check_decorators(node)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef  # noqa: N815

    def _check_decorators(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for dec in node.decorator_list:
            # @tool  (LangChain)
            if isinstance(dec, ast.Name) and dec.id == "tool":
                self._add(
                    dec,
                    "LangChain",
                    f'@tool "{node.name}" \u2014 no policy check',
                )
            # @mcp.tool()  (MCP without aegis middleware)
            if isinstance(dec, ast.Call):
                dotted = self._dotted_name(dec.func) if isinstance(dec.func, ast.Attribute) else ""
                if dotted.endswith(".tool"):
                    # Check that the receiver looks like an mcp server
                    root = dotted.split(".")[0]
                    resolved = self._imports.get(root, root)
                    if "mcp" in resolved.lower() or root in ("mcp", "server", "app"):
                        self._add(
                            dec,
                            "MCP",
                            f'@mcp.tool() "{node.name}" \u2014 no aegis middleware',
                        )

    # -- class detection ----------------------------------------------------

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        for base in node.bases:
            base_name = (
                self._dotted_name(base) if isinstance(base, (ast.Attribute, ast.Name)) else ""
            )
            # LangChain BaseTool subclass
            if base_name in ("BaseTool", "langchain_core.tools.BaseTool"):
                # Ignore if it also inherits GovernedTool
                all_bases = {
                    self._dotted_name(b) if isinstance(b, (ast.Attribute, ast.Name)) else ""
                    for b in node.bases
                }
                if "GovernedTool" not in all_bases:
                    self._add(
                        node,
                        "LangChain",
                        f'BaseTool subclass "{node.name}" \u2014 not governed',
                    )
        self.generic_visit(node)

    # -- call detection -----------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        if isinstance(node.func, ast.Attribute):
            dotted = self._dotted_name(node.func)
            self._check_openai(node, dotted)
            self._check_anthropic(node, dotted)
            self._check_subprocess(node, dotted)
            self._check_http(node, dotted)
        elif isinstance(node.func, ast.Name):
            self._check_subprocess_name(node, node.func.id)
        self.generic_visit(node)

    # -- individual pattern matchers ----------------------------------------

    def _check_openai(self, node: ast.Call, dotted: str) -> None:
        # openai.chat.completions.create  or  client.chat.completions.create
        if (
            dotted.endswith("chat.completions.create") or dotted.endswith("completions.create")
        ) and self._has_keyword(node, "tools"):
            self._add(node, "OpenAI", "function call with tools= \u2014 no governance wrapper")

    def _check_anthropic(self, node: ast.Call, dotted: str) -> None:
        # anthropic.messages.create  or  client.messages.create
        if dotted.endswith("messages.create"):
            root = dotted.split(".")[0]
            resolved = self._imports.get(root, root)
            if ("anthropic" in resolved.lower() or root == "client") and self._has_keyword(
                node, "tools"
            ):
                self._add(
                    node,
                    "Anthropic",
                    "messages.create with tools= \u2014 no governance wrapper",
                )

    def _check_subprocess(self, node: ast.Call, dotted: str) -> None:
        dangerous = {
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "os.system",
            "os.popen",
        }
        if dotted in dangerous:
            self._add(node, "subprocess", f"{dotted} \u2014 direct shell execution")
        # os.exec* family
        parts = dotted.split(".")
        if len(parts) == 2 and parts[0] == "os" and parts[1].startswith("exec"):
            self._add(node, "subprocess", f"{dotted} \u2014 direct process exec")

    def _check_subprocess_name(self, node: ast.Call, name: str) -> None:
        """Handle bare ``from subprocess import run; run(...)``."""
        resolved = self._imports.get(name, "")
        bare_dangerous = {
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "os.system",
            "os.popen",
        }
        if resolved in bare_dangerous:
            self._add(node, "subprocess", f"{resolved} \u2014 direct shell execution")
        if resolved.startswith("os.exec"):
            self._add(node, "subprocess", f"{resolved} \u2014 direct process exec")

    def _check_http(self, node: ast.Call, dotted: str) -> None:
        http_posts = {"requests.post", "httpx.post"}
        if dotted in http_posts:
            self._add(node, "HTTP", f"{dotted} \u2014 raw HTTP in agent code")
        # Also match aliased imports: e.g.  import httpx as h; h.post(...)
        parts = dotted.split(".")
        if len(parts) == 2:
            resolved_root = self._imports.get(parts[0], parts[0])
            resolved = f"{resolved_root}.{parts[1]}"
            if resolved in http_posts and dotted not in http_posts:
                self._add(node, "HTTP", f"{resolved} \u2014 raw HTTP in agent code")

    # -- utils --------------------------------------------------------------

    @staticmethod
    def _has_keyword(node: ast.Call, name: str) -> bool:
        return any(kw.arg == name for kw in node.keywords)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_file(filepath: str | Path) -> list[Finding]:
    """Parse a single Python file and return findings."""
    filepath = Path(filepath)
    try:
        source = filepath.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    try:
        tree = ast.parse(source, filename=str(filepath))
    except SyntaxError:
        return []
    visitor = _ToolCallVisitor(str(filepath))
    visitor.visit(tree)
    return visitor.findings


def scan_directory(directory: str | Path) -> tuple[int, list[Finding]]:
    """Recursively scan *directory* for Python files.

    Returns ``(file_count, findings)``.
    """
    directory = Path(directory)
    findings: list[Finding] = []
    file_count = 0
    for py_file in sorted(directory.rglob("*.py")):
        # Skip hidden dirs, venvs, __pycache__, .git
        parts = py_file.relative_to(directory).parts
        if any(p.startswith(".") or p in ("__pycache__", "node_modules") for p in parts):
            continue
        file_count += 1
        findings.extend(scan_file(py_file))
    return file_count, findings


def format_report(
    file_count: int,
    findings: list[Finding],
    *,
    directory: str = ".",
) -> str:
    """Build the human-readable scan report."""
    lines: list[str] = []
    lines.append("Aegis Governance Scan")
    lines.append("=" * 21)
    lines.append(f"Scanned: {file_count} files in {directory}")
    lines.append("")

    if findings:
        lines.append(f"Found {len(findings)} ungoverned tool call(s):")
        for f in findings:
            # Make path relative for readability
            try:
                rel = str(Path(f.file).relative_to(Path(directory).resolve()))
            except ValueError:
                rel = f.file
            lines.append(f"  {rel}:{f.line:<8}{f.category:<14}{f.detail}")
        lines.append("")
        grade = _grade(len(findings))
        lines.append(f"Governance Score: {grade} ({len(findings)} ungoverned call(s))")
    else:
        lines.append("No ungoverned tool calls found.")
        lines.append("")
        lines.append("Governance Score: A (clean)")

    lines.append("")
    lines.append("Fix: pip install agent-aegis")
    lines.append("Docs: https://acacian.github.io/aegis/")
    return "\n".join(lines)


def run_scan(directory: str = ".") -> int:
    """Execute the scan and print the report. Returns exit code."""
    target = Path(directory).resolve()
    if not target.is_dir():
        print(f"Error: not a directory: {target}", file=sys.stderr)
        return 1

    file_count, findings = scan_directory(target)
    report = format_report(file_count, findings, directory=str(target))
    print(report)
    return 1 if findings else 0
