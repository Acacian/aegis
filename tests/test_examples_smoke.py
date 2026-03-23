"""Smoke tests: verify all example scripts are valid Python (no syntax errors)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"


def _example_files() -> list[Path]:
    return sorted(EXAMPLES_DIR.glob("*.py"))


@pytest.mark.parametrize("example", _example_files(), ids=lambda p: p.name)
def test_example_parses(example: Path) -> None:
    """Each example should be valid Python (no syntax errors)."""
    source = example.read_text(encoding="utf-8")
    ast.parse(source, filename=str(example))


@pytest.mark.parametrize("example", _example_files(), ids=lambda p: p.name)
def test_example_has_docstring(example: Path) -> None:
    """Each example should have a module docstring."""
    source = example.read_text(encoding="utf-8")
    tree = ast.parse(source)
    docstring = ast.get_docstring(tree)
    assert docstring, f"{example.name} is missing a module docstring"
