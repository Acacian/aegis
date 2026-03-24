"""Pack loader — resolve packs by name or path.

Provides a simple API for loading guardrail packs:

- ``load_pack("pii")`` loads the built-in PII pack.
- ``load_pack("/path/to/custom.yaml")`` loads a pack from a file.
- ``list_builtin_packs()`` returns names of all available built-in packs.
"""

from __future__ import annotations

from pathlib import Path

from aegis.packs.schema import Pack

# Built-in packs are stored in the ``builtin/`` sub-package as YAML files.
_BUILTIN_DIR: Path = Path(__file__).parent / "builtin"


def load_pack(name_or_path: str) -> Pack:
    """Load a pack by built-in name or filesystem path.

    Resolution order:

    1. If *name_or_path* contains a path separator (``/`` or ``\\``) or
       ends with ``.yaml`` / ``.yml``, treat it as a file path.
    2. Otherwise, look up a built-in pack by name.

    Args:
        name_or_path: Either a built-in pack name (e.g. ``"pii"``) or
            a path to a YAML file.

    Raises:
        FileNotFoundError: If the pack file or built-in name does not exist.
    """
    path = Path(name_or_path)

    # Heuristic: if it looks like a file path, load directly.
    if _looks_like_path(name_or_path):
        return Pack.from_yaml(path)

    # Otherwise, resolve as a built-in pack name.
    return _load_builtin(name_or_path)


def list_builtin_packs() -> list[str]:
    """Return the names of all available built-in packs.

    Scans the ``builtin/`` directory for ``.yaml`` and ``.yml`` files
    and returns their stems (e.g. ``"pii"``, ``"injection"``).
    """
    if not _BUILTIN_DIR.is_dir():
        return []
    names: list[str] = []
    for p in sorted(_BUILTIN_DIR.iterdir()):
        if p.suffix in (".yaml", ".yml") and not p.name.startswith("_"):
            names.append(p.stem)
    return names


def _looks_like_path(value: str) -> bool:
    """Determine whether *value* looks like a filesystem path."""
    return "/" in value or "\\" in value or value.endswith(".yaml") or value.endswith(".yml")


def _load_builtin(name: str) -> Pack:
    """Load a built-in pack by name.

    Tries ``<name>.yaml`` then ``<name>.yml`` in the builtin directory.

    Raises:
        FileNotFoundError: If no matching file is found.
    """
    for suffix in (".yaml", ".yml"):
        candidate = _BUILTIN_DIR / f"{name}{suffix}"
        if candidate.exists():
            return Pack.from_yaml(candidate)

    available = list_builtin_packs()
    available_str = ", ".join(available) if available else "(none)"
    raise FileNotFoundError(f"Built-in pack {name!r} not found. Available packs: {available_str}")
