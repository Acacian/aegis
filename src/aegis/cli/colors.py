"""ANSI color helpers for CLI output.

Respects the ``NO_COLOR`` environment variable (https://no-color.org/).
When ``NO_COLOR`` is set (any value) or stdout is not a TTY, all color
functions return text unchanged.
"""

from __future__ import annotations

import os
import sys

_RESET = "\033[0m"
_BOLD = "\033[1m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_BRIGHT_RED = "\033[91m"
_CYAN = "\033[36m"


def _color_enabled() -> bool:
    """Return True when color output is allowed."""
    if os.environ.get("NO_COLOR") is not None:
        return False
    if not hasattr(sys.stdout, "isatty"):
        return False
    return sys.stdout.isatty()


# Module-level cache so we don't re-check on every call.
_enabled: bool | None = None


def _is_enabled() -> bool:
    global _enabled  # noqa: PLW0603
    if _enabled is None:
        _enabled = _color_enabled()
    return _enabled


def reset_cache() -> None:
    """Reset the cached color-enabled flag (useful for testing)."""
    global _enabled  # noqa: PLW0603
    _enabled = None


def force_color(enabled: bool) -> None:
    """Force color output on or off (overrides auto-detection)."""
    global _enabled  # noqa: PLW0603
    _enabled = enabled


def _wrap(code: str, text: str) -> str:
    if not _is_enabled():
        return text
    return f"{code}{text}{_RESET}"


def green(text: str) -> str:
    """Wrap *text* in green ANSI codes."""
    return _wrap(_GREEN, text)


def red(text: str) -> str:
    """Wrap *text* in red ANSI codes."""
    return _wrap(_RED, text)


def yellow(text: str) -> str:
    """Wrap *text* in yellow ANSI codes."""
    return _wrap(_YELLOW, text)


def bright_red(text: str) -> str:
    """Wrap *text* in bright-red ANSI codes."""
    return _wrap(_BRIGHT_RED, text)


def bold(text: str) -> str:
    """Wrap *text* in bold ANSI codes."""
    return _wrap(_BOLD, text)


def cyan(text: str) -> str:
    """Wrap *text* in cyan ANSI codes."""
    return _wrap(_CYAN, text)


def risk_color(level: str) -> str:
    """Colorize a risk-level string by severity."""
    upper = level.upper()
    if upper == "LOW":
        return green(level)
    if upper == "MEDIUM":
        return yellow(level)
    if upper == "HIGH":
        return red(level)
    if upper == "CRITICAL":
        return bright_red(level)
    return level


def status_color(status: str) -> str:
    """Colorize a result status string."""
    upper = status.upper()
    if upper in ("SUCCESS", "ALLOWED"):
        return green(status)
    if upper in ("BLOCKED", "FAILED", "DENIED"):
        return red(status)
    return status
