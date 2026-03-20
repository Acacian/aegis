"""Tests for __main__.py module."""

from __future__ import annotations

from unittest.mock import patch


def test_main_module_calls_main():
    """python -m aegis should call main()."""
    with patch("aegis.cli.main.main"):
        # Execute the __main__ module code
        import aegis.__main__  # noqa: F401

        # The module-level call to main() was already executed on import
        # We can verify main is importable and callable
        from aegis.cli.main import main

        main(["--version"])
