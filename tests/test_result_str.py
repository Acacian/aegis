"""Tests for Result.__str__ representation."""

from __future__ import annotations

from aegis.core.action import Action
from aegis.core.result import Result, ResultStatus


def test_result_str_success():
    """SUCCESS result should show [OK] icon."""
    r = Result(action=Action("read", "salesforce"), status=ResultStatus.SUCCESS)
    assert str(r) == "[OK] read -> salesforce"


def test_result_str_failed():
    """FAILED result should show [FAIL] icon."""
    r = Result(action=Action("write", "db"), status=ResultStatus.FAILED, error="oops")
    assert str(r) == "[FAIL] write -> db"


def test_result_str_blocked():
    """BLOCKED result should show [BLOCK] icon."""
    r = Result(action=Action("delete", "prod"), status=ResultStatus.BLOCKED, error="blocked")
    assert str(r) == "[BLOCK] delete -> prod"


def test_result_str_denied():
    """DENIED result should show [DENY] icon."""
    r = Result(action=Action("write", "crm"), status=ResultStatus.DENIED, error="denied")
    assert str(r) == "[DENY] write -> crm"


def test_result_str_skipped():
    """SKIPPED result should show [SKIP] icon."""
    r = Result(action=Action("read", "api"), status=ResultStatus.SKIPPED, error="skipped")
    assert str(r) == "[SKIP] read -> api"
