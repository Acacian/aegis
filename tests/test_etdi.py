"""Tests for aegis.core.etdi -- Enhanced Tool Definition Interface.

Reference: arXiv:2506.01333
"""

from __future__ import annotations

import threading

import pytest

from aegis.core.etdi import (
    ETDIVerifier,
    ETDIViolation,
    Permission,
    ToolDefinitionRecord,
    VersionPin,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_verifier(**kwargs: object) -> ETDIVerifier:
    return ETDIVerifier(**kwargs)  # type: ignore[arg-type]


def _register_tool(
    v: ETDIVerifier,
    name: str = "read_file",
    version: str = "1.0.0",
    schema: dict | None = None,
    permissions: set[str] | None = None,
) -> ToolDefinitionRecord:
    return v.register(
        name,
        version,
        schema or {"type": "object"},
        permissions or {"read", "fs"},
    )


# ---------------------------------------------------------------------------
# ToolDefinitionRecord frozen dataclass
# ---------------------------------------------------------------------------


class TestToolDefinitionRecord:
    def test_creation(self) -> None:
        rec = ToolDefinitionRecord(
            "tid", "read_file", "1.0", "hash", frozenset({Permission.READ}), 1000.0
        )
        assert rec.tool_id == "tid"
        assert rec.name == "read_file"
        assert Permission.READ in rec.permissions

    def test_frozen(self) -> None:
        rec = ToolDefinitionRecord("tid", "read_file", "1.0", "hash", frozenset(), 1000.0)
        with pytest.raises(AttributeError):
            rec.name = "other"  # type: ignore[misc]

    def test_default_deprecated_at(self) -> None:
        rec = ToolDefinitionRecord("tid", "name", "1.0", "h", frozenset(), 0.0)
        assert rec.deprecated_at == 0.0


# ---------------------------------------------------------------------------
# VersionPin frozen dataclass
# ---------------------------------------------------------------------------


class TestVersionPin:
    def test_creation(self) -> None:
        pin = VersionPin("tid", "1.0.0", "abc123", "strict")
        assert pin.tool_id == "tid"
        assert pin.pinned_version == "1.0.0"
        assert pin.policy == "strict"

    def test_frozen(self) -> None:
        pin = VersionPin("tid", "1.0.0", "abc", "strict")
        with pytest.raises(AttributeError):
            pin.tool_id = "x"  # type: ignore[misc]

    def test_default_policy(self) -> None:
        pin = VersionPin("tid", "1.0.0", "abc")
        assert pin.policy == "strict"


# ---------------------------------------------------------------------------
# ETDIViolation frozen dataclass
# ---------------------------------------------------------------------------


class TestETDIViolation:
    def test_creation(self) -> None:
        v = ETDIViolation("tid", "hash_mismatch", "description")
        assert v.tool_id == "tid"
        assert v.violation_type == "hash_mismatch"

    def test_frozen(self) -> None:
        v = ETDIViolation("tid", "type", "desc")
        with pytest.raises(AttributeError):
            v.tool_id = "x"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_register_returns_record(self) -> None:
        v = _make_verifier()
        rec = _register_tool(v)
        assert rec.name == "read_file"
        assert rec.version == "1.0.0"
        assert Permission.READ in rec.permissions
        assert Permission.FS in rec.permissions

    def test_register_custom_id(self) -> None:
        v = _make_verifier()
        rec = v.register("tool", "1.0", tool_id="custom::tool")
        assert rec.tool_id == "custom::tool"

    def test_register_no_permissions(self) -> None:
        v = _make_verifier()
        rec = v.register("tool", "1.0")
        assert rec.permissions == frozenset()

    def test_list_tools(self) -> None:
        v = _make_verifier()
        v.register("t1", "1.0")
        v.register("t2", "2.0")
        tools = v.list_tools()
        assert len(tools) == 2

    def test_get_record(self) -> None:
        v = _make_verifier()
        _register_tool(v)
        rec = v.get_record("read_file")
        assert rec is not None
        assert rec.name == "read_file"

    def test_get_record_missing(self) -> None:
        v = _make_verifier()
        assert v.get_record("nonexistent") is None


# ---------------------------------------------------------------------------
# Version pinning
# ---------------------------------------------------------------------------


class TestVersionPinning:
    def test_pin_version(self) -> None:
        v = _make_verifier()
        _register_tool(v)
        result = v.pin_version("read_file")
        assert isinstance(result, VersionPin)
        assert result.pinned_version == "1.0.0"

    def test_pin_unknown_tool(self) -> None:
        v = _make_verifier()
        result = v.pin_version("ghost")
        assert isinstance(result, ETDIViolation)
        assert result.violation_type == "unregistered_tool"

    def test_is_pinned(self) -> None:
        v = _make_verifier()
        _register_tool(v)
        assert not v.is_pinned("read_file")
        v.pin_version("read_file")
        assert v.is_pinned("read_file")

    def test_pin_policy_override(self) -> None:
        v = _make_verifier()
        _register_tool(v)
        pin = v.pin_version("read_file", policy="warn")
        assert isinstance(pin, VersionPin)
        assert pin.policy == "warn"

    def test_list_pins(self) -> None:
        v = _make_verifier()
        _register_tool(v, name="t1")
        _register_tool(v, name="t2")
        v.pin_version("t1")
        v.pin_version("t2")
        pins = v.list_pins()
        assert len(pins) == 2

    def test_get_pin(self) -> None:
        v = _make_verifier()
        _register_tool(v)
        v.pin_version("read_file")
        pin = v.get_pin("read_file")
        assert pin is not None
        assert pin.pinned_version == "1.0.0"

    def test_get_pin_missing(self) -> None:
        v = _make_verifier()
        assert v.get_pin("x") is None


# ---------------------------------------------------------------------------
# Version checking (rug-pull detection)
# ---------------------------------------------------------------------------


class TestVersionChecking:
    def test_check_clean(self) -> None:
        v = _make_verifier()
        schema = {"type": "object"}
        _register_tool(v, schema=schema)
        v.pin_version("read_file")
        assert v.check_version("read_file", schema) is None

    def test_check_hash_mismatch(self) -> None:
        v = _make_verifier()
        _register_tool(v, schema={"type": "object"})
        v.pin_version("read_file")
        violation = v.check_version("read_file", {"type": "string"})
        assert violation is not None
        assert violation.violation_type == "hash_mismatch"

    def test_check_version_mismatch(self) -> None:
        v = _make_verifier()
        _register_tool(v)
        v.pin_version("read_file")
        violation = v.check_version("read_file", current_version="2.0.0")
        assert violation is not None
        assert violation.violation_type == "version_mismatch"

    def test_check_not_pinned_returns_none(self) -> None:
        v = _make_verifier()
        _register_tool(v)
        assert v.check_version("read_file", {"type": "string"}) is None

    def test_check_no_schema_no_version(self) -> None:
        v = _make_verifier()
        _register_tool(v)
        v.pin_version("read_file")
        assert v.check_version("read_file") is None


# ---------------------------------------------------------------------------
# Permission checking
# ---------------------------------------------------------------------------


class TestPermissionChecking:
    def test_within_scope(self) -> None:
        v = _make_verifier()
        _register_tool(v, permissions={"read", "fs"})
        assert v.check_permissions("read_file", {"read"}) is None

    def test_exact_scope(self) -> None:
        v = _make_verifier()
        _register_tool(v, permissions={"read", "fs"})
        assert v.check_permissions("read_file", {"read", "fs"}) is None

    def test_escalation_detected(self) -> None:
        v = _make_verifier()
        _register_tool(v, permissions={"read"})
        violation = v.check_permissions("read_file", {"read", "write", "exec"})
        assert violation is not None
        assert violation.violation_type == "permission_escalation"
        assert "write" in violation.description
        assert "exec" in violation.description

    def test_unregistered_tool(self) -> None:
        v = _make_verifier()
        violation = v.check_permissions("ghost", {"read"})
        assert violation is not None
        assert violation.violation_type == "unregistered_tool"

    def test_empty_requested(self) -> None:
        v = _make_verifier()
        _register_tool(v, permissions={"read"})
        assert v.check_permissions("read_file", set()) is None


# ---------------------------------------------------------------------------
# Deprecation
# ---------------------------------------------------------------------------


class TestDeprecation:
    def test_deprecate_tool(self) -> None:
        v = _make_verifier()
        _register_tool(v)
        result = v.deprecate("read_file")
        assert result is None
        assert v.is_deprecated("read_file")

    def test_deprecate_unknown(self) -> None:
        v = _make_verifier()
        result = v.deprecate("ghost")
        assert isinstance(result, ETDIViolation)

    def test_check_deprecated(self) -> None:
        v = _make_verifier()
        _register_tool(v)
        v.deprecate("read_file")
        violation = v.check_deprecated("read_file")
        assert violation is not None
        assert violation.violation_type == "deprecated_tool"

    def test_check_not_deprecated(self) -> None:
        v = _make_verifier()
        _register_tool(v)
        assert v.check_deprecated("read_file") is None

    def test_check_deprecated_unregistered(self) -> None:
        v = _make_verifier()
        violation = v.check_deprecated("ghost")
        assert violation is not None
        assert violation.violation_type == "unregistered_tool"


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_registration(self) -> None:
        v = _make_verifier()
        errors: list[str] = []

        def worker(i: int) -> None:
            try:
                v.register(f"tool_{i}", "1.0", permissions={"read"})
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert len(v.list_tools()) == 20

    def test_concurrent_pin_and_check(self) -> None:
        v = _make_verifier()
        schema = {"type": "object"}
        for i in range(10):
            v.register(f"t{i}", "1.0", schema, {"read"})
            v.pin_version(f"t{i}")

        errors: list[str] = []

        def check_worker(i: int) -> None:
            result = v.check_version(f"t{i}", schema)
            if result is not None:
                errors.append(f"Unexpected violation for t{i}")

        threads = [threading.Thread(target=check_worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
