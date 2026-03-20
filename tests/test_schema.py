"""Tests for the policy JSON Schema."""

from __future__ import annotations

import json

from aegis.core.schema import POLICY_SCHEMA, get_schema_json


def test_schema_is_valid_json():
    """Schema should be serializable to JSON."""
    result = get_schema_json()
    parsed = json.loads(result)
    assert parsed["title"] == "Aegis Policy"


def test_schema_has_required_fields():
    """Schema should require version and rules."""
    assert "version" in POLICY_SCHEMA["required"]
    assert "rules" in POLICY_SCHEMA["required"]


def test_schema_risk_levels():
    """Schema should define all 4 risk levels."""
    rule_props = POLICY_SCHEMA["properties"]["rules"]["items"]["properties"]
    assert set(rule_props["risk_level"]["enum"]) == {"low", "medium", "high", "critical"}


def test_schema_approval_modes():
    """Schema should define all 3 approval modes."""
    rule_props = POLICY_SCHEMA["properties"]["rules"]["items"]["properties"]
    assert set(rule_props["approval"]["enum"]) == {"auto", "approve", "block"}


def test_schema_version_enum():
    """Schema should only allow version '1'."""
    assert POLICY_SCHEMA["properties"]["version"]["enum"] == ["1"]


def test_cli_schema_command(capsys):
    """aegis schema should output valid JSON Schema."""
    from aegis.cli.main import main

    main(["schema"])
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["title"] == "Aegis Policy"
    assert "rules" in parsed["properties"]
