"""Tests for OutputSchemaGuardrail."""

import json

import pytest

from aegis.guardrails.output_schema import (
    OutputSchemaGuardrail,
    SchemaViolation,
    _extract_json,
)

# -- Fixtures ------------------------------------------------------------------

_PERSON_SCHEMA = {
    "type": "object",
    "required": ["name", "age"],
    "properties": {
        "name": {"type": "string"},
        "age": {"type": "integer", "minimum": 0},
    },
    "additionalProperties": False,
}

_NESTED_SCHEMA = {
    "type": "object",
    "required": ["user", "scores"],
    "properties": {
        "user": {
            "type": "object",
            "required": ["id", "email"],
            "properties": {
                "id": {"type": "integer"},
                "email": {"type": "string"},
            },
        },
        "scores": {
            "type": "array",
            "items": {"type": "number"},
        },
    },
}


# -- JSON extraction -----------------------------------------------------------


class TestExtractJSON:
    def test_plain_json(self):
        assert _extract_json('{"a": 1}') == '{"a": 1}'

    def test_strips_markdown_json_fence(self):
        text = '```json\n{"a": 1}\n```'
        assert _extract_json(text) == '{"a": 1}'

    def test_strips_markdown_plain_fence(self):
        text = '```\n{"a": 1}\n```'
        assert _extract_json(text) == '{"a": 1}'

    def test_strips_whitespace(self):
        assert _extract_json('  {"a": 1}  ') == '{"a": 1}'


# -- Valid outputs -------------------------------------------------------------


class TestOutputSchemaValid:
    def test_valid_person(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA)
        result = g.check('{"name": "Alice", "age": 30}')
        assert result.passed is True
        assert result.action == "allowed"
        assert result.parsed_output == {"name": "Alice", "age": 30}

    def test_valid_nested(self):
        g = OutputSchemaGuardrail(schema=_NESTED_SCHEMA)
        data = {"user": {"id": 1, "email": "a@b.com"}, "scores": [9.5, 8.0]}
        result = g.check(json.dumps(data))
        assert result.passed is True
        assert result.parsed_output == data

    def test_valid_with_markdown_fence(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA)
        text = '```json\n{"name": "Bob", "age": 25}\n```'
        result = g.check(text)
        assert result.passed is True

    def test_valid_empty_violations(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA)
        result = g.check('{"name": "X", "age": 1}')
        assert result.violations == []
        assert result.repair_hint is None


# -- Invalid outputs -----------------------------------------------------------


class TestOutputSchemaInvalid:
    def test_invalid_json(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA)
        result = g.check("not json at all")
        assert result.passed is False
        assert "Invalid JSON" in result.details
        assert result.violations[0].validator == "json_parse"
        assert result.repair_hint is not None

    def test_wrong_type(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA)
        result = g.check('{"name": "Alice", "age": "thirty"}')
        assert result.passed is False
        assert any(v.validator == "type" for v in result.violations)

    def test_missing_required(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA)
        result = g.check('{"name": "Alice"}')
        assert result.passed is False
        assert any(v.validator == "required" for v in result.violations)

    def test_additional_properties(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA)
        result = g.check('{"name": "Alice", "age": 30, "extra": true}')
        assert result.passed is False
        assert any(v.validator == "additionalProperties" for v in result.violations)

    def test_minimum_violation(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA)
        result = g.check('{"name": "Alice", "age": -5}')
        assert result.passed is False
        assert any(v.validator == "minimum" for v in result.violations)

    def test_nested_violation(self):
        g = OutputSchemaGuardrail(schema=_NESTED_SCHEMA)
        data = {"user": {"id": "not_int", "email": "a@b.com"}, "scores": [1]}
        result = g.check(json.dumps(data))
        assert result.passed is False
        assert any("user" in v.path for v in result.violations)

    def test_array_item_violation(self):
        g = OutputSchemaGuardrail(schema=_NESTED_SCHEMA)
        data = {"user": {"id": 1, "email": "a@b.com"}, "scores": [1, "bad"]}
        result = g.check(json.dumps(data))
        assert result.passed is False


# -- Actions -------------------------------------------------------------------


class TestOutputSchemaActions:
    def test_block_action(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA, action="block")
        result = g.check('{"name": 123}')
        assert result.passed is False
        assert result.action == "blocked"

    def test_warn_action(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA, action="warn")
        result = g.check('{"name": 123}')
        assert result.passed is False
        assert result.action == "warned"

    def test_log_action(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA, action="log")
        result = g.check('{"name": 123}')
        assert result.passed is False
        assert result.action == "allowed"

    def test_invalid_action_raises(self):
        with pytest.raises(ValueError, match="Invalid action"):
            OutputSchemaGuardrail(schema=_PERSON_SCHEMA, action="mask")

    def test_clean_result_action(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA)
        result = g.check('{"name": "X", "age": 1}')
        assert result.action == "allowed"


# -- Type coercion -------------------------------------------------------------


class TestOutputSchemaCoercion:
    def test_coerce_string_to_int(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA, coerce_types=True)
        result = g.check('{"name": "Alice", "age": "30"}')
        assert result.passed is True
        assert result.parsed_output["age"] == 30

    def test_coerce_string_to_float(self):
        schema = {
            "type": "object",
            "properties": {"score": {"type": "number"}},
        }
        g = OutputSchemaGuardrail(schema=schema, coerce_types=True)
        result = g.check('{"score": "9.5"}')
        assert result.passed is True
        assert result.parsed_output["score"] == 9.5

    def test_coerce_string_to_bool(self):
        schema = {
            "type": "object",
            "properties": {"active": {"type": "boolean"}},
        }
        g = OutputSchemaGuardrail(schema=schema, coerce_types=True)
        result = g.check('{"active": "true"}')
        assert result.passed is True
        assert result.parsed_output["active"] is True

    def test_coerce_false_string(self):
        schema = {
            "type": "object",
            "properties": {"active": {"type": "boolean"}},
        }
        g = OutputSchemaGuardrail(schema=schema, coerce_types=True)
        result = g.check('{"active": "false"}')
        assert result.passed is True
        assert result.parsed_output["active"] is False

    def test_coerce_number_to_string(self):
        schema = {
            "type": "object",
            "properties": {"label": {"type": "string"}},
        }
        g = OutputSchemaGuardrail(schema=schema, coerce_types=True)
        result = g.check('{"label": 42}')
        assert result.passed is True
        assert result.parsed_output["label"] == "42"

    def test_coerce_string_to_array(self):
        schema = {
            "type": "object",
            "properties": {"tags": {"type": "array", "items": {"type": "string"}}},
        }
        g = OutputSchemaGuardrail(schema=schema, coerce_types=True)
        data = {"tags": '["a", "b"]'}
        result = g.check(json.dumps(data))
        assert result.passed is True
        assert result.parsed_output["tags"] == ["a", "b"]

    def test_no_coerce_by_default(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA)
        result = g.check('{"name": "Alice", "age": "30"}')
        assert result.passed is False  # "30" is string, not int


# -- Pydantic integration -----------------------------------------------------


class TestOutputSchemaPydantic:
    def test_pydantic_v2_schema(self):
        try:
            from pydantic import BaseModel
        except ImportError:
            pytest.skip("pydantic not installed")

        class Person(BaseModel):
            name: str
            age: int

        g = OutputSchemaGuardrail(pydantic_model=Person)
        result = g.check('{"name": "Alice", "age": 30}')
        assert result.passed is True

    def test_pydantic_v2_invalid(self):
        try:
            from pydantic import BaseModel
        except ImportError:
            pytest.skip("pydantic not installed")

        class Person(BaseModel):
            name: str
            age: int

        g = OutputSchemaGuardrail(pydantic_model=Person)
        result = g.check('{"name": "Alice", "age": "not_int"}')
        assert result.passed is False

    def test_no_schema_or_model_raises(self):
        with pytest.raises(ValueError, match="Either 'schema' or 'pydantic_model'"):
            OutputSchemaGuardrail()

    def test_bad_pydantic_model_raises(self):
        with pytest.raises(ValueError, match="does not look like a Pydantic"):
            OutputSchemaGuardrail(pydantic_model=str)


# -- Repair hints --------------------------------------------------------------


class TestOutputSchemaRepairHint:
    def test_repair_hint_on_failure(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA)
        result = g.check('{"name": 123}')
        assert result.repair_hint is not None
        assert "fix" in result.repair_hint.lower() or "schema" in result.repair_hint.lower()

    def test_repair_hint_for_json_error(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA)
        result = g.check("not json")
        assert result.repair_hint is not None
        assert "JSON" in result.repair_hint

    def test_no_repair_hint_on_success(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA)
        result = g.check('{"name": "X", "age": 1}')
        assert result.repair_hint is None

    def test_repair_hint_limits_violations(self):
        """Repair hint should cap at 5 violations."""
        schema = {
            "type": "object",
            "required": ["a", "b", "c", "d", "e", "f", "g"],
            "properties": {
                "a": {"type": "string"},
                "b": {"type": "string"},
                "c": {"type": "string"},
                "d": {"type": "string"},
                "e": {"type": "string"},
                "f": {"type": "string"},
                "g": {"type": "string"},
            },
        }
        g = OutputSchemaGuardrail(schema=schema)
        result = g.check("{}")
        assert result.repair_hint is not None
        assert "more error" in result.repair_hint


# -- Result structure ----------------------------------------------------------


class TestOutputSchemaResultStructure:
    def test_violation_fields(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA)
        result = g.check('{"name": 123, "age": "bad"}')
        assert len(result.violations) >= 1
        v = result.violations[0]
        assert isinstance(v, SchemaViolation)
        assert v.path
        assert v.message
        assert v.validator
        assert v.schema_path

    def test_severity_setting(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA, severity="critical")
        result = g.check('{"name": 123}')
        assert result.severity == "critical"

    def test_default_severity_is_high(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA)
        result = g.check('{"name": "X", "age": 1}')
        assert result.severity == "high"

    def test_details_empty_on_pass(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA)
        result = g.check('{"name": "X", "age": 1}')
        assert result.details == ""

    def test_details_nonempty_on_fail(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA)
        result = g.check('{"name": 123}')
        assert "Schema validation failed" in result.details


# -- validate() vs check() alias ----------------------------------------------


class TestOutputSchemaAlias:
    def test_check_and_validate_same(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA)
        content = '{"name": "Alice", "age": 30}'
        r1 = g.check(content)
        r2 = g.validate(content)
        assert r1.passed == r2.passed
        assert r1.action == r2.action


# -- Edge cases ----------------------------------------------------------------


class TestOutputSchemaEdgeCases:
    def test_empty_string(self):
        g = OutputSchemaGuardrail(schema=_PERSON_SCHEMA)
        result = g.check("")
        assert result.passed is False
        assert result.violations[0].validator == "json_parse"

    def test_null_json(self):
        g = OutputSchemaGuardrail(
            schema={"type": "object", "properties": {}},
        )
        result = g.check("null")
        assert result.passed is False

    def test_array_root(self):
        schema = {"type": "array", "items": {"type": "integer"}}
        g = OutputSchemaGuardrail(schema=schema)
        result = g.check("[1, 2, 3]")
        assert result.passed is True
        assert result.parsed_output == [1, 2, 3]

    def test_array_root_invalid(self):
        schema = {"type": "array", "items": {"type": "integer"}}
        g = OutputSchemaGuardrail(schema=schema)
        result = g.check('[1, "two", 3]')
        assert result.passed is False

    def test_enum_validation(self):
        schema = {
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": ["active", "inactive"]},
            },
        }
        g = OutputSchemaGuardrail(schema=schema)
        result = g.check('{"status": "active"}')
        assert result.passed is True

        result = g.check('{"status": "deleted"}')
        assert result.passed is False

    def test_pattern_validation(self):
        schema = {
            "type": "object",
            "properties": {
                "email": {"type": "string", "pattern": "^[^@]+@[^@]+$"},
            },
        }
        g = OutputSchemaGuardrail(schema=schema)
        result = g.check('{"email": "user@example.com"}')
        assert result.passed is True

        result = g.check('{"email": "not-an-email"}')
        assert result.passed is False
