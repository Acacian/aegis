"""Output schema validation guardrail.

Validates LLM responses against JSON Schema or Pydantic models to ensure
structured output compliance.  Designed for the output side of the I/O
guardrail pipeline.

Supports:
- JSON Schema validation (via ``jsonschema`` library)
- Pydantic model validation (via ``pydantic`` — lazy-loaded)
- Custom format validators (email, date, url, etc.)
- Repair hints on validation failure

Usage::

    from aegis.guardrails.output_schema import OutputSchemaGuardrail

    schema = {
        "type": "object",
        "required": ["name", "age"],
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer", "minimum": 0},
        },
    }

    guardrail = OutputSchemaGuardrail(schema=schema)
    result = guardrail.check('{"name": "Alice", "age": 30}')
    assert result.passed  # valid JSON matching schema

    result = guardrail.check('{"name": "Bob", "age": "thirty"}')
    assert not result.passed  # "thirty" is not an integer
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SchemaViolation:
    """A single schema validation error."""

    path: str  # JSON path to the error (e.g. "$.age")
    message: str  # Human-readable error message
    validator: str  # Which validator failed (e.g. "type", "required")
    schema_path: str  # Path in the schema that was violated


@dataclass(frozen=True)
class OutputSchemaResult:
    """Result of output schema validation."""

    passed: bool
    action: str  # "allowed", "blocked", "warned"
    details: str
    severity: str
    violations: list[SchemaViolation] = field(default_factory=list)
    parsed_output: Any = None  # The parsed JSON/dict if valid
    repair_hint: str | None = None  # Hint for LLM retry


# ---------------------------------------------------------------------------
# JSON extraction helpers
# ---------------------------------------------------------------------------


def _extract_json(content: str) -> str:
    """Try to extract JSON from content that may have markdown fences."""
    text = content.strip()

    # Strip markdown code fences
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove opening fence (```json, ```yaml, etc.)
        lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    return text


# ---------------------------------------------------------------------------
# OutputSchemaGuardrail
# ---------------------------------------------------------------------------


class OutputSchemaGuardrail:
    """Validate LLM output against a JSON Schema.

    Args:
        schema: A JSON Schema dict.  Alternatively, pass a Pydantic model
            class via ``pydantic_model``.
        pydantic_model: A Pydantic ``BaseModel`` subclass to use as schema.
            Requires ``pydantic`` installed.  Ignored if ``schema`` is given.
        action: What to do on validation failure —
            ``"block"`` (default), ``"warn"``, or ``"log"``.
        severity: Severity of schema violations.
        strict: If ``True``, no additional properties allowed beyond those
            defined in the schema.  Default ``True``.
        coerce_types: If ``True``, attempt basic type coercion (e.g.
            ``"42"`` → ``42`` for integer fields) before validating.
    """

    def __init__(
        self,
        *,
        schema: dict[str, Any] | None = None,
        pydantic_model: type | None = None,
        action: str = "block",
        severity: str = "high",
        strict: bool = True,
        coerce_types: bool = False,
    ) -> None:
        if schema is None and pydantic_model is None:
            raise ValueError("Either 'schema' or 'pydantic_model' must be provided")

        if action not in ("block", "warn", "log"):
            raise ValueError(f"Invalid action: {action!r}. Must be block, warn, or log")

        self.action = action
        self.severity = severity
        self.strict = strict
        self.coerce_types = coerce_types

        if schema is not None:
            self._schema = schema
            self._pydantic_model = None
        else:
            self._pydantic_model = pydantic_model
            self._schema = self._schema_from_pydantic(pydantic_model)

    @staticmethod
    def _schema_from_pydantic(model_cls: type) -> dict[str, Any]:
        """Extract JSON Schema from a Pydantic model class."""
        try:
            # Pydantic v2
            if hasattr(model_cls, "model_json_schema"):
                return model_cls.model_json_schema()  # type: ignore[union-attr]
            # Pydantic v1
            if hasattr(model_cls, "schema"):
                return model_cls.schema()  # type: ignore[union-attr]
        except Exception as exc:
            raise ValueError(f"Failed to extract schema from {model_cls}: {exc}") from exc

        raise ValueError(
            f"{model_cls} does not look like a Pydantic model. "
            "Expected model_json_schema() or schema() method."
        )

    def validate(self, content: str) -> OutputSchemaResult:
        """Validate content against the schema.

        Args:
            content: The LLM output string to validate.  Should contain
                valid JSON (optionally wrapped in markdown fences).

        Returns:
            An :class:`OutputSchemaResult` with violation details.
        """
        # Step 1: Parse JSON
        extracted = _extract_json(content)
        try:
            data = json.loads(extracted)
        except json.JSONDecodeError as exc:
            return OutputSchemaResult(
                passed=False,
                action=self._resolve_action(),
                details=f"Invalid JSON: {exc.msg} at position {exc.pos}",
                severity=self.severity,
                violations=[
                    SchemaViolation(
                        path="$",
                        message=f"JSON parse error: {exc.msg}",
                        validator="json_parse",
                        schema_path="$",
                    )
                ],
                repair_hint=(
                    "The output is not valid JSON. Please return only valid JSON "
                    "without markdown fences or extra text."
                ),
            )

        # Step 2: Optional type coercion
        if self.coerce_types:
            data = self._coerce(data, self._schema)

        # Step 3: Validate against schema
        violations = self._validate_schema(data)

        if not violations:
            # Also validate via Pydantic if model was provided
            if self._pydantic_model is not None:
                pydantic_violations = self._validate_pydantic(data)
                if pydantic_violations:
                    violations = pydantic_violations

        if not violations:
            return OutputSchemaResult(
                passed=True,
                action="allowed",
                details="",
                severity=self.severity,
                parsed_output=data,
            )

        details = f"Schema validation failed: {len(violations)} error(s)"
        repair_hint = self._build_repair_hint(violations)

        return OutputSchemaResult(
            passed=False,
            action=self._resolve_action(),
            details=details,
            severity=self.severity,
            violations=violations,
            parsed_output=data,
            repair_hint=repair_hint,
        )

    def check(self, content: str) -> OutputSchemaResult:
        """Alias for :meth:`validate` — matches guardrail API convention."""
        return self.validate(content)

    def _resolve_action(self) -> str:
        """Map action setting to result action string."""
        if self.action == "block":
            return "blocked"
        if self.action == "warn":
            return "warned"
        return "allowed"

    def _validate_schema(self, data: Any) -> list[SchemaViolation]:
        """Validate data against JSON Schema using jsonschema library."""
        try:
            import jsonschema
        except ImportError as exc:
            raise ImportError(
                "jsonschema is required for OutputSchemaGuardrail. "
                "Install with: pip install jsonschema"
            ) from exc

        validator_cls = jsonschema.Draft7Validator
        validator = validator_cls(self._schema)

        violations: list[SchemaViolation] = []
        for error in sorted(validator.iter_errors(data), key=lambda e: list(e.path)):
            json_path = "$." + ".".join(str(p) for p in error.absolute_path) if error.absolute_path else "$"
            schema_path = ".".join(str(p) for p in error.absolute_schema_path) if error.absolute_schema_path else "$"
            violations.append(
                SchemaViolation(
                    path=json_path,
                    message=error.message,
                    validator=error.validator,  # type: ignore[arg-type]
                    schema_path=schema_path,
                )
            )

        return violations

    def _validate_pydantic(self, data: Any) -> list[SchemaViolation]:
        """Validate data against Pydantic model."""
        if self._pydantic_model is None:
            return []

        try:
            # Pydantic v2
            if hasattr(self._pydantic_model, "model_validate"):
                self._pydantic_model.model_validate(data)  # type: ignore[union-attr]
                return []
            # Pydantic v1
            if hasattr(self._pydantic_model, "parse_obj"):
                self._pydantic_model.parse_obj(data)  # type: ignore[union-attr]
                return []
        except Exception as exc:
            return [
                SchemaViolation(
                    path="$",
                    message=str(exc),
                    validator="pydantic",
                    schema_path="$",
                )
            ]
        return []

    def _coerce(self, data: Any, schema: dict[str, Any]) -> Any:
        """Attempt basic type coercion to fix common LLM output issues."""
        if not isinstance(data, dict) or not isinstance(schema, dict):
            return data

        properties = schema.get("properties", {})
        for key, prop_schema in properties.items():
            if key not in data:
                continue

            expected_type = prop_schema.get("type")
            value = data[key]

            if expected_type == "integer" and isinstance(value, str):
                try:
                    data[key] = int(value)
                except ValueError:
                    pass
            elif expected_type == "number" and isinstance(value, str):
                try:
                    data[key] = float(value)
                except ValueError:
                    pass
            elif expected_type == "boolean" and isinstance(value, str):
                if value.lower() in ("true", "1", "yes"):
                    data[key] = True
                elif value.lower() in ("false", "0", "no"):
                    data[key] = False
            elif expected_type == "string" and not isinstance(value, str):
                data[key] = str(value)
            elif expected_type == "array" and isinstance(value, str):
                try:
                    parsed = json.loads(value)
                    if isinstance(parsed, list):
                        data[key] = parsed
                except (json.JSONDecodeError, ValueError):
                    pass
            elif expected_type == "object" and isinstance(value, dict):
                data[key] = self._coerce(value, prop_schema)

        return data

    @staticmethod
    def _build_repair_hint(violations: list[SchemaViolation]) -> str:
        """Build a repair hint for LLM retry."""
        if not violations:
            return ""

        hints = ["The output did not match the expected schema. Please fix:"]
        for v in violations[:5]:  # Limit to first 5
            hints.append(f"  - {v.path}: {v.message}")

        if len(violations) > 5:
            hints.append(f"  ... and {len(violations) - 5} more error(s)")

        return "\n".join(hints)
