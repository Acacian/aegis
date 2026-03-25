"""JSON Schema for Aegis policy files.

Provides a schema that editors and CI pipelines can use to validate
policy YAML files before loading.

Usage::

    from aegis.core.schema import POLICY_SCHEMA
    import jsonschema
    jsonschema.validate(policy_dict, POLICY_SCHEMA)

Or via CLI::

    aegis schema                # Print the JSON Schema
    aegis validate policy.yaml  # Validate a policy file
"""

from __future__ import annotations

import json

POLICY_SCHEMA: dict[str, object] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://github.com/Acacian/aegis/blob/main/policy.schema.json",
    "title": "Aegis Policy",
    "description": "Schema for Aegis policy YAML/JSON files.",
    "type": "object",
    "required": ["version", "rules"],
    "properties": {
        "version": {
            "type": "string",
            "description": "Policy format version.",
            "enum": ["1", "2"],
        },
        "defaults": {
            "type": "object",
            "description": "Default risk level and approval mode when no rule matches.",
            "properties": {
                "risk_level": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                    "default": "medium",
                },
                "approval": {
                    "type": "string",
                    "enum": ["auto", "approve", "block"],
                    "default": "approve",
                },
            },
            "additionalProperties": False,
        },
        "rules": {
            "type": "array",
            "description": "Ordered list of policy rules. First match wins.",
            "items": {
                "type": "object",
                "required": ["match"],
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Human-readable rule name.",
                    },
                    "match": {
                        "type": "object",
                        "description": "Glob patterns to match actions.",
                        "properties": {
                            "type": {
                                "type": "string",
                                "description": (
                                    "Glob pattern for action type (e.g. 'read', 'delete*')."
                                ),
                                "default": "*",
                            },
                            "target": {
                                "type": "string",
                                "description": (
                                    "Glob pattern for action target (e.g. 'salesforce', '*')."
                                ),
                                "default": "*",
                            },
                        },
                        "additionalProperties": False,
                    },
                    "risk_level": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"],
                        "default": "medium",
                    },
                    "approval": {
                        "type": "string",
                        "enum": ["auto", "approve", "block"],
                        "default": "approve",
                    },
                    "conditions": {
                        "type": "object",
                        "description": (
                            "Optional conditions for time-based or param-based matching. "
                            "Keys: time_after, time_before, weekdays, "
                            "param_eq, param_gt, param_lt, param_gte, param_lte, "
                            "param_contains, param_matches."
                        ),
                    },
                },
                "additionalProperties": False,
            },
        },
        "plan_rules": {
            "type": "object",
            "description": "Plan-level governance rules for sequence and cumulative risk.",
            "properties": {
                "sequence_patterns": {
                    "type": "array",
                    "description": "Forbidden or flagged action sequences.",
                    "items": {
                        "type": "object",
                        "required": ["name", "steps"],
                        "properties": {
                            "name": {"type": "string"},
                            "steps": {
                                "type": "array",
                                "items": {"type": "string"},
                                "minItems": 2,
                                "description": "Ordered glob patterns forming the sequence.",
                            },
                            "approval": {
                                "type": "string",
                                "enum": ["auto", "approve", "block"],
                                "default": "block",
                            },
                            "risk_level": {
                                "type": "string",
                                "enum": ["low", "medium", "high", "critical"],
                                "default": "critical",
                            },
                            "description": {"type": "string"},
                            "window": {
                                "type": "integer",
                                "minimum": 0,
                                "default": 0,
                                "description": "Max step distance (0 = unlimited).",
                            },
                        },
                        "additionalProperties": False,
                    },
                },
                "cumulative_risk": {
                    "type": "object",
                    "description": "Threshold for total accumulated risk.",
                    "properties": {
                        "max_total_risk": {"type": "integer", "minimum": 1},
                        "on_exceed": {
                            "type": "string",
                            "enum": ["auto", "approve", "block"],
                            "default": "block",
                        },
                    },
                    "additionalProperties": False,
                },
            },
            "additionalProperties": False,
        },
    },
    "additionalProperties": False,
}


def get_schema_json(indent: int = 2) -> str:
    """Return the policy JSON Schema as a formatted JSON string."""
    return json.dumps(POLICY_SCHEMA, indent=indent)
