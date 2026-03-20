"""JSON Schema for Aegis policy files.

Provides a schema that editors and CI pipelines can use to validate
policy YAML files before loading.

Usage::

    from aegis.core.schema import POLICY_SCHEMA
    import jsonschema
    jsonschema.validate(policy_dict, POLICY_SCHEMA)

Or via CLI::

    aegis schema          # Print the JSON Schema
    aegis validate --schema policy.yaml  # Validate against schema
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
            "enum": ["1"],
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
                                    "Glob pattern for action type"
                                    " (e.g. 'read', 'delete*')."
                                ),
                                "default": "*",
                            },
                            "target": {
                                "type": "string",
                                "description": (
                                    "Glob pattern for action target"
                                    " (e.g. 'salesforce', '*')."
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
                },
                "additionalProperties": False,
            },
        },
    },
    "additionalProperties": False,
}


def get_schema_json(indent: int = 2) -> str:
    """Return the policy JSON Schema as a formatted JSON string."""
    return json.dumps(POLICY_SCHEMA, indent=indent)
