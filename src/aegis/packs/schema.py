"""Pack schema — YAML-driven guardrail rule definitions.

A *pack* is a YAML file that declares a set of guardrail rules.
:class:`Pack` validates the structure and can convert rules into
concrete :class:`~aegis.guardrails.base.Guardrail` instances.

Example YAML::

    name: pii
    version: "1.0"
    description: Detect and mask common PII patterns
    rules:
      - name: ssn
        type: pattern
        pattern: "\\\\b\\\\d{3}-\\\\d{2}-\\\\d{4}\\\\b"
        action: mask
        severity: high
        description: US Social Security Numbers
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aegis.guardrails.base import Guardrail

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


@dataclass
class PackRule:
    """A single rule within a pack.

    Attributes:
        name: Unique name for this rule within the pack.
        type: Rule type — ``"pattern"`` (regex), ``"keyword"``
            (word-boundary keyword list), or ``"custom"`` (user-provided).
        pattern: Regex string for ``"pattern"`` type rules.
        keywords: Keyword list for ``"keyword"`` type rules.
        action: Disposition when the rule matches — ``"block"``,
            ``"mask"``, ``"warn"``, or ``"log"``.
        severity: Finding severity — ``"low"``, ``"medium"``,
            ``"high"``, or ``"critical"``.
        description: Human-readable description of what this rule detects.
    """

    name: str
    type: str  # "pattern", "keyword", "custom"
    pattern: str | None = None
    keywords: list[str] | None = None
    action: str = "block"
    severity: str = "medium"
    description: str = ""


@dataclass
class Pack:
    """A named collection of guardrail rules loaded from YAML.

    Use :meth:`from_yaml` to load from a file, then :meth:`to_guardrails`
    to convert the rules into executable guardrail instances.

    Attributes:
        name: Pack name (e.g. ``"pii"``).
        version: Semver-style version string.
        description: What this pack protects against.
        rules: Ordered list of :class:`PackRule` definitions.
    """

    name: str
    version: str
    description: str
    rules: list[PackRule] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, path: str | Path) -> Pack:
        """Load a pack from a YAML file.

        Args:
            path: Path to the YAML file.

        Raises:
            FileNotFoundError: If *path* does not exist.
            ImportError: If PyYAML is not installed.
            ValueError: If the YAML structure is invalid.
        """
        if yaml is None:  # pragma: no cover
            raise ImportError(
                "PyYAML is required to load packs. Install it with: pip install pyyaml"
            )
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Pack file not found: {path}")
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, object] | None) -> Pack:
        """Load a pack from a dictionary.

        Args:
            data: Parsed YAML/JSON content.

        Raises:
            ValueError: If required fields are missing or invalid.
        """
        if data is None or not isinstance(data, dict):
            raise ValueError(
                "Pack data must be a mapping with 'name', 'version', and 'rules' keys."
            )
        name = data.get("name")
        version = data.get("version")
        if not name or not version:
            raise ValueError("Pack must have 'name' and 'version' fields.")

        raw_rules = data.get("rules")
        if not isinstance(raw_rules, list):
            raise ValueError("Pack 'rules' must be a list.")

        rules: list[PackRule] = []
        for i, raw in enumerate(raw_rules):
            if not isinstance(raw, dict):
                raise ValueError(f"Rule {i} must be a mapping, got {type(raw).__name__}.")
            rule_name = raw.get("name", f"rule_{i}")
            rule_type = raw.get("type", "pattern")
            keywords_raw = raw.get("keywords")
            keywords = list(keywords_raw) if isinstance(keywords_raw, list) else None
            rules.append(
                PackRule(
                    name=str(rule_name),
                    type=str(rule_type),
                    pattern=str(raw["pattern"]) if "pattern" in raw else None,
                    keywords=keywords,
                    action=str(raw.get("action", "block")),
                    severity=str(raw.get("severity", "medium")),
                    description=str(raw.get("description", "")),
                )
            )

        return cls(
            name=str(name),
            version=str(version),
            description=str(data.get("description", "")),
            rules=rules,
        )

    def to_guardrails(self) -> list[Guardrail]:
        """Convert pack rules to concrete :class:`Guardrail` instances.

        Raises:
            ValueError: If a rule type is unsupported or a pattern/keyword
                rule is missing its required field.
        """
        from aegis.guardrails.pattern import KeywordGuardrail, PatternGuardrail

        guardrails: list[Guardrail] = []
        for rule in self.rules:
            if rule.type == "pattern":
                if not rule.pattern:
                    raise ValueError(f"Pattern rule {rule.name!r} must have a 'pattern' field.")
                guardrails.append(
                    PatternGuardrail(
                        name=rule.name,
                        pattern=rule.pattern,
                        action=rule.action,
                        severity=rule.severity,
                        description=rule.description,
                    )
                )
            elif rule.type == "keyword":
                if not rule.keywords:
                    raise ValueError(f"Keyword rule {rule.name!r} must have a 'keywords' field.")
                guardrails.append(
                    KeywordGuardrail(
                        name=rule.name,
                        keywords=rule.keywords,
                        action=rule.action,
                        severity=rule.severity,
                        description=rule.description,
                    )
                )
            else:
                raise ValueError(
                    f"Unsupported rule type {rule.type!r} in rule {rule.name!r}. "
                    "Supported types: 'pattern', 'keyword'."
                )
        return guardrails
