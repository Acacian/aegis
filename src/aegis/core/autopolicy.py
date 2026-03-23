"""Natural language to YAML policy generator.

Provides two tiers of policy generation:

**Tier 1 (Template — built-in, no dependencies):**
Keyword/pattern-based parser that converts structured natural language
descriptions into YAML policies. Handles common patterns like
"block delete", "allow reads", "require approval for writes".

**Tier 2 (LLM — pluggable):**
Users can supply a custom ``PolicyGenerator`` (e.g. backed by OpenAI,
Anthropic, or any LLM) via the Protocol interface. The generator
receives the natural language description and returns a policy dict.

Example::

    from aegis.core.autopolicy import generate_policy

    # Tier 1: keyword-based (no LLM needed)
    policy = generate_policy(
        "block all deletes, allow reads automatically, "
        "require approval for writes and updates"
    )

    # Tier 2: LLM-backed
    policy = generate_policy(
        "Financial agents should not transfer more than $10K "
        "without CFO approval. Block all account deletions.",
        generator=my_llm_generator,
    )
"""

from __future__ import annotations

import logging
import re
from typing import Any, Protocol, runtime_checkable

import yaml

from aegis.core.builder import PolicyBuilder
from aegis.core.policy import Policy

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Protocol (Tier 2) — pluggable LLM-backed generator
# ---------------------------------------------------------------------------


@runtime_checkable
class PolicyGenerator(Protocol):
    """Pluggable policy generator for LLM-backed natural language parsing.

    Implement this protocol with your preferred LLM provider (OpenAI,
    Anthropic, etc.) and pass it to :func:`generate_policy`.

    The ``generate`` method receives a natural language description and
    must return a policy dict compatible with :meth:`Policy.from_dict`::

        {
            "version": "1",
            "defaults": {"risk_level": "medium", "approval": "approve"},
            "rules": [
                {"name": "...", "match": {"type": "..."}, ...}
            ]
        }
    """

    def generate(self, description: str) -> dict[str, Any]:
        """Generate a policy dict from a natural language description."""
        ...  # pragma: no cover


# ---------------------------------------------------------------------------
# Tier 1: keyword/template-based generator
# ---------------------------------------------------------------------------

# Maps action verbs to glob patterns and default risk levels.
_ACTION_PATTERNS: list[tuple[re.Pattern[str], str, str, str]] = [
    # (regex, match_type glob, default_risk, default_approval)
    (
        re.compile(
            r"\b(?:block|deny|forbid|prohibit|prevent)\b.*\b(?:delet|drop|destroy|remov|purg|truncat|kill|terminat)",
            re.I,
        ),
        "delete*",
        "critical",
        "block",
    ),
    (
        re.compile(
            r"\b(?:block|deny|forbid|prohibit|prevent)\b.*\b(?:export|download|transfer)", re.I
        ),
        "export*",
        "high",
        "block",
    ),
    (
        re.compile(r"\b(?:block|deny|forbid|prohibit|prevent)\b.*\b(?:all|every)", re.I),
        "*",
        "critical",
        "block",
    ),
    (
        re.compile(r"\b(?:block|deny|forbid|prohibit|prevent)\b.*\b(\w+)", re.I),
        "{0}*",
        "critical",
        "block",
    ),
    (
        re.compile(
            r"\b(?:allow|auto|permit)\b.*\b(?:read|search|list|get|fetch|view|query|lookup)", re.I
        ),
        "read*",
        "low",
        "auto",
    ),
    (re.compile(r"\b(?:allow|auto|permit)\b.*\b(?:all|every)", re.I), "*", "low", "auto"),
    (re.compile(r"\b(?:allow|auto|permit)\b.*\b(\w+)", re.I), "{0}*", "low", "auto"),
    (
        re.compile(
            r"\b(?:approv|review|confirm|human)\b.*\b(?:writ|updat|modif|edit|chang|patch)", re.I
        ),
        "write*",
        "medium",
        "approve",
    ),
    (
        re.compile(r"\b(?:approv|review|confirm|human)\b.*\b(?:send|email|messag|notif)", re.I),
        "send*",
        "medium",
        "approve",
    ),
    (
        re.compile(r"\b(?:approv|review|confirm|human)\b.*\b(?:deploy|releas|publish)", re.I),
        "deploy*",
        "high",
        "approve",
    ),
    (
        re.compile(r"\b(?:approv|review|confirm|human)\b.*\b(\w+)", re.I),
        "{0}*",
        "medium",
        "approve",
    ),
    (
        re.compile(
            r"\b(?:read|search|list|get|fetch|view|query|lookup)\b.*\b(?:auto|safe|allow)", re.I
        ),
        "read*",
        "low",
        "auto",
    ),
    (
        re.compile(
            r"\b(?:delet|drop|destroy|remov|purg|truncat)\b.*\b(?:block|deny|never|forbid)", re.I
        ),
        "delete*",
        "critical",
        "block",
    ),
    (
        re.compile(
            r"\b(?:writ|updat|modif|edit|chang|patch)\b.*\b(?:approv|review|confirm)", re.I
        ),
        "write*",
        "medium",
        "approve",
    ),
]

# Condition patterns (param thresholds, time restrictions, etc.)
_CONDITION_PATTERNS: list[tuple[re.Pattern[str], str, Any]] = [
    (re.compile(r"\bmore than (?:\$)?(\d[\d,]*)", re.I), "param_gt", "amount"),
    (re.compile(r"\bover (?:\$)?(\d[\d,]*)", re.I), "param_gt", "amount"),
    (re.compile(r"\bexceed(?:s|ing)? (?:\$)?(\d[\d,]*)", re.I), "param_gt", "amount"),
    (
        re.compile(r"\b(?:greater|larger|bigger) than (?:\$)?(\d[\d,]*)", re.I),
        "param_gt",
        "amount",
    ),
    (re.compile(r"\bcount\b.*?(?:>|more than|over|exceed)\s*(\d+)", re.I), "param_gt", "count"),
    (re.compile(r"\bafter (?:business )?hours|after (\d{1,2}:\d{2})", re.I), "time_after", None),
    (re.compile(r"\bbefore (\d{1,2}:\d{2})", re.I), "time_before", None),
    (re.compile(r"\bweekday|(?:mon|tues|wednes|thurs|fri)day", re.I), "weekdays", None),
    (re.compile(r"\bweekend|(?:satur|sun)day", re.I), "weekdays", None),
]

# Target patterns
_TARGET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(?:on|from|to|in)\s+(?:the\s+)?production\b", re.I), "prod*"),
    (re.compile(r"\b(?:on|from|to|in)\s+(?:the\s+)?staging\b", re.I), "staging*"),
    (re.compile(r"\b(?:on|from|to|in)\s+(?:the\s+)?database\b", re.I), "db*"),
    (re.compile(r"\b(?:on|from|to|in)\s+(?:the\s+)?crm\b", re.I), "crm*"),
    (re.compile(r"\b(?:on|from|to|in)\s+(?:the\s+)?filesystem\b", re.I), "file*"),
]


class KeywordPolicyGenerator:
    """Built-in keyword/template policy generator (no external deps).

    Parses natural language descriptions into policy rules by matching
    common patterns like "block deletes", "allow reads automatically",
    "require approval for writes over $10K".
    """

    def generate(self, description: str) -> dict[str, Any]:
        """Generate a policy dict from a natural language description.

        Splits the description by sentence boundaries (periods, semicolons,
        commas, 'and') and matches each fragment against known patterns.
        """
        fragments = re.split(r"[.;]\s*|\s*,\s*(?:and\s+)?|\s+and\s+", description)
        fragments = [f.strip() for f in fragments if f.strip()]

        builder = PolicyBuilder().defaults(risk_level="medium", approval="approve")
        rule_count = 0
        seen_types: set[str] = set()

        for fragment in fragments:
            rule = self._parse_fragment(fragment)
            if rule and rule["match_type"] not in seen_types:
                rule_count += 1
                name = rule.get("name", f"rule_{rule_count}")
                rb = builder.rule(name).match(
                    type=rule["match_type"],
                    target=rule.get("target", "*"),
                )
                rb.risk(rule["risk_level"])

                approval = rule["approval"]
                if approval == "auto":
                    rb.approve_auto()
                elif approval == "block":
                    rb.block()
                else:
                    rb.approve_human()

                if rule.get("conditions"):
                    rb.when(**rule["conditions"])

                seen_types.add(rule["match_type"])

        return builder.to_dict()

    def _parse_fragment(self, fragment: str) -> dict[str, Any] | None:
        """Parse a single natural language fragment into a rule spec."""
        for pattern, match_type_tpl, default_risk, default_approval in _ACTION_PATTERNS:
            m = pattern.search(fragment)
            if m:
                # Resolve captured group into match_type if template has {0}
                if "{0}" in match_type_tpl and m.lastindex and m.lastindex >= 1:
                    verb = m.group(m.lastindex).lower().rstrip("s").rstrip("e")
                    match_type = match_type_tpl.format(verb)
                else:
                    match_type = match_type_tpl

                # Detect target
                target = "*"
                for tp, tgt in _TARGET_PATTERNS:
                    if tp.search(fragment):
                        target = tgt
                        break

                # Detect conditions
                conditions: dict[str, Any] = {}
                for cp, cond_key, cond_param in _CONDITION_PATTERNS:
                    cm = cp.search(fragment)
                    if cm:
                        if cond_key == "param_gt" and cond_param:
                            val_str = cm.group(1).replace(",", "")
                            conditions[cond_key] = {cond_param: int(val_str)}
                        elif cond_key == "time_after":
                            time_val = cm.group(1) if cm.group(1) else "18:00"
                            conditions[cond_key] = time_val
                        elif cond_key == "time_before":
                            conditions[cond_key] = cm.group(1)
                        elif cond_key == "weekdays":
                            if re.search(r"weekend|satur|sun", fragment, re.I):
                                conditions[cond_key] = [6, 7]
                            else:
                                conditions[cond_key] = [1, 2, 3, 4, 5]

                # Generate name from match type
                clean_type = match_type.replace("*", "").rstrip("_") or "all"
                name = f"{clean_type}_{default_approval}"

                return {
                    "name": name,
                    "match_type": match_type,
                    "target": target,
                    "risk_level": default_risk,
                    "approval": default_approval,
                    "conditions": conditions if conditions else None,
                }

        return None


# Singleton instance used as default generator.
_DEFAULT_GENERATOR = KeywordPolicyGenerator()

# ---------------------------------------------------------------------------
# LLM prompt template for Tier 2 implementations
# ---------------------------------------------------------------------------

POLICY_GENERATION_PROMPT = """\
You are a policy generator for Aegis, an AI agent governance framework.
Convert the following natural language description into a YAML policy.

The output must be valid YAML matching this schema:
```yaml
version: "1"
defaults:
  risk_level: medium     # low | medium | high | critical
  approval: approve      # auto | approve | block

rules:
  - name: rule_name      # unique snake_case identifier
    match:
      type: "glob*"      # glob pattern for action type
      target: "glob*"    # glob pattern for target (optional)
    risk_level: low       # override default
    approval: auto        # override default
    conditions:           # optional
      param_gt: {key: value}
      time_after: "18:00"
      weekdays: [1,2,3,4,5]
```

Risk levels: low (safe reads), medium (writes), high (bulk/sensitive), critical (destructive).
Approval: auto (no human), approve (human required), block (never allowed).

IMPORTANT: Output ONLY the YAML. No explanation, no markdown fences.

Description:
{description}
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_policy(
    description: str,
    generator: PolicyGenerator | None = None,
) -> Policy:
    """Generate a policy from a natural language description.

    Args:
        description: Natural language description of desired governance rules.
            E.g. "block all deletes, allow reads, require approval for writes"
        generator: Optional custom generator (e.g. LLM-backed). Falls back to
            the built-in keyword parser when ``None``.

    Returns:
        A validated :class:`Policy` object.

    Example::

        # Tier 1 (built-in, no LLM)
        policy = generate_policy("block deletes, auto-approve reads")

        # Tier 2 (LLM-backed)
        from my_llm import OpenAIPolicyGenerator
        policy = generate_policy(
            "Financial agents cannot transfer more than $10K",
            generator=OpenAIPolicyGenerator(api_key="sk-..."),
        )
    """
    gen = generator or _DEFAULT_GENERATOR
    policy_dict = gen.generate(description)
    return Policy.from_dict(policy_dict)


def generate_policy_yaml(
    description: str,
    generator: PolicyGenerator | None = None,
) -> str:
    """Generate a YAML policy string from a natural language description.

    Same as :func:`generate_policy` but returns YAML text instead of
    a :class:`Policy` object. Useful for saving to a file.

    Args:
        description: Natural language description of desired governance rules.
        generator: Optional custom generator (e.g. LLM-backed).

    Returns:
        YAML string compatible with :meth:`Policy.from_yaml`.
    """
    gen = generator or _DEFAULT_GENERATOR
    policy_dict = gen.generate(description)
    return yaml.dump(policy_dict, default_flow_style=False, sort_keys=False)
