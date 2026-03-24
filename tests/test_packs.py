"""Tests for the Pack system (schema + loader)."""

import pytest

from aegis.guardrails.pattern import KeywordGuardrail, PatternGuardrail
from aegis.packs.loader import list_builtin_packs, load_pack
from aegis.packs.schema import Pack, PackRule

# -- Pack.from_yaml ---------------------------------------------------------


class TestPackFromYAML:
    def test_loads_pii_yaml(self):
        pack = load_pack("pii")
        assert pack.name == "@aegis/pii-detection"
        assert pack.version == "1.0.0"
        assert len(pack.rules) > 0

    def test_loads_injection_yaml(self):
        pack = load_pack("injection")
        assert pack.name == "@aegis/prompt-injection"
        assert pack.version == "1.0.0"
        assert len(pack.rules) > 0


# -- Pack.from_dict ---------------------------------------------------------


class TestPackFromDict:
    def test_minimal_pack(self):
        data = {
            "name": "test",
            "version": "1.0",
            "rules": [
                {
                    "name": "r1",
                    "type": "pattern",
                    "pattern": r"\d+",
                    "action": "block",
                }
            ],
        }
        pack = Pack.from_dict(data)
        assert pack.name == "test"
        assert pack.version == "1.0"
        assert len(pack.rules) == 1
        assert pack.rules[0].name == "r1"
        assert pack.rules[0].type == "pattern"

    def test_keyword_rule(self):
        data = {
            "name": "kw",
            "version": "1.0",
            "rules": [
                {
                    "name": "kw_rule",
                    "type": "keyword",
                    "keywords": ["admin", "root"],
                    "action": "block",
                }
            ],
        }
        pack = Pack.from_dict(data)
        assert pack.rules[0].type == "keyword"
        assert pack.rules[0].keywords == ["admin", "root"]

    def test_missing_name_raises(self):
        with pytest.raises(ValueError, match="name"):
            Pack.from_dict({"version": "1.0", "rules": []})

    def test_missing_version_raises(self):
        with pytest.raises(ValueError, match="version"):
            Pack.from_dict({"name": "x", "rules": []})

    def test_missing_rules_raises(self):
        with pytest.raises(ValueError, match="rules"):
            Pack.from_dict({"name": "x", "version": "1.0"})

    def test_none_data_raises(self):
        with pytest.raises(ValueError, match="mapping"):
            Pack.from_dict(None)

    def test_non_dict_data_raises(self):
        with pytest.raises(ValueError, match="mapping"):
            Pack.from_dict("not a dict")  # type: ignore[arg-type]

    def test_rule_not_dict_raises(self):
        with pytest.raises(ValueError, match="mapping"):
            Pack.from_dict(
                {
                    "name": "x",
                    "version": "1.0",
                    "rules": ["not a dict"],
                }
            )

    def test_rules_not_list_raises(self):
        with pytest.raises(ValueError, match="list"):
            Pack.from_dict(
                {
                    "name": "x",
                    "version": "1.0",
                    "rules": "not a list",
                }
            )


# -- Pack.to_guardrails -----------------------------------------------------


class TestPackToGuardrails:
    def test_pattern_rule_creates_pattern_guardrail(self):
        pack = Pack(
            name="test",
            version="1.0",
            description="test",
            rules=[
                PackRule(
                    name="digits",
                    type="pattern",
                    pattern=r"\d+",
                    action="block",
                    severity="high",
                    description="match digits",
                )
            ],
        )
        guardrails = pack.to_guardrails()
        assert len(guardrails) == 1
        assert isinstance(guardrails[0], PatternGuardrail)
        assert guardrails[0].name == "digits"

    def test_keyword_rule_creates_keyword_guardrail(self):
        pack = Pack(
            name="test",
            version="1.0",
            description="test",
            rules=[
                PackRule(
                    name="words",
                    type="keyword",
                    keywords=["secret", "private"],
                    action="mask",
                )
            ],
        )
        guardrails = pack.to_guardrails()
        assert len(guardrails) == 1
        assert isinstance(guardrails[0], KeywordGuardrail)
        assert guardrails[0].name == "words"

    def test_unsupported_type_raises(self):
        pack = Pack(
            name="test",
            version="1.0",
            description="test",
            rules=[PackRule(name="bad", type="custom")],
        )
        with pytest.raises(ValueError, match="Unsupported rule type"):
            pack.to_guardrails()

    def test_pattern_rule_without_pattern_raises(self):
        pack = Pack(
            name="test",
            version="1.0",
            description="test",
            rules=[PackRule(name="missing", type="pattern", pattern=None)],
        )
        with pytest.raises(ValueError, match="pattern"):
            pack.to_guardrails()

    def test_keyword_rule_without_keywords_raises(self):
        pack = Pack(
            name="test",
            version="1.0",
            description="test",
            rules=[PackRule(name="missing", type="keyword", keywords=None)],
        )
        with pytest.raises(ValueError, match="keywords"):
            pack.to_guardrails()

    def test_pii_pack_to_guardrails(self):
        pack = load_pack("pii")
        guardrails = pack.to_guardrails()
        assert len(guardrails) > 0
        # All PII rules should be pattern-based
        for g in guardrails:
            assert isinstance(g, PatternGuardrail)

    def test_multiple_rules(self):
        pack = Pack(
            name="multi",
            version="1.0",
            description="",
            rules=[
                PackRule(name="r1", type="pattern", pattern=r"\d+", action="block"),
                PackRule(
                    name="r2",
                    type="keyword",
                    keywords=["bad"],
                    action="mask",
                ),
                PackRule(name="r3", type="pattern", pattern=r"[A-Z]+", action="warn"),
            ],
        )
        guardrails = pack.to_guardrails()
        assert len(guardrails) == 3


# -- load_pack --------------------------------------------------------------


class TestLoadPack:
    def test_load_pii(self):
        pack = load_pack("pii")
        assert pack.name == "@aegis/pii-detection"

    def test_load_injection(self):
        pack = load_pack("injection")
        assert pack.name == "@aegis/prompt-injection"

    def test_load_nonexistent_raises(self):
        with pytest.raises(FileNotFoundError, match="not found"):
            load_pack("nonexistent_pack_name")


# -- list_builtin_packs -----------------------------------------------------


class TestListBuiltinPacks:
    def test_returns_available_packs(self):
        packs = list_builtin_packs()
        assert isinstance(packs, list)
        assert "pii" in packs
        assert "injection" in packs

    def test_returns_sorted(self):
        packs = list_builtin_packs()
        assert packs == sorted(packs)
