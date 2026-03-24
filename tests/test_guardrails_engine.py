"""Tests for GuardrailEngine."""

from pathlib import Path

from aegis.guardrails.engine import GuardrailEngine
from aegis.guardrails.pattern import KeywordGuardrail, PatternGuardrail

# -- Basic engine operations ------------------------------------------------


class TestGuardrailEngine:
    def test_engine_runs_all_guardrails(self):
        engine = GuardrailEngine()
        engine.add(PatternGuardrail(name="email", pattern=r"\w+@\w+\.\w+", action="warn"))
        engine.add(PatternGuardrail(name="phone", pattern=r"\d{3}-\d{4}", action="warn"))

        results = engine.check("contact: a@b.com or 123-4567")
        assert len(results) == 2
        assert results[0].guardrail_name == "email"
        assert results[1].guardrail_name == "phone"

    def test_engine_check_returns_all_even_when_blocked(self):
        """check() does NOT short-circuit -- all guardrails run."""
        engine = GuardrailEngine()
        engine.add(PatternGuardrail(name="first", pattern=r"bad", action="block"))
        engine.add(PatternGuardrail(name="second", pattern=r"bad", action="warn"))

        results = engine.check("bad content")
        assert len(results) == 2

    def test_engine_blocks_on_first_block_in_transform(self):
        """check_and_transform() stops on the first blocked result."""
        engine = GuardrailEngine()
        engine.add(PatternGuardrail(name="blocker", pattern=r"bad", action="block"))
        engine.add(PatternGuardrail(name="after", pattern=r"bad", action="warn"))

        results, content = engine.check_and_transform("bad content")
        assert len(results) == 1
        assert results[0].action == "blocked"
        assert results[0].guardrail_name == "blocker"

    def test_engine_applies_masking_sequentially(self):
        """Masks accumulate: each guardrail sees already-masked content."""
        engine = GuardrailEngine()
        engine.add(PatternGuardrail(name="email", pattern=r"\w+@\w+\.\w+", action="mask"))
        engine.add(PatternGuardrail(name="phone", pattern=r"\d{3}-\d{4}", action="mask"))

        results, content = engine.check_and_transform("email a@b.com phone 123-4567")
        assert len(results) == 2
        # Both original patterns should be replaced
        assert "a@b.com" not in content
        assert "123-4567" not in content
        assert "***" in content

    def test_empty_engine_returns_empty_results(self):
        engine = GuardrailEngine()
        results = engine.check("anything")
        assert results == []

    def test_empty_engine_transform_returns_original(self):
        engine = GuardrailEngine()
        results, content = engine.check_and_transform("anything")
        assert results == []
        assert content == "anything"

    def test_engine_len_and_repr(self):
        engine = GuardrailEngine()
        assert len(engine) == 0
        engine.add(PatternGuardrail(name="a", pattern=r"x"))
        assert len(engine) == 1
        assert "GuardrailEngine" in repr(engine)

    def test_engine_guardrails_property_returns_copy(self):
        engine = GuardrailEngine()
        g = PatternGuardrail(name="a", pattern=r"x")
        engine.add(g)
        copy = engine.guardrails
        assert len(copy) == 1
        copy.append(PatternGuardrail(name="b", pattern=r"y"))
        assert len(engine) == 1  # Original unchanged

    def test_engine_from_pack_loads_yaml(self):
        """from_pack() loads a YAML pack and creates guardrails."""
        builtin_dir = Path(__file__).parent.parent / "src" / "aegis" / "packs" / "builtin"
        pii_yaml = builtin_dir / "pii.yaml"

        engine = GuardrailEngine.from_pack(pii_yaml)
        assert len(engine) > 0
        # All loaded guardrails should have names
        for g in engine.guardrails:
            assert g.name

    def test_engine_with_mixed_guardrails(self):
        """Engine handles both pattern and keyword guardrails."""
        engine = GuardrailEngine()
        engine.add(PatternGuardrail(name="pat", pattern=r"\d+", action="mask"))
        engine.add(KeywordGuardrail(name="kw", keywords=["secret"], action="mask"))

        results, content = engine.check_and_transform("secret number 42")
        assert len(results) == 2
        assert "42" not in content
        assert "secret" not in content.lower()

    def test_engine_non_blocking_result_continues(self):
        """warn and log actions do not stop the pipeline."""
        engine = GuardrailEngine()
        engine.add(PatternGuardrail(name="w", pattern=r"warn", action="warn"))
        engine.add(PatternGuardrail(name="l", pattern=r"log", action="log"))
        engine.add(PatternGuardrail(name="m", pattern=r"\d+", action="mask"))

        results, content = engine.check_and_transform("warn log 99")
        assert len(results) == 3
        assert "99" not in content

    def test_engine_constructor_with_guardrails_list(self):
        gs = [
            PatternGuardrail(name="a", pattern=r"x"),
            PatternGuardrail(name="b", pattern=r"y"),
        ]
        engine = GuardrailEngine(guardrails=gs)
        assert len(engine) == 2
