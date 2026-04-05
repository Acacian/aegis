"""Tests for the Selection Audit engine."""

from __future__ import annotations

import asyncio
import threading
import time
from unittest.mock import MagicMock

import pytest

from aegis.core.selection_audit import (
    CommitRevealSelection,
    EliminatedOption,
    EliminationReason,
    FindingType,
    SelectionAuditor,
    SelectionAuditResult,
    SelectionOption,
    SelectionSet,
    audit_selection,
    set_global_auditor,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _opt(
    option_id: str = "opt-1",
    action_type: str = "read",
    target: str = "crm",
    estimated_impact: float = 0.0,
    **kwargs,
) -> SelectionOption:
    return SelectionOption(
        option_id=option_id,
        description=f"Option {option_id}",
        action_type=action_type,
        target=target,
        estimated_impact=estimated_impact,
        **kwargs,
    )


def _elim(
    option: SelectionOption | None = None,
    reason: EliminationReason = EliminationReason.AGENT_PREFERENCE,
    explanation: str = "",
) -> EliminatedOption:
    return EliminatedOption(
        option=option or _opt(),
        reason=reason,
        agent_explanation=explanation,
    )


# ---------------------------------------------------------------------------
# SelectionOption
# ---------------------------------------------------------------------------


class TestSelectionOption:
    def test_creation_with_defaults(self) -> None:
        opt = SelectionOption(
            option_id="a",
            description="desc",
            action_type="read",
            target="crm",
        )
        assert opt.option_id == "a"
        assert opt.description == "desc"
        assert opt.action_type == "read"
        assert opt.target == "crm"
        assert opt.params == {}
        assert opt.estimated_impact == 0.0
        assert opt.metadata == {}

    def test_creation_with_all_fields(self) -> None:
        opt = SelectionOption(
            option_id="b",
            description="full",
            action_type="write",
            target="stripe",
            params={"key": "val"},
            estimated_impact=0.75,
            metadata={"source": "planner"},
        )
        assert opt.params == {"key": "val"}
        assert opt.estimated_impact == 0.75
        assert opt.metadata == {"source": "planner"}

    def test_frozen(self) -> None:
        opt = _opt()
        with pytest.raises(AttributeError):
            opt.option_id = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# EliminatedOption
# ---------------------------------------------------------------------------


class TestEliminatedOption:
    def test_creation(self) -> None:
        opt = _opt("elim-1")
        elim = EliminatedOption(
            option=opt,
            reason=EliminationReason.POLICY_VIOLATION,
            agent_explanation="violates rule X",
        )
        assert elim.option is opt
        assert elim.reason == EliminationReason.POLICY_VIOLATION
        assert elim.agent_explanation == "violates rule X"

    def test_default_explanation(self) -> None:
        elim = _elim()
        assert elim.agent_explanation == ""

    def test_frozen(self) -> None:
        elim = _elim()
        with pytest.raises(AttributeError):
            elim.reason = EliminationReason.UNKNOWN  # type: ignore[misc]

    def test_all_elimination_reasons(self) -> None:
        for reason in EliminationReason:
            elim = _elim(reason=reason)
            assert elim.reason == reason


# ---------------------------------------------------------------------------
# SelectionSet
# ---------------------------------------------------------------------------


class TestSelectionSet:
    def test_creation_with_selected_and_eliminated(self) -> None:
        selected = _opt("selected")
        eliminated = [
            _elim(_opt("e1")),
            _elim(_opt("e2")),
        ]
        ss = SelectionSet(
            agent_id="agent-1",
            context="tool_selection",
            selected=selected,
            eliminated=eliminated,
        )
        assert ss.selected is selected
        assert len(ss.eliminated) == 2
        assert ss.agent_id == "agent-1"
        assert ss.context == "tool_selection"

    def test_total_options(self) -> None:
        ss = SelectionSet(
            selected=_opt(),
            eliminated=[_elim(), _elim(), _elim()],
        )
        assert ss.total_options == 4

    def test_total_options_no_selected(self) -> None:
        ss = SelectionSet(eliminated=[_elim(), _elim()])
        assert ss.total_options == 2

    def test_total_options_empty(self) -> None:
        ss = SelectionSet()
        assert ss.total_options == 0

    def test_elimination_ratio(self) -> None:
        ss = SelectionSet(
            selected=_opt(),
            eliminated=[_elim(), _elim(), _elim()],
        )
        # 3 eliminated out of 4 total = 0.75
        assert ss.elimination_ratio == pytest.approx(0.75)

    def test_elimination_ratio_empty(self) -> None:
        ss = SelectionSet()
        assert ss.elimination_ratio == 0.0

    def test_elimination_ratio_all_eliminated(self) -> None:
        ss = SelectionSet(eliminated=[_elim(), _elim()])
        assert ss.elimination_ratio == pytest.approx(1.0)

    def test_auto_generated_id(self) -> None:
        ss1 = SelectionSet()
        ss2 = SelectionSet()
        assert ss1.selection_id != ss2.selection_id
        assert len(ss1.selection_id) == 16

    def test_timestamp_auto_set(self) -> None:
        ss = SelectionSet()
        assert ss.timestamp is not None


# ---------------------------------------------------------------------------
# SelectionAuditor: high_elimination detection
# ---------------------------------------------------------------------------


class TestHighEliminationDetection:
    def test_high_elimination_detected(self) -> None:
        auditor = SelectionAuditor(elimination_threshold=0.5)
        ss = SelectionSet(
            selected=_opt("sel"),
            eliminated=[_elim(_opt(f"e{i}")) for i in range(9)],
        )
        # 9/10 = 0.9 > 0.5 threshold
        result = auditor.audit(ss)
        high_elim = [f for f in result.findings if f.finding_type == FindingType.HIGH_ELIMINATION]
        assert len(high_elim) == 1
        assert high_elim[0].severity == pytest.approx(0.9)

    def test_below_threshold_not_detected(self) -> None:
        auditor = SelectionAuditor(elimination_threshold=0.8)
        ss = SelectionSet(
            selected=_opt("sel"),
            eliminated=[_elim(_opt("e1"))],
        )
        # 1/2 = 0.5 < 0.8 threshold
        result = auditor.audit(ss)
        high_elim = [f for f in result.findings if f.finding_type == FindingType.HIGH_ELIMINATION]
        assert len(high_elim) == 0

    def test_exactly_at_threshold_not_detected(self) -> None:
        auditor = SelectionAuditor(elimination_threshold=0.8)
        ss = SelectionSet(
            selected=_opt("sel"),
            eliminated=[_elim(_opt(f"e{i}")) for i in range(4)],
        )
        # 4/5 = 0.8, not strictly > 0.8
        result = auditor.audit(ss)
        high_elim = [f for f in result.findings if f.finding_type == FindingType.HIGH_ELIMINATION]
        assert len(high_elim) == 0


# ---------------------------------------------------------------------------
# SelectionAuditor: better_option_eliminated detection
# ---------------------------------------------------------------------------


class TestBetterOptionEliminatedDetection:
    def test_better_option_detected(self) -> None:
        """Eliminated option with lower impact than selected triggers finding."""
        auditor = SelectionAuditor()
        selected = _opt("sel", estimated_impact=0.5)
        elim_opt = _opt("elim", estimated_impact=0.2)  # lower impact = "better"
        ss = SelectionSet(
            selected=selected,
            eliminated=[
                _elim(elim_opt, reason=EliminationReason.AGENT_PREFERENCE, explanation="x")
            ],
        )
        result = auditor.audit(ss)
        better = [
            f for f in result.findings if f.finding_type == FindingType.BETTER_OPTION_ELIMINATED
        ]
        assert len(better) == 1
        assert better[0].severity == 0.8
        assert "elim" in better[0].detail["eliminated"]

    def test_worse_option_not_flagged(self) -> None:
        """Eliminated option with higher impact than selected is not flagged."""
        auditor = SelectionAuditor()
        selected = _opt("sel", estimated_impact=0.2)
        elim_opt = _opt("elim", estimated_impact=0.8)  # higher impact
        ss = SelectionSet(
            selected=selected,
            eliminated=[_elim(elim_opt)],
        )
        result = auditor.audit(ss)
        better = [
            f for f in result.findings if f.finding_type == FindingType.BETTER_OPTION_ELIMINATED
        ]
        assert len(better) == 0

    def test_no_selected_skips_check(self) -> None:
        """When there is no selected option, better-option check is skipped."""
        auditor = SelectionAuditor()
        ss = SelectionSet(
            eliminated=[_elim(_opt("e", estimated_impact=0.1))],
        )
        result = auditor.audit(ss)
        better = [
            f for f in result.findings if f.finding_type == FindingType.BETTER_OPTION_ELIMINATED
        ]
        assert len(better) == 0


# ---------------------------------------------------------------------------
# SelectionAuditor: unjustified_elimination detection
# ---------------------------------------------------------------------------


class TestUnjustifiedEliminationDetection:
    def test_unjustified_detected(self) -> None:
        """Agent preference without explanation triggers finding."""
        auditor = SelectionAuditor()
        ss = SelectionSet(
            selected=_opt("sel"),
            eliminated=[
                _elim(reason=EliminationReason.AGENT_PREFERENCE, explanation=""),
                _elim(reason=EliminationReason.AGENT_PREFERENCE, explanation=""),
            ],
        )
        result = auditor.audit(ss)
        unjust = [
            f for f in result.findings if f.finding_type == FindingType.UNJUSTIFIED_ELIMINATION
        ]
        assert len(unjust) == 1
        assert "2 options" in unjust[0].message

    def test_justified_not_detected(self) -> None:
        """Agent preference with explanation is not flagged."""
        auditor = SelectionAuditor()
        ss = SelectionSet(
            selected=_opt("sel"),
            eliminated=[
                _elim(reason=EliminationReason.AGENT_PREFERENCE, explanation="good reason"),
            ],
        )
        result = auditor.audit(ss)
        unjust = [
            f for f in result.findings if f.finding_type == FindingType.UNJUSTIFIED_ELIMINATION
        ]
        assert len(unjust) == 0

    def test_policy_violation_not_flagged(self) -> None:
        """Non-agent-preference eliminations are not flagged as unjustified."""
        auditor = SelectionAuditor()
        ss = SelectionSet(
            selected=_opt("sel"),
            eliminated=[
                _elim(reason=EliminationReason.POLICY_VIOLATION, explanation=""),
                _elim(reason=EliminationReason.RESOURCE_CONSTRAINT, explanation=""),
            ],
        )
        result = auditor.audit(ss)
        unjust = [
            f for f in result.findings if f.finding_type == FindingType.UNJUSTIFIED_ELIMINATION
        ]
        assert len(unjust) == 0


# ---------------------------------------------------------------------------
# SelectionAuditor: systematic exclusion (pattern detection)
# ---------------------------------------------------------------------------


class TestSystematicExclusionDetection:
    def test_systematic_exclusion_detected(self) -> None:
        """Target repeatedly eliminated across many selections triggers finding."""
        auditor = SelectionAuditor(history_window=100)
        for i in range(12):
            ss = SelectionSet(
                selected=_opt(f"sel-{i}", target="allowed"),
                eliminated=[_elim(_opt(f"e-{i}", target="blocked-target"))],
            )
            result = auditor.audit(ss)

        # After 12 iterations (>10 for pattern), "blocked-target" excluded in all
        systematic = [
            f for f in result.findings if f.finding_type == FindingType.SYSTEMATIC_EXCLUSION
        ]
        assert len(systematic) >= 1
        assert "blocked-target" in systematic[0].message

    def test_no_pattern_with_few_selections(self) -> None:
        """Pattern detection needs at least 10 selections in history."""
        auditor = SelectionAuditor()
        for i in range(5):
            ss = SelectionSet(
                selected=_opt(f"sel-{i}"),
                eliminated=[_elim(_opt(f"e-{i}", target="victim"))],
            )
            result = auditor.audit(ss)

        systematic = [
            f for f in result.findings if f.finding_type == FindingType.SYSTEMATIC_EXCLUSION
        ]
        assert len(systematic) == 0


# ---------------------------------------------------------------------------
# SelectionAuditor: overall_risk and is_suspicious
# ---------------------------------------------------------------------------


class TestOverallRisk:
    def test_overall_risk_is_max_severity(self) -> None:
        auditor = SelectionAuditor(elimination_threshold=0.3)
        ss = SelectionSet(
            selected=_opt("sel", estimated_impact=0.5),
            eliminated=[
                _elim(
                    _opt("e", estimated_impact=0.1),
                    reason=EliminationReason.AGENT_PREFERENCE,
                    explanation="",
                ),
            ],
        )
        result = auditor.audit(ss)
        assert result.overall_risk > 0
        severities = [f.severity for f in result.findings]
        assert result.overall_risk == max(severities)

    def test_no_findings_zero_risk(self) -> None:
        auditor = SelectionAuditor()
        ss = SelectionSet(
            selected=_opt("sel"),
            eliminated=[_elim(reason=EliminationReason.POLICY_VIOLATION, explanation="ok")],
        )
        result = auditor.audit(ss)
        # Only 1 eliminated out of 2 total = 0.5 ratio, threshold is 0.8 -> no high_elimination
        # Reason is policy_violation -> no unjustified
        if not result.findings:
            assert result.overall_risk == 0.0

    def test_is_suspicious_above_half(self) -> None:
        r = SelectionAuditResult(selection_id="test", overall_risk=0.6)
        assert r.is_suspicious is True

    def test_is_suspicious_below_half(self) -> None:
        r = SelectionAuditResult(selection_id="test", overall_risk=0.3)
        assert r.is_suspicious is False

    def test_is_suspicious_at_boundary(self) -> None:
        r = SelectionAuditResult(selection_id="test", overall_risk=0.5)
        assert r.is_suspicious is False


# ---------------------------------------------------------------------------
# SelectionAuditor: history window
# ---------------------------------------------------------------------------


class TestHistoryWindow:
    def test_history_trimmed_to_window(self) -> None:
        auditor = SelectionAuditor(history_window=5)
        for i in range(10):
            auditor.audit(SelectionSet(selected=_opt(f"s-{i}")))
        assert len(auditor._history) == 5


# ---------------------------------------------------------------------------
# @audit_selection decorator
# ---------------------------------------------------------------------------


class TestAuditSelectionDecorator:
    def test_decorator_audits_selection_set(self) -> None:
        auditor = SelectionAuditor()

        @audit_selection(auditor=auditor, context="test", agent_id="test-agent")
        async def select() -> SelectionSet:
            return SelectionSet(
                selected=_opt("sel"),
                eliminated=[_elim()],
            )

        result = asyncio.get_event_loop().run_until_complete(select())
        assert isinstance(result, SelectionSet)
        assert result.agent_id == "test-agent"
        assert result.context == "test"

    def test_decorator_passes_through_non_selection(self) -> None:
        auditor = SelectionAuditor()

        @audit_selection(auditor=auditor)
        async def not_selection() -> dict:
            return {"key": "value"}

        result = asyncio.get_event_loop().run_until_complete(not_selection())
        assert result == {"key": "value"}

    def test_decorator_with_global_auditor(self) -> None:
        auditor = SelectionAuditor()
        set_global_auditor(auditor)
        try:

            @audit_selection(context="global-test")
            async def select() -> SelectionSet:
                return SelectionSet(
                    selected=_opt("sel"),
                    eliminated=[_elim()],
                )

            result = asyncio.get_event_loop().run_until_complete(select())
            assert isinstance(result, SelectionSet)
            assert result.context == "global-test"
        finally:
            set_global_auditor(None)  # type: ignore[arg-type]

    def test_decorator_preserves_existing_agent_id(self) -> None:
        auditor = SelectionAuditor()

        @audit_selection(auditor=auditor, agent_id="")
        async def select() -> SelectionSet:
            return SelectionSet(
                agent_id="original-agent",
                selected=_opt("sel"),
            )

        result = asyncio.get_event_loop().run_until_complete(select())
        assert result.agent_id == "original-agent"

    def test_decorator_with_to_selection_set(self) -> None:
        auditor = SelectionAuditor()

        class CustomResult:
            _aegis_audit = None

            def to_selection_set(self) -> SelectionSet:
                return SelectionSet(selected=_opt("sel"), eliminated=[_elim()])

        @audit_selection(auditor=auditor, context="custom")
        async def select() -> CustomResult:
            return CustomResult()

        result = asyncio.get_event_loop().run_until_complete(select())
        assert isinstance(result, CustomResult)


# ---------------------------------------------------------------------------
# CommitRevealSelection
# ---------------------------------------------------------------------------


class TestCommitRevealSelection:
    def _make_cr(self) -> CommitRevealSelection:
        auditor = SelectionAuditor()
        policy = MagicMock()
        return CommitRevealSelection(auditor=auditor, policy=policy)

    def test_commit_returns_selection_id(self) -> None:
        cr = self._make_cr()
        ss = SelectionSet(selected=_opt("sel"))

        sid = asyncio.get_event_loop().run_until_complete(cr.commit(ss))
        assert sid == ss.selection_id

    def test_commit_reveal_flow(self) -> None:
        cr = self._make_cr()
        ss = SelectionSet(
            selected=_opt("sel"),
            eliminated=[_elim()],
        )

        sid = asyncio.get_event_loop().run_until_complete(cr.commit(ss))
        result = asyncio.get_event_loop().run_until_complete(cr.reveal(sid))
        assert isinstance(result, SelectionAuditResult)
        assert result.selection_id == ss.selection_id

    def test_reveal_cleans_up(self) -> None:
        cr = self._make_cr()
        ss = SelectionSet(selected=_opt("sel"))

        sid = asyncio.get_event_loop().run_until_complete(cr.commit(ss))
        asyncio.get_event_loop().run_until_complete(cr.reveal(sid))

        # Second reveal should raise
        with pytest.raises(ValueError, match="No committed selection"):
            asyncio.get_event_loop().run_until_complete(cr.reveal(sid))

    def test_reveal_unknown_id_raises(self) -> None:
        cr = self._make_cr()
        with pytest.raises(ValueError, match="No committed selection"):
            asyncio.get_event_loop().run_until_complete(cr.reveal("nonexistent"))

    def test_multiple_commits(self) -> None:
        cr = self._make_cr()
        ss1 = SelectionSet(selected=_opt("s1"))
        ss2 = SelectionSet(selected=_opt("s2"))

        sid1 = asyncio.get_event_loop().run_until_complete(cr.commit(ss1))
        sid2 = asyncio.get_event_loop().run_until_complete(cr.commit(ss2))
        assert sid1 != sid2

        r1 = asyncio.get_event_loop().run_until_complete(cr.reveal(sid1))
        r2 = asyncio.get_event_loop().run_until_complete(cr.reveal(sid2))
        assert r1.selection_id == ss1.selection_id
        assert r2.selection_id == ss2.selection_id

    def test_max_pending_limit(self) -> None:
        """CommitRevealSelection enforces max_pending limit."""
        auditor = SelectionAuditor()
        cr = CommitRevealSelection(auditor=auditor, policy=MagicMock(), max_pending=3)

        for i in range(3):
            ss = SelectionSet(selected=_opt(f"s{i}"))
            asyncio.get_event_loop().run_until_complete(cr.commit(ss))

        # 4th commit should fail
        ss4 = SelectionSet(selected=_opt("s3"))
        with pytest.raises(RuntimeError, match="Too many pending commits"):
            asyncio.get_event_loop().run_until_complete(cr.commit(ss4))

    def test_ttl_expiry(self) -> None:
        """Expired committed entries are pruned on next commit."""
        auditor = SelectionAuditor()
        cr = CommitRevealSelection(
            auditor=auditor,
            policy=MagicMock(),
            ttl_seconds=0.01,
        )

        ss1 = SelectionSet(selected=_opt("s1"))
        sid1 = asyncio.get_event_loop().run_until_complete(cr.commit(ss1))

        time.sleep(0.05)  # wait for TTL to expire

        # Reveal should fail — entry expired
        with pytest.raises(ValueError, match="No committed selection"):
            asyncio.get_event_loop().run_until_complete(cr.reveal(sid1))

    def test_ttl_prune_frees_capacity(self) -> None:
        """Expired entries are pruned, freeing capacity for new commits."""
        auditor = SelectionAuditor()
        cr = CommitRevealSelection(
            auditor=auditor,
            policy=MagicMock(),
            max_pending=2,
            ttl_seconds=0.01,
        )

        for i in range(2):
            ss = SelectionSet(selected=_opt(f"s{i}"))
            asyncio.get_event_loop().run_until_complete(cr.commit(ss))

        time.sleep(0.05)  # TTL expires

        # Should succeed because expired entries were pruned
        ss_new = SelectionSet(selected=_opt("new"))
        sid = asyncio.get_event_loop().run_until_complete(cr.commit(ss_new))
        assert sid == ss_new.selection_id


# ---------------------------------------------------------------------------
# Thread safety (WARNING-07)
# ---------------------------------------------------------------------------


class TestSelectionAuditorThreadSafety:
    def test_concurrent_audits_no_crash(self) -> None:
        """Multiple threads auditing concurrently should not crash."""
        auditor = SelectionAuditor(history_window=50)
        errors: list[Exception] = []

        def audit_many(thread_id: int) -> None:
            try:
                for i in range(20):
                    ss = SelectionSet(
                        selected=_opt(f"t{thread_id}-s{i}", target="target"),
                        eliminated=[_elim(_opt(f"t{thread_id}-e{i}", target="victim"))],
                    )
                    auditor.audit(ss)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=audit_many, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0


# ---------------------------------------------------------------------------
# Sync decorator (SPEC_GAP-05)
# ---------------------------------------------------------------------------


class TestAuditSelectionSyncDecorator:
    def test_sync_function_supported(self) -> None:
        """@audit_selection works with synchronous functions."""
        auditor = SelectionAuditor()

        @audit_selection(auditor=auditor, context="sync_test", agent_id="sync-agent")
        def sync_select() -> SelectionSet:
            return SelectionSet(
                selected=_opt("chosen"),
                eliminated=[_elim(_opt("rejected"))],
            )

        result = sync_select()
        assert isinstance(result, SelectionSet)
        assert result.agent_id == "sync-agent"
        assert result.context == "sync_test"

    def test_async_function_still_works(self) -> None:
        """@audit_selection still works with async functions."""
        auditor = SelectionAuditor()

        @audit_selection(auditor=auditor, context="async_test")
        async def async_select() -> SelectionSet:
            return SelectionSet(
                selected=_opt("chosen"),
                eliminated=[_elim(_opt("rejected"))],
            )

        result = asyncio.get_event_loop().run_until_complete(async_select())
        assert isinstance(result, SelectionSet)
        assert result.context == "async_test"

    def test_sync_non_selection_passthrough(self) -> None:
        """Sync function returning non-SelectionSet passes through."""

        @audit_selection()
        def compute() -> dict[str, int]:
            return {"value": 42}

        result = compute()
        assert result == {"value": 42}
