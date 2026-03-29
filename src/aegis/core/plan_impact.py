"""Policy Impact Analyzer — deep analysis of policy changes against audit history.

Extends the basic diff/replay engine with pattern grouping, risk migration
tracking, and period filtering.  This is the core analytical engine behind
``aegis plan --audit-db``.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from aegis.core.action import Action
from aegis.core.policy import Policy

# Severity ordering — mirrors ``_APPROVAL_SEVERITY`` in ``diff.py``.
_APPROVAL_SEVERITY: dict[str, int] = {
    "auto": 0,
    "approve": 1,
    "block": 2,
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ActionImpact:
    """Impact of a policy change on a single historical action."""

    action_type: str
    target: str
    params: dict[str, Any]
    agent_id: str
    timestamp: datetime
    old_decision: str
    new_decision: str
    old_risk: str
    new_risk: str
    change: str  # "newly_blocked", "newly_allowed", "restricted", "promoted", "unchanged"


@dataclass(frozen=True)
class PatternGroup:
    """A group of actions sharing the same type+target pattern."""

    action_type: str
    target: str
    count: int


@dataclass(frozen=True)
class RiskMigration:
    """Tracks actions moving between risk levels."""

    from_risk: str
    to_risk: str
    count: int


@dataclass
class ImpactReport:
    """Aggregate impact report from policy change analysis.

    Contains summary statistics, pattern breakdowns, and risk
    migration data.  Supports both text and dict serialization.
    """

    total_actions: int = 0
    newly_blocked: int = 0
    newly_allowed: int = 0
    restricted: int = 0
    promoted: int = 0
    unchanged: int = 0

    top_newly_blocked_patterns: list[PatternGroup] = field(default_factory=list)
    top_newly_allowed_patterns: list[PatternGroup] = field(default_factory=list)

    risk_higher: int = 0
    risk_lower: int = 0
    risk_migrations: list[RiskMigration] = field(default_factory=list)

    impacts: list[ActionImpact] = field(default_factory=list)

    def to_text(self) -> str:
        """Render as human-readable text (terraform plan style)."""
        if self.total_actions == 0:
            return "No historical actions to analyze."

        lines: list[str] = []
        total = self.total_actions
        lines.append(f"Policy Impact Analysis (based on {total:,} historical actions)")
        lines.append("")

        # Summary counts
        def _pct(n: int) -> str:
            return f"{n / total * 100:.1f}%" if total else "0.0%"

        nb = self.newly_blocked
        na = self.newly_allowed
        uc = self.unchanged
        lines.append(f"  Actions that would be NEWLY BLOCKED: {nb:>5} ({_pct(nb)})")
        lines.append(f"  Actions that would be NEWLY ALLOWED: {na:>5} ({_pct(na)})")
        lines.append(f"  Actions unchanged:                   {uc:>5} ({_pct(uc)})")

        if self.restricted:
            rs = self.restricted
            lines.append(f"  Actions restricted (not blocked):    {rs:>5} ({_pct(rs)})")
        if self.promoted:
            pm = self.promoted
            lines.append(f"  Actions promoted (less restrictive): {pm:>5} ({_pct(pm)})")

        # Top newly blocked patterns
        if self.top_newly_blocked_patterns:
            lines.append("")
            lines.append("  Top newly blocked patterns:")
            for pg in self.top_newly_blocked_patterns[:10]:
                lines.append(f"    - {pg.action_type} with target={pg.target}: {pg.count} actions")

        # Top newly allowed patterns
        if self.top_newly_allowed_patterns:
            lines.append("")
            lines.append("  Top newly allowed patterns:")
            for pg in self.top_newly_allowed_patterns[:10]:
                lines.append(f"    - {pg.action_type} with target={pg.target}: {pg.count} actions")

        # Risk level changes
        if self.risk_higher or self.risk_lower:
            lines.append("")
            lines.append("  Risk level changes:")
            if self.risk_higher:
                lines.append(f"    - Actions moving to HIGHER risk: {self.risk_higher}")
            if self.risk_lower:
                lines.append(f"    - Actions moving to LOWER risk: {self.risk_lower}")

        if self.risk_migrations:
            lines.append("")
            lines.append("  Risk migration detail:")
            for rm in self.risk_migrations:
                lines.append(f"    - {rm.from_risk} -> {rm.to_risk}: {rm.count} actions")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "total_actions": self.total_actions,
            "newly_blocked": self.newly_blocked,
            "newly_allowed": self.newly_allowed,
            "restricted": self.restricted,
            "promoted": self.promoted,
            "unchanged": self.unchanged,
            "top_newly_blocked_patterns": [
                {"action_type": pg.action_type, "target": pg.target, "count": pg.count}
                for pg in self.top_newly_blocked_patterns
            ],
            "top_newly_allowed_patterns": [
                {"action_type": pg.action_type, "target": pg.target, "count": pg.count}
                for pg in self.top_newly_allowed_patterns
            ],
            "risk_higher": self.risk_higher,
            "risk_lower": self.risk_lower,
            "risk_migrations": [
                {"from_risk": rm.from_risk, "to_risk": rm.to_risk, "count": rm.count}
                for rm in self.risk_migrations
            ],
            "impacts": [
                {
                    "action_type": ai.action_type,
                    "target": ai.target,
                    "agent_id": ai.agent_id,
                    "old_decision": ai.old_decision,
                    "new_decision": ai.new_decision,
                    "old_risk": ai.old_risk,
                    "new_risk": ai.new_risk,
                    "change": ai.change,
                }
                for ai in self.impacts
            ],
        }


# ---------------------------------------------------------------------------
# Period parsing
# ---------------------------------------------------------------------------

# Matches durations like "30d", "7d", "12h", "4w".
_DURATION_RE = re.compile(r"^(\d+)([dhwm])$", re.IGNORECASE)

# Matches quarter notation like "2026-Q1".
_QUARTER_RE = re.compile(r"^(\d{4})-[Qq]([1-4])$")


def parse_period(
    period: str,
    *,
    now: datetime | None = None,
) -> tuple[datetime, datetime]:
    """Parse a period string into (start, end) datetimes.

    Supported formats:
    - Duration: "30d", "7d", "24h", "4w" (relative to *now*)
    - Quarter: "2026-Q1", "2025-Q3"
    - ISO date range: "2026-01-01..2026-03-31"

    Args:
        period: The period string.
        now: Reference time for relative durations (defaults to utcnow).

    Returns:
        Tuple of (start, end) datetimes.

    Raises:
        ValueError: If the format is not recognized.
    """
    if now is None:
        now = datetime.now(UTC).replace(tzinfo=None)

    # Duration format: "30d", "7d", "24h", "4w"
    m = _DURATION_RE.match(period)
    if m:
        amount = int(m.group(1))
        unit = m.group(2).lower()
        if unit == "h":
            delta = timedelta(hours=amount)
        elif unit == "d":
            delta = timedelta(days=amount)
        elif unit == "w":
            delta = timedelta(weeks=amount)
        elif unit == "m":
            delta = timedelta(days=amount * 30)
        else:
            raise ValueError(f"Unknown duration unit: {unit}")
        return (now - delta, now)

    # Quarter format: "2026-Q1"
    m = _QUARTER_RE.match(period)
    if m:
        year = int(m.group(1))
        quarter = int(m.group(2))
        start_month = (quarter - 1) * 3 + 1
        start = datetime(year, start_month, 1)
        # End of quarter
        end_month = start_month + 2
        if end_month == 12:
            end = datetime(year + 1, 1, 1) - timedelta(seconds=1)
        else:
            end = datetime(year, end_month + 1, 1) - timedelta(seconds=1)
        return (start, end)

    # ISO date range: "2026-01-01..2026-03-31"
    if ".." in period:
        parts = period.split("..", 1)
        start = datetime.fromisoformat(parts[0].strip())
        end = datetime.fromisoformat(parts[1].strip())
        return (start, end)

    raise ValueError(
        f"Unrecognized period format: {period!r}. "
        "Use '30d', '7d', '4w', '2026-Q1', or '2026-01-01..2026-03-31'."
    )


# ---------------------------------------------------------------------------
# Audit DB loader with period support
# ---------------------------------------------------------------------------


def load_actions_from_audit_db(
    db_path: Path,
    *,
    session_id: str | None = None,
    period: tuple[datetime, datetime] | None = None,
) -> list[dict[str, Any]]:
    """Load raw audit rows from SQLite, with optional period filtering.

    Returns a list of dicts with keys matching the audit_log schema.
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    clauses: list[str] = []
    params: list[object] = []

    if session_id is not None:
        clauses.append("session_id = ?")
        params.append(session_id)

    if period is not None:
        start, end = period
        clauses.append("timestamp >= ?")
        params.append(start.isoformat())
        clauses.append("timestamp <= ?")
        params.append(end.isoformat())

    query = "SELECT * FROM audit_log"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY id"

    cursor = conn.execute(query, params)
    columns = [desc[0] for desc in cursor.description]
    rows = [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]
    conn.close()
    return rows


def _rows_to_actions(rows: list[dict[str, Any]]) -> list[tuple[Action, str, str, datetime]]:
    """Convert raw audit rows to (Action, approval, risk_level, timestamp) tuples."""
    result: list[tuple[Action, str, str, datetime]] = []
    for row in rows:
        raw_params = row.get("action_params", "{}")
        if isinstance(raw_params, str):
            try:
                parsed = json.loads(raw_params)
            except (json.JSONDecodeError, TypeError):
                parsed = {}
        else:
            parsed = raw_params or {}

        action = Action(
            type=row["action_type"],
            target=row["action_target"],
            params=parsed if isinstance(parsed, dict) else {},
            description=row.get("action_desc") or "",
            agent_id=row.get("agent_id") or "",
            parent_agent_id=row.get("parent_agent_id") or "",
            chain_id=row.get("chain_id") or "",
            chain_depth=int(row.get("chain_depth") or 0),
        )

        ts_raw = row.get("timestamp", "")
        ts = datetime.fromisoformat(ts_raw) if ts_raw else datetime.min

        result.append((action, row["approval"], row.get("risk_level", "MEDIUM"), ts))
    return result


# ---------------------------------------------------------------------------
# Change classification
# ---------------------------------------------------------------------------

_RISK_SEVERITY: dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _classify_change(old_decision: str, new_decision: str) -> str:
    """Classify the direction of a decision change."""
    if old_decision == new_decision:
        return "unchanged"
    if old_decision != "block" and new_decision == "block":
        return "newly_blocked"
    if old_decision == "block" and new_decision != "block":
        return "newly_allowed"

    old_sev = _APPROVAL_SEVERITY.get(old_decision, 0)
    new_sev = _APPROVAL_SEVERITY.get(new_decision, 0)
    if new_sev > old_sev:
        return "restricted"
    if new_sev < old_sev:
        return "promoted"
    return "unchanged"


def _risk_direction(old_risk: str, new_risk: str) -> str:
    """Classify risk level change direction."""
    old_sev = _RISK_SEVERITY.get(old_risk.upper(), 0)
    new_sev = _RISK_SEVERITY.get(new_risk.upper(), 0)
    if new_sev > old_sev:
        return "higher"
    if new_sev < old_sev:
        return "lower"
    return "same"


# ---------------------------------------------------------------------------
# PolicyImpactAnalyzer
# ---------------------------------------------------------------------------


class PolicyImpactAnalyzer:
    """Performs deep impact analysis of policy changes against audit data.

    Replays each historical action against both old and new policies,
    then aggregates results into pattern groups and risk migrations.

    Example::

        analyzer = PolicyImpactAnalyzer()
        report = analyzer.analyze(old_policy, new_policy, audit_rows)
        print(report.to_text())
    """

    def analyze(
        self,
        old_policy: Policy,
        new_policy: Policy,
        audit_rows: list[dict[str, Any]],
    ) -> ImpactReport:
        """Run full impact analysis.

        Args:
            old_policy: The current/baseline policy.
            new_policy: The proposed policy.
            audit_rows: Raw audit rows from the SQLite database
                (dicts with keys matching the audit_log schema).

        Returns:
            An :class:`ImpactReport` with summary stats, patterns,
            and risk migrations.
        """
        entries = _rows_to_actions(audit_rows)
        impacts: list[ActionImpact] = []

        for action, _original_approval, _original_risk, ts in entries:
            old_decision = old_policy.evaluate(action)
            new_decision = new_policy.evaluate(action)

            old_approval = old_decision.approval.value
            new_approval = new_decision.approval.value
            old_risk_name = old_decision.risk_level.name
            new_risk_name = new_decision.risk_level.name

            change = _classify_change(old_approval, new_approval)

            impacts.append(
                ActionImpact(
                    action_type=action.type,
                    target=action.target,
                    params=action.params,
                    agent_id=action.agent_id,
                    timestamp=ts,
                    old_decision=old_approval,
                    new_decision=new_approval,
                    old_risk=old_risk_name,
                    new_risk=new_risk_name,
                    change=change,
                )
            )

        return self._build_report(impacts)

    def analyze_from_db(
        self,
        old_policy: Policy,
        new_policy: Policy,
        db_path: Path,
        *,
        session_id: str | None = None,
        period: tuple[datetime, datetime] | None = None,
    ) -> ImpactReport:
        """Load audit rows from a SQLite DB and run impact analysis.

        Args:
            old_policy: Current policy.
            new_policy: Proposed policy.
            db_path: Path to the SQLite audit database.
            session_id: Optional session filter.
            period: Optional (start, end) time window.
        """
        rows = load_actions_from_audit_db(
            db_path,
            session_id=session_id,
            period=period,
        )
        return self.analyze(old_policy, new_policy, rows)

    def _build_report(self, impacts: list[ActionImpact]) -> ImpactReport:
        """Aggregate individual impacts into an :class:`ImpactReport`."""
        total = len(impacts)
        newly_blocked = sum(1 for i in impacts if i.change == "newly_blocked")
        newly_allowed = sum(1 for i in impacts if i.change == "newly_allowed")
        restricted = sum(1 for i in impacts if i.change == "restricted")
        promoted = sum(1 for i in impacts if i.change == "promoted")
        unchanged = sum(1 for i in impacts if i.change == "unchanged")

        # Pattern grouping for newly blocked
        blocked_counter: Counter[tuple[str, str]] = Counter()
        for i in impacts:
            if i.change == "newly_blocked":
                blocked_counter[(i.action_type, i.target)] += 1

        top_blocked = [
            PatternGroup(action_type=k[0], target=k[1], count=v)
            for k, v in blocked_counter.most_common(10)
        ]

        # Pattern grouping for newly allowed
        allowed_counter: Counter[tuple[str, str]] = Counter()
        for i in impacts:
            if i.change == "newly_allowed":
                allowed_counter[(i.action_type, i.target)] += 1

        top_allowed = [
            PatternGroup(action_type=k[0], target=k[1], count=v)
            for k, v in allowed_counter.most_common(10)
        ]

        # Risk migrations
        risk_higher = 0
        risk_lower = 0
        migration_counter: Counter[tuple[str, str]] = Counter()

        for i in impacts:
            direction = _risk_direction(i.old_risk, i.new_risk)
            if direction == "higher":
                risk_higher += 1
                migration_counter[(i.old_risk, i.new_risk)] += 1
            elif direction == "lower":
                risk_lower += 1
                migration_counter[(i.old_risk, i.new_risk)] += 1

        risk_migrations = [
            RiskMigration(from_risk=k[0], to_risk=k[1], count=v)
            for k, v in migration_counter.most_common()
        ]

        return ImpactReport(
            total_actions=total,
            newly_blocked=newly_blocked,
            newly_allowed=newly_allowed,
            restricted=restricted,
            promoted=promoted,
            unchanged=unchanged,
            top_newly_blocked_patterns=top_blocked,
            top_newly_allowed_patterns=top_allowed,
            risk_higher=risk_higher,
            risk_lower=risk_lower,
            risk_migrations=risk_migrations,
            impacts=impacts,
        )
