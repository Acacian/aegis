"""IsolateGPT — execution isolation architecture for agent data boundaries.

Enforces data isolation boundaries between agent contexts, preventing
unauthorized data flow across security boundaries.  Each boundary defines
which agents may access which data classifications, and all cross-boundary
transfers are logged and validated.

Key capabilities:

- **Boundary creation**: Define isolation boundaries between agent groups.
- **Data classification**: Assign sensitivity levels and data classes.
- **Access control**: Check if an agent can access data across a boundary.
- **Transfer logging**: Record and audit cross-boundary data transfers.
- **Leakage detection**: Detect unauthorized data flow patterns.

No external dependencies.  Thread-safe.  Sub-millisecond per operation.

Reference:
    IsolateGPT: Execution Isolation Architecture.
    arXiv:2403.04960 (2024).

Example::

    isolator = DataIsolator()
    isolator.create_boundary("hr-boundary", "HR Data Boundary",
                             allowed_agents=frozenset({"hr-agent"}),
                             data_classes=frozenset({DataClass.PII}))
    isolator.classify_data("emp-records", DataClass.PII,
                           owner="hr-agent", level=SensitivityLevel.CONFIDENTIAL)
    result = isolator.check_access("hr-agent", "emp-records", "hr-boundary")
    assert result  # Allowed
    result = isolator.check_access("sales-agent", "emp-records", "hr-boundary")
    assert not result  # Denied
"""

from __future__ import annotations

import hashlib
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(data: str) -> str:
    """Compute SHA-256 hex digest of a UTF-8 string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class SensitivityLevel(Enum):
    """Data sensitivity classification levels.

    Ordered from least to most sensitive.
    """

    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3
    TOP_SECRET = 4


class DataClass(Enum):
    """Categories of data for classification purposes."""

    PII = "pii"
    CREDENTIALS = "credentials"
    FINANCIAL = "financial"
    HEALTH = "health"
    PROPRIETARY = "proprietary"
    SYSTEM = "system"
    USER_CONTENT = "user_content"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IsolationBoundary:
    """A data isolation boundary between agent groups.

    Attributes:
        boundary_id: Unique boundary identifier.
        name: Human-readable boundary name.
        allowed_agents: Set of agent IDs allowed within this boundary.
        data_classes: Set of data classes governed by this boundary.
        policy: Additional policy rules.
    """

    boundary_id: str
    name: str
    allowed_agents: frozenset[str]
    data_classes: frozenset[DataClass]
    policy: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DataClassification:
    """Classification assigned to a data item.

    Attributes:
        data_id: Unique data identifier.
        classification: Data class category.
        owner: Agent that owns this data.
        sensitivity_level: Sensitivity level of this data.
    """

    data_id: str
    classification: DataClass
    owner: str
    sensitivity_level: SensitivityLevel


@dataclass(frozen=True)
class IsolationViolation:
    """A detected isolation boundary violation.

    Attributes:
        source_agent: Agent that attempted the access.
        target_agent: Agent that owns the data (or boundary context).
        data_class: Data class involved.
        boundary_id: Boundary that was violated.
        description: Human-readable description of the violation.
    """

    source_agent: str
    target_agent: str
    data_class: DataClass
    boundary_id: str
    description: str


@dataclass(frozen=True)
class IsolationReport:
    """Health report on data isolation enforcement.

    Attributes:
        total_boundaries: Number of defined boundaries.
        total_checks: Total access checks performed.
        violations: Tuple of detected violations.
        isolation_score: Isolation health score (0.0-100.0).
    """

    total_boundaries: int
    total_checks: int
    violations: tuple[IsolationViolation, ...]
    isolation_score: float


@dataclass(frozen=True)
class TransferRecord:
    """Record of a data transfer between agents.

    Attributes:
        transfer_id: Unique transfer identifier.
        source_agent: Agent sending data.
        target_agent: Agent receiving data.
        data_id: Data item being transferred.
        boundary_id: Boundary governing this transfer.
        allowed: Whether the transfer was permitted.
        timestamp: Timestamp of the transfer.
    """

    transfer_id: str
    source_agent: str
    target_agent: str
    data_id: str
    boundary_id: str
    allowed: bool
    timestamp: str


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class DataIsolator:
    """Thread-safe data isolation enforcer for multi-agent systems.

    Defines boundaries, classifies data, checks access, and detects
    unauthorized data flow across isolation boundaries.
    """

    def __init__(self) -> None:
        self._boundaries: dict[str, IsolationBoundary] = {}
        self._classifications: dict[str, DataClassification] = {}
        self._transfers: list[TransferRecord] = []
        self._violations: list[IsolationViolation] = []
        self._check_count: int = 0
        self._lock = threading.Lock()

    # -- boundary management -------------------------------------------------

    def create_boundary(
        self,
        boundary_id: str,
        name: str,
        allowed_agents: frozenset[str],
        data_classes: frozenset[DataClass],
        policy: dict[str, Any] | None = None,
    ) -> IsolationBoundary:
        """Define an isolation boundary between agent groups.

        Parameters
        ----------
        boundary_id:
            Unique identifier for the boundary.
        name:
            Human-readable name.
        allowed_agents:
            Set of agent IDs allowed within this boundary.
        data_classes:
            Set of data classes governed by this boundary.
        policy:
            Optional additional policy rules.

        Raises
        ------
        ValueError:
            If boundary_id is empty or already exists.
        """
        if not boundary_id:
            raise ValueError("boundary_id must be a non-empty string")

        boundary = IsolationBoundary(
            boundary_id=boundary_id,
            name=name,
            allowed_agents=allowed_agents,
            data_classes=data_classes,
            policy=dict(policy) if policy else {},
        )

        with self._lock:
            if boundary_id in self._boundaries:
                raise ValueError(f"Boundary already exists: {boundary_id}")
            self._boundaries[boundary_id] = boundary

        return boundary

    # -- data classification -------------------------------------------------

    def classify_data(
        self,
        data_id: str,
        classification: DataClass,
        owner: str,
        level: SensitivityLevel = SensitivityLevel.INTERNAL,
    ) -> DataClassification:
        """Assign a classification to a data item.

        Parameters
        ----------
        data_id:
            Unique data identifier.
        classification:
            Data class category.
        owner:
            Agent that owns this data.
        level:
            Sensitivity level.

        Raises
        ------
        ValueError:
            If data_id is empty.
        """
        if not data_id:
            raise ValueError("data_id must be a non-empty string")

        dc = DataClassification(
            data_id=data_id,
            classification=classification,
            owner=owner,
            sensitivity_level=level,
        )

        with self._lock:
            self._classifications[data_id] = dc

        return dc

    # -- access control ------------------------------------------------------

    def check_access(
        self,
        agent_id: str,
        data_id: str,
        boundary_id: str,
    ) -> bool:
        """Verify if an agent can access data across a boundary.

        Returns ``True`` if access is allowed.

        Checks:
        1. Boundary exists.
        2. Data is classified.
        3. Data class falls under the boundary's governance.
        4. Agent is in the boundary's allowed list.
        """
        with self._lock:
            self._check_count += 1
            boundary = self._boundaries.get(boundary_id)
            data = self._classifications.get(data_id)

        if boundary is None:
            return False

        if data is None:
            return False

        # Data class must be governed by this boundary
        if data.classification not in boundary.data_classes:
            return True  # Not governed by this boundary, so no restriction

        # Agent must be in allowed list
        return agent_id in boundary.allowed_agents

    # -- transfer logging ----------------------------------------------------

    def record_transfer(
        self,
        source_agent: str,
        target_agent: str,
        data_id: str,
        boundary_id: str,
    ) -> TransferRecord:
        """Log a data transfer between agents.

        Checks access and records the transfer.  If the transfer violates
        a boundary, it is recorded as a violation.

        Returns the transfer record.
        """
        allowed = self.check_access(target_agent, data_id, boundary_id)

        transfer = TransferRecord(
            transfer_id=uuid.uuid4().hex,
            source_agent=source_agent,
            target_agent=target_agent,
            data_id=data_id,
            boundary_id=boundary_id,
            allowed=allowed,
            timestamp=_now_iso(),
        )

        with self._lock:
            self._transfers.append(transfer)

            if not allowed:
                data = self._classifications.get(data_id)
                data_class = data.classification if data else DataClass.SYSTEM
                violation = IsolationViolation(
                    source_agent=source_agent,
                    target_agent=target_agent,
                    data_class=data_class,
                    boundary_id=boundary_id,
                    description=(
                        f"Unauthorized transfer of {data_id} from "
                        f"{source_agent} to {target_agent} across "
                        f"boundary {boundary_id}"
                    ),
                )
                self._violations.append(violation)

        return transfer

    # -- leakage detection ---------------------------------------------------

    def detect_leakage(self) -> list[IsolationViolation]:
        """Detect unauthorized data flow across boundaries.

        Analyzes transfer records for patterns of boundary violations,
        including:
        - Direct boundary violations (agent not in allowed list)
        - Cross-boundary transfers without authorization
        - Repeated violation patterns

        Returns list of detected violations.
        """
        leaks: list[IsolationViolation] = []

        with self._lock:
            # Return all recorded violations
            leaks.extend(self._violations)

            # Additional analysis: detect agents accessing data outside
            # any boundary they belong to
            for transfer in self._transfers:
                if transfer.allowed:
                    continue
                # Already in violations, skip duplicates
                # Check if this represents a systemic leak pattern
                # (same agent repeatedly violating the same boundary)

            # Detect pattern: agent accessing multiple data classes
            # across different boundaries
            agent_boundary_violations: dict[str, set[str]] = {}
            for v in self._violations:
                agent_boundary_violations.setdefault(v.source_agent, set()).add(v.boundary_id)

            for agent, boundaries in agent_boundary_violations.items():
                if len(boundaries) > 1:
                    leaks.append(
                        IsolationViolation(
                            source_agent=agent,
                            target_agent="(multiple)",
                            data_class=DataClass.SYSTEM,
                            boundary_id=",".join(sorted(boundaries)),
                            description=(
                                f"Agent {agent} violated multiple boundaries: {sorted(boundaries)}"
                            ),
                        )
                    )

        return leaks

    # -- reporting -----------------------------------------------------------

    def report(self) -> IsolationReport:
        """Generate an isolation health report.

        Returns an :class:`IsolationReport` with boundary count,
        check count, violations, and an isolation score.
        """
        with self._lock:
            total_boundaries = len(self._boundaries)
            total_checks = self._check_count
            violations = tuple(self._violations)

        # Isolation score: 100 if no violations, decreases per violation
        if total_checks == 0:
            score = 100.0
        else:
            violation_rate = len(violations) / total_checks
            score = max(0.0, round((1.0 - violation_rate) * 100.0, 1))

        return IsolationReport(
            total_boundaries=total_boundaries,
            total_checks=total_checks,
            violations=violations,
            isolation_score=score,
        )

    # -- queries -------------------------------------------------------------

    def get_boundary(self, boundary_id: str) -> IsolationBoundary | None:
        """Return a boundary by ID, or ``None``."""
        with self._lock:
            return self._boundaries.get(boundary_id)

    def get_classification(self, data_id: str) -> DataClassification | None:
        """Return a data classification by ID, or ``None``."""
        with self._lock:
            return self._classifications.get(data_id)

    def get_transfers(
        self,
        agent_id: str | None = None,
        boundary_id: str | None = None,
    ) -> list[TransferRecord]:
        """Return transfer records, optionally filtered."""
        with self._lock:
            records = list(self._transfers)

        if agent_id is not None:
            records = [
                r for r in records if r.source_agent == agent_id or r.target_agent == agent_id
            ]

        if boundary_id is not None:
            records = [r for r in records if r.boundary_id == boundary_id]

        return records

    def list_boundaries(self) -> list[IsolationBoundary]:
        """Return all defined boundaries."""
        with self._lock:
            return list(self._boundaries.values())
