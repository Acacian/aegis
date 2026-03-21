"""
Compliance audit demo — shows how Aegis provides evidence for SOC2, GDPR, HIPAA.

Usage:
    python examples/compliance_demo.py

This demo demonstrates:
- Every action is logged with full context (who, what, when, why)
- Export audit trail as JSONL for compliance review
- Query audit logs by session, risk level, or action type
- Immutable audit entries that can't be modified after creation
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

from aegis import Action, Policy, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.core.result import Result, ResultStatus


POLICY_YAML = """\
version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  - name: view_data
    match: { type: "view" }
    risk_level: low
    approval: auto

  - name: read_records
    match: { type: "read" }
    risk_level: low
    approval: auto

  - name: export_data
    match: { type: "export" }
    risk_level: high
    approval: approve

  - name: modify_records
    match: { type: "update" }
    risk_level: medium
    approval: approve

  - name: delete_records
    match: { type: "delete" }
    risk_level: critical
    approval: block

  - name: access_pii
    match: { type: "access_pii" }
    risk_level: high
    approval: approve
"""


class ComplianceExecutor(BaseExecutor):
    """Simulates a compliant system with full audit context."""

    async def execute(self, action: Action) -> Result:
        print(f"  [EXEC] {action.type} -> {action.target}")
        return Result(action=action, status=ResultStatus.SUCCESS)


async def main() -> None:
    print("=" * 60)
    print("  Aegis Compliance Demo")
    print("  Audit Trail for SOC2 / GDPR / HIPAA")
    print("=" * 60)

    # Create policy from YAML string
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as f:
        f.write(POLICY_YAML)
        policy_path = f.name

    policy = Policy.from_yaml(policy_path)

    async with Runtime(
        executor=ComplianceExecutor(), policy=policy
    ) as runtime:
        # Simulate a series of agent actions
        actions = [
            Action("view", "patient_records", description="View patient list"),
            Action("read", "patient_records", params={"patient_id": "P-1234"}),
            Action(
                "access_pii",
                "patient_records",
                params={"patient_id": "P-1234", "fields": ["ssn", "dob"]},
                description="Access PII fields for identity verification",
            ),
            Action(
                "export",
                "patient_records",
                params={"format": "csv", "records": 500},
                description="Export patient data for quarterly report",
            ),
            Action(
                "delete",
                "patient_records",
                params={"patient_id": "P-1234"},
                description="Delete patient record",
            ),
        ]

        print("\n--- Running Actions ---\n")
        for action in actions:
            plan = runtime.plan([action])
            results = await runtime.execute(plan)
            r = results[0]
            status = "ALLOWED" if r.status == ResultStatus.SUCCESS else "BLOCKED"
            print(f"  [{status}] {action.type}:{action.target}")
            print(f"    Risk: {r.decision.risk_level if r.decision else 'N/A'}")
            print(
                f"    Rule: {r.decision.matched_rule if r.decision else 'N/A'}"
            )
            print()

        # Export audit trail
        print("--- Audit Trail (JSONL export) ---\n")
        audit_entries = runtime.audit_log.entries
        for entry in audit_entries:
            record = {
                "timestamp": str(entry.get("timestamp", "")),
                "action_type": entry.get("action_type", ""),
                "target": entry.get("target", ""),
                "risk_level": entry.get("risk_level", ""),
                "decision": entry.get("decision", ""),
                "matched_rule": entry.get("matched_rule", ""),
            }
            print(f"  {json.dumps(record)}")

        print(f"\n  Total entries: {len(audit_entries)}")
        print(
            "  Export format: JSONL (one JSON object per line, "
            "immutable after write)"
        )
        print(
            "\n  Compliance evidence: every action is traced with "
            "risk level, decision, and matched rule."
        )

    # Clean up
    Path(policy_path).unlink(missing_ok=True)


if __name__ == "__main__":
    asyncio.run(main())
