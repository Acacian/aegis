---
description: "Compliance Reports API: generate structured SOC2, GDPR, and governance reports from Aegis audit logs. Ready for third-party auditor review."
---

# Compliance Reports

## ReportGenerator

Generates structured compliance reports (SOC2, GDPR, governance) from audit log entries.

```python
from aegis.core.policy import Policy
from aegis.core.compliance import ReportGenerator

policy = Policy.from_yaml("policy.yaml")
gen = ReportGenerator(policy)
```

### `generate(audit_entries, report_type="governance", period_start=None, period_end=None) -> ComplianceReport`

Generate a compliance report from audit entries.

| Param | Type | Description |
|-------|------|-------------|
| `audit_entries` | `list[dict]` | Dicts matching the AuditLogger output schema |
| `report_type` | `str` | `"soc2"`, `"gdpr"`, or `"governance"` |
| `period_start` | `datetime \| None` | Start of audit period (inferred from entries if omitted) |
| `period_end` | `datetime \| None` | End of audit period (inferred from entries if omitted) |

Raises `ValueError` if `report_type` is not recognized.

```python
from aegis.runtime.audit import AuditLogger

logger = AuditLogger(db_path="aegis_audit.db")
entries = logger.get_log()
report = gen.generate(entries, report_type="soc2")
```

### `to_markdown(report) -> str`

Render a compliance report as Markdown text.

```python
md = gen.to_markdown(report)
print(md)
# # SOC2 Compliance Report
# ## Period: 2026-01-01 to 2026-03-23
# ### Summary
# ...
```

### `to_dict(report) -> dict`

Serialize a compliance report to a plain dict (JSON-safe).

```python
import json
data = gen.to_dict(report)
print(json.dumps(data, indent=2))
```

## Report Types

| Type | Description | Criteria Checked |
|------|-------------|-----------------|
| `soc2` | SOC2 Trust Services Criteria | CC6.1 Logical Access, CC6.8 Unauthorized Access, CC7.2 Monitoring, CC8.1 Change Management |
| `gdpr` | GDPR data protection | Data access logging, Right to erasure, Data minimization |
| `governance` | General governance | Policy coverage, Approval gate usage, Risk distribution, Agent behavior |

## ComplianceReport

Structured compliance report dataclass.

| Field | Type | Description |
|-------|------|-------------|
| `report_type` | `str` | `"soc2"`, `"gdpr"`, `"governance"`, or `"custom"` |
| `generated_at` | `datetime` | When the report was generated |
| `period_start` | `datetime` | Start of audit period |
| `period_end` | `datetime` | End of audit period |
| `total_actions` | `int` | Total audited actions |
| `blocked_actions` | `int` | Actions blocked by policy |
| `approved_actions` | `int` | Actions requiring human approval |
| `auto_approved` | `int` | Actions auto-approved by policy |
| `summary` | `str` | Human-readable summary |
| `findings` | `list[ComplianceFinding]` | List of findings |
| `score` | `int` | Numeric score 0--100 |
| `grade` | `str` | Letter grade `"A+"` through `"F"` |

## ComplianceFinding

A single finding within a compliance report.

| Field | Type | Description |
|-------|------|-------------|
| `severity` | `str` | `"critical"`, `"warning"`, or `"info"` |
| `category` | `str` | e.g. `"access_control"`, `"audit_trail"`, `"data_handling"` |
| `title` | `str` | Short title (includes PASS/FAIL/WARN status) |
| `description` | `str` | Detailed explanation |
| `recommendation` | `str` | Suggested remediation |

## Grading Scale

| Score | Grade |
|-------|-------|
| 97--100 | A+ |
| 93--96 | A |
| 90--92 | A- |
| 87--89 | B+ |
| 83--86 | B |
| 80--82 | B- |
| 77--79 | C+ |
| 73--76 | C |
| 70--72 | C- |
| 67--69 | D+ |
| 63--66 | D |
| 60--62 | D- |
| 0--59 | F |
