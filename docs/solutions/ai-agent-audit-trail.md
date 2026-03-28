---
description: "Tamper-evident audit trail for AI agents. SHA-256 hash-chained logging to SQLite, JSONL, and SIEM. Compliance-ready evidence export."
---

# AI Agent Audit Trail: Tamper-Evident Logging for Every Action

When an AI agent deletes a production database row or sends an email to the wrong person, the first question is always: "What happened and why?" Without an audit trail, you have no visibility into what your agent did, which policy rule applied, who approved it, and when it happened. Aegis provides SHA-256 hash-chained audit logging to SQLite, JSONL, and SIEM systems, with evidence package export for compliance audits.

## Quick Start

```bash
pip install agent-aegis
```

```python
import aegis
aegis.auto_instrument()

# Every AI agent action is now automatically audit-logged:
# - What action was attempted
# - What policy rule matched
# - What the governance decision was (auto/approve/block)
# - When it happened (ISO 8601 timestamp)
# - Full action context (type, target, parameters)
```

View the audit trail:

```bash
# Table view
aegis audit

# JSON output
aegis audit --format json

# Export to JSONL for log aggregators (DataDog, ELK, CloudWatch)
aegis audit --format jsonl -o audit_export.jsonl
```

## How It Works

### Three Storage Backends

Aegis writes audit data to three backends simultaneously:

| Backend | Use Case | Format |
|---------|----------|--------|
| **SQLite** | Local storage, CLI queries, evidence packages | Structured database |
| **JSONL** | Log aggregation (DataDog, ELK, Splunk) | One JSON object per line |
| **Python logging** | Existing log infrastructure integration | Structured log records |

```python
from aegis import Policy, Runtime
from aegis.runtime.audit import AuditLogger
from aegis.adapters.base import BaseExecutor
from aegis.core.result import Result, ResultStatus


class MyExecutor(BaseExecutor):
    async def execute(self, action):
        # Your execution logic here
        return Result(action=action, status=ResultStatus.SUCCESS)


runtime = Runtime(
    executor=MyExecutor(),
    policy=Policy.from_yaml("policy.yaml"),
    audit_logger=AuditLogger(db_path="audit.db"),
)
```

### What Gets Logged

Every governance decision captures the full context:

| Field | Description | Example |
|-------|-------------|---------|
| `timestamp` | ISO 8601 UTC | `2026-03-29T10:30:00Z` |
| `session_id` | Grouping identifier | `session-abc-123` |
| `action_type` | What the agent tried to do | `delete_user` |
| `action_target` | Which system/resource | `production_db` |
| `action_params` | Full parameters (JSON) | `{"user_id": "42"}` |
| `risk_level` | Policy risk classification | `critical` |
| `matched_rule` | Which policy rule fired | `block_prod_deletes` |
| `approval` | Required approval type | `block` |
| `result_status` | Final outcome | `blocked` |
| `human_decision` | Approval outcome (if applicable) | `null` / `approved` / `denied` |

### SHA-256 Tamper-Evident Chain

For compliance-grade logging, use the cryptographic audit chain. Each entry is hash-chained to the previous one, making any tampering or deletion detectable:

```python
from aegis.core.crypto_audit import CryptoAuditChain

chain = CryptoAuditChain(storage_path="audit_chain.jsonl")

# Append an entry (returns the entry with its computed hash)
entry = chain.append(
    agent_id="sales-agent",
    action_type="update_deal",
    action_target="salesforce",
    decision="auto",
    risk_level="medium",
    matched_rule="approve_crm_writes",
    metadata={"deal_id": "DEAL-001", "amount": 50000},
)

print(f"Entry #{entry.sequence_id}")
print(f"Hash: {entry.entry_hash}")
print(f"Previous: {entry.previous_hash}")

# Verify the entire chain
result = chain.verify()
print(f"Chain intact: {result.valid}")
print(f"Entries verified: {result.verified_entries}/{result.chain_length}")
```

The chain uses SHA-256 (or SHA3-256) hashing. Each entry's hash is computed over its content concatenated with the previous entry's hash. The genesis entry uses `"0" * 64` as the previous hash. If any entry is modified, deleted, or reordered, verification fails.

### Cloud-Native Logging (SIEM Integration)

For production deployments, pipe audit data to your log aggregator:

```python
import logging
from aegis.runtime.audit_logging import LoggingAuditLogger

# Configure standard Python logging (DataDog, CloudWatch, ELK agents pick this up)
logging.basicConfig(level=logging.DEBUG)

runtime = Runtime(
    executor=MyExecutor(),
    policy=Policy.from_yaml("policy.yaml"),
    audit_logger=LoggingAuditLogger(),  # Emits structured JSON to "aegis.audit" logger
)
```

Risk levels map to log levels:

| Risk Level | Log Level |
|------------|-----------|
| `low` | `DEBUG` |
| `medium` | `INFO` |
| `high` | `WARNING` |
| `critical` | `ERROR` |

This means your existing alerting rules (e.g., "page on ERROR") automatically fire for critical governance decisions.

### Evidence Package Generation

Export audit data in the formats auditors expect:

```bash
# Full audit trail as JSONL
aegis audit --format jsonl -o evidence/audit_trail.jsonl

# Filter by session
aegis audit --session prod-agent-042 --format jsonl -o evidence/session_042.jsonl

# Table view for quick review
aegis audit

# JSON for programmatic processing
aegis audit --format json
```

Programmatic access:

```python
from aegis.runtime.audit import AuditLogger

logger = AuditLogger(db_path="audit.db")

# Get all entries
entries = logger.get_log()
for entry in entries:
    print(
        f"{entry['timestamp']} | "
        f"{entry['action_type']}@{entry['action_target']} | "
        f"{entry['result_status']}"
    )

# Filter by session
session_entries = logger.get_log(session_id="prod-agent-042")

# Export to JSONL
count = logger.export_jsonl("evidence/full_audit.jsonl")
print(f"Exported {count} entries")
```

### Audit Immutability

Aegis enforces audit immutability at the code level:

- `Result` objects are frozen after creation -- the governance decision cannot be altered after the fact
- Audit writes happen **before** the result is returned to the caller -- if logging fails, the action is not reported as successful
- The cryptographic chain makes post-hoc tampering detectable even if the attacker has filesystem access

## Comparison

| Feature | Aegis | printf / print() | Platform-Specific Logs |
|---------|-------|-------------------|----------------------|
| **Setup** | 1 line (`auto_instrument()`) | Per-action manual logging | Platform integration |
| **Tamper evidence** | SHA-256 hash chain | None | Varies |
| **Storage** | SQLite + JSONL + Python logging | stdout | Platform-locked |
| **Evidence export** | JSONL, JSON, table | Copy-paste | Vendor export format |
| **Structured data** | Full context (type, target, params, rule, decision) | Free-form strings | Varies |
| **Query by session** | Built-in | grep | Platform query language |
| **SIEM integration** | Python logging backend (DataDog, ELK, CloudWatch) | Manual | Native (if supported) |
| **Compliance mapping** | EU AI Act Art. 12, SOC2, NIST | None | Varies |
| **Chain verification** | `chain.verify()` -- one call | N/A | N/A |
| **Cost** | Free (open source, MIT) | Free | Platform pricing |

**When to use platform-specific logs:** You are already invested in a specific observability platform that provides AI agent tracing.

**When to use Aegis:** You need a self-contained, tamper-evident audit trail that works across all AI frameworks, exports to standard formats, and satisfies compliance requirements without vendor lock-in.

## Try It Now

- [**Interactive Playground**](https://acacian.github.io/aegis/playground/) -- try Aegis in your browser, no install needed
- [**GitHub**](https://github.com/Acacian/aegis) -- source code, examples, and documentation
- [**PyPI**](https://pypi.org/project/agent-aegis/) -- `pip install agent-aegis`
