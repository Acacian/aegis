---
description: "Meet EU AI Act requirements for AI agents with automatic audit trails, risk assessment, and compliance evidence packages. Python library, open source."
---

# EU AI Act Compliance for AI Agents

The EU AI Act (Regulation 2024/1689) requires high-risk AI systems to maintain automatic logging, risk management, and technical documentation by August 2, 2026. If you deploy AI agents that make decisions or take actions in the EU, you need tamper-evident audit trails and a way to demonstrate compliance to auditors. Aegis maps its governance features directly to EU AI Act articles and generates auditor-ready evidence packages.

## Quick Start

```bash
pip install agent-aegis
```

Run a compliance gap analysis against the EU AI Act:

```bash
aegis regulatory --framework eu-ai-act
```

This outputs a report showing which EU AI Act articles are covered by your Aegis configuration, which have partial coverage, and where gaps remain.

Add governance to your AI agent with one line:

```python
import aegis
aegis.auto_instrument()

# Every AI agent action is now:
# - Logged in a tamper-evident audit chain (Article 12)
# - Evaluated against your risk policy (Article 9)
# - Traceable with full decision context (Article 13)
```

## How It Works

### Regulatory Compliance Mapper

Aegis includes a built-in compliance mapper that covers five regulatory frameworks:

- **EU AI Act** (Regulation 2024/1689)
- **NIST AI RMF** (AI 100-1)
- **SOC2** Trust Services Criteria
- **ISO/IEC 42001:2023** (AI Management System)
- **OWASP Top 10** for Agentic Applications (2025)

The mapper evaluates your Aegis configuration against each framework's requirements and produces a gap analysis:

```python
from aegis.core.regulatory import RegulatoryMapper, RegulatoryFramework

mapper = RegulatoryMapper()
analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT)

print(f"Total requirements: {analysis.total_requirements}")
print(f"Fully covered: {analysis.fully_covered}")
print(f"Partially covered: {analysis.partially_covered}")
print(f"Gaps: {analysis.not_covered}")
print(f"Coverage score: {analysis.coverage_score:.0%}")

# Actionable recommendations
for rec in analysis.recommendations:
    print(f"  - {rec}")
```

### EU AI Act Article Mapping

| EU AI Act Article | Requirement | Aegis Feature | Coverage |
|-------------------|-------------|---------------|----------|
| **Article 9** | Risk management system | 4-tier risk model (low/medium/high/critical), YAML policy engine | Full |
| **Article 10** | Data governance | PII detection (12 categories), data masking, guardrails | Partial |
| **Article 11** | Technical documentation | Policy YAML as machine-readable docs, compliance reports | Partial |
| **Article 12** | Automatic logging | SHA-256 tamper-evident audit chain, SQLite + JSONL + SIEM export | Full |
| **Article 13** | Transparency | Decision audit trail with matched rule, risk level, full context | Full |
| **Article 14** | Human oversight | 7 approval handlers (CLI, Slack, Discord, Telegram, email, webhook, custom) | Full |
| **Article 15** | Accuracy, robustness | Prompt injection detection (109 patterns), guardrail engine | Partial |

### Tamper-Evident Audit Chain (Article 12)

The cryptographic audit chain satisfies Article 12's requirement for "automatic recording of events" that is "appropriate to the intended purpose." Each entry is SHA-256 hash-chained to the previous entry, making any tampering detectable:

```python
from aegis.core.crypto_audit import CryptoAuditChain

chain = CryptoAuditChain(storage_path="audit_chain.jsonl")

# Every governed action is automatically added to the chain
chain.append(
    agent_id="crm-agent-01",
    action_type="update_contact",
    action_target="salesforce",
    decision="auto",
    risk_level="low",
    matched_rule="allow_crm_reads",
)

# Verify chain integrity (for auditors)
result = chain.verify()
print(f"Chain valid: {result.valid}")
print(f"Entries verified: {result.verified_entries}")
print(f"Chain length: {result.chain_length}")
```

Each audit entry contains:

- Monotonically increasing sequence ID
- ISO 8601 timestamp
- Agent identifier
- Action type and target
- Governance decision and matched policy rule
- Risk level classification
- SHA-256 hash linking to previous entry
- Arbitrary metadata

### Evidence Package Generation

Export audit data in formats auditors expect:

```bash
# Full audit trail as JSONL
aegis audit --format jsonl -o evidence/audit_trail.jsonl

# Filter by date range
aegis audit --after 2026-01-01 --before 2026-06-30 --format jsonl -o evidence/h1_2026.jsonl

# Table view for quick review
aegis audit

# JSON output for programmatic processing
aegis audit --format json
```

Programmatic export:

```python
from aegis.runtime.audit import AuditLogger

logger = AuditLogger(db_path="audit.db")

# Export all entries
count = logger.export_jsonl("evidence/full_audit.jsonl")
print(f"Exported {count} audit entries")

# Query specific sessions
entries = logger.get_log(session_id="prod-agent-session-042")
```

### Risk Management System (Article 9)

Define your risk management as code:

```yaml
# policy.yaml — machine-readable risk management documentation
version: "1"

defaults:
  risk_level: high
  approval: approve

rules:
  - name: allow_reads
    match:
      type: "read_*"
    risk_level: low
    approval: auto

  - name: approve_writes
    match:
      type: "write_*"
    risk_level: medium
    approval: approve

  - name: block_deletes
    match:
      type: "delete_*"
    risk_level: critical
    approval: block

  - name: block_off_hours
    match:
      type: "*"
    conditions:
      time_after: "22:00"
    risk_level: critical
    approval: block
```

Validate the policy:

```bash
aegis validate policy.yaml
```

## Comparison

| Feature | Aegis | Manual Compliance | Enterprise Platforms |
|---------|-------|-------------------|---------------------|
| **Setup time** | Minutes (pip install + YAML) | Months of documentation | Weeks of integration |
| **Audit trail** | Automatic, tamper-evident (SHA-256) | Manual logging | Platform-specific |
| **Risk assessment** | 4-tier model in YAML | Spreadsheets and documents | Proprietary format |
| **Evidence export** | JSONL + SQLite + SIEM webhook | PDF reports | Vendor-locked format |
| **Compliance mapping** | 5 frameworks built-in | Manual cross-referencing | Framework-dependent |
| **Cost** | Free (open source, MIT) | Staff time | $10K-100K+/year |
| **Deployment** | Any Python environment | N/A | Cloud/SaaS |
| **Vendor lock-in** | None | N/A | High |

**When to use enterprise platforms:** You need SSO/SCIM, fleet-wide dashboards, and dedicated compliance staff support.

**When to use Aegis:** You need to ship EU AI Act compliance evidence quickly, without vendor lock-in, while keeping full control of your audit data.

## Key Deadlines

| Date | Milestone |
|------|-----------|
| **2025-02-02** | Prohibited AI practices enforcement begins |
| **2025-08-02** | GPAI model obligations begin |
| **2026-08-02** | **High-risk AI system requirements apply** (Articles 9-15) |
| **2027-08-02** | Full regulation enforcement for all AI systems |

The penalty for non-compliance with high-risk requirements is up to EUR 35M or 7% of global annual turnover.

## Try It Now

- [**Interactive Playground**](https://acacian.github.io/aegis/playground/) -- try Aegis in your browser, no install needed
- [**GitHub**](https://github.com/Acacian/aegis) -- source code, examples, and documentation
- [**PyPI**](https://pypi.org/project/agent-aegis/) -- `pip install agent-aegis`
