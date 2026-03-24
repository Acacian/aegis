# Agent Governance Event Format (AGEF) v1

**Status:** Draft
**Version:** 1.0.0
**Date:** 2026-03-24

## What is AGEF?

AGEF (Agent Governance Event Format) is a standardized JSON schema for recording AI agent governance events. It provides a common vocabulary and structure for policy decisions, guardrail activations, approval workflows, cost tracking, and tamper-evident audit trails.

AGEF is to AI governance what SARIF is to static analysis and what CEF is to security logging: a format that makes governance data interoperable across tools, frameworks, and organizations.

## Why AGEF Exists

AI agents are being deployed in production systems that interact with databases, APIs, file systems, and external services. Multiple frameworks exist for building these agents (LangChain, CrewAI, OpenAI Agents SDK, Anthropic Claude, AutoGen), and multiple governance approaches are emerging to control them.

Today, every governance tool invents its own event format. This means:

- **No interoperability** -- governance events from one tool cannot be consumed by another
- **No aggregation** -- organizations running multiple frameworks cannot unify their audit trails
- **No ecosystem** -- SIEM vendors, compliance tools, and dashboards must build custom integrations for each governance tool
- **No comparison** -- there is no standard way to benchmark governance approaches

AGEF solves this by defining one schema that any governance tool can emit and any analysis tool can consume.

## Core Concepts

### Events

Every governance interaction produces an **event** -- a self-contained JSON object conforming to the AGEF schema. Events are immutable once created.

### Event Types

| Type | Description | Required Sections |
|------|-------------|-------------------|
| `policy_decision` | A policy engine evaluated an agent action and rendered a decision | `action`, `decision` |
| `guardrail_trigger` | A content guardrail detected something noteworthy (PII, injection, toxicity) | `guardrail` |
| `approval_request` | An action was escalated to a human for approval | `action`, `approval` |
| `approval_response` | A human responded to an approval request | `approval` |
| `cost_alert` | Token usage or cost crossed a threshold | `cost` |
| `rate_limit` | A rate limit was hit or is being approached | `rate_limit` |
| `audit_entry` | A general-purpose audit record | _(none)_ |

### Agent Identity and Lineage

The `agent` section captures not just who the agent is, but its position in a delegation chain. When Agent A delegates to Agent B which delegates to Agent C, each event records:

- `agent.id` -- the specific agent
- `agent.parent_agent_id` -- who delegated to it
- `agent.chain_id` -- the shared chain identifier
- `agent.chain_depth` -- position in the chain (0, 1, 2, ...)

This enables full reconstruction of multi-agent governance histories.

### Tamper-Evident Evidence Chain

The `evidence` section creates a hash-linked chain of events within a session:

- Each event's `evidence.hash` is computed over its canonical form
- `evidence.previous_hash` points to the preceding event's hash
- `evidence.sequence_number` provides total ordering
- An optional `evidence.signature` supports cryptographic attestation

Breaking or omitting a link in the chain is detectable, providing auditability guarantees without requiring a blockchain.

## Examples

### Policy Decision: Action Allowed

```json
{
  "agef_version": "1.0.0",
  "event_id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
  "timestamp": "2026-03-24T10:30:00.000Z",
  "event_type": "policy_decision",
  "agent": {
    "id": "sales-agent-001",
    "name": "Sales Data Agent",
    "framework": "langchain",
    "model": "gpt-4o",
    "chain_id": "chain-7890",
    "chain_depth": 0
  },
  "action": {
    "type": "db_query",
    "target": "salesforce",
    "params": {
      "query": "SELECT name, revenue FROM accounts WHERE region = 'APAC'"
    },
    "description": "Read APAC account data for quarterly report"
  },
  "decision": {
    "outcome": "allowed",
    "risk_level": "LOW",
    "rule": "read-only-salesforce",
    "reason": "Read-only Salesforce queries are auto-approved",
    "approval_required": false
  },
  "evidence": {
    "hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "previous_hash": null,
    "session_id": "session-20260324-103000",
    "sequence_number": 0
  }
}
```

### Guardrail Trigger: PII Detected and Masked

```json
{
  "agef_version": "1.0.0",
  "event_id": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
  "timestamp": "2026-03-24T10:30:05.123Z",
  "event_type": "guardrail_trigger",
  "agent": {
    "id": "support-agent-042",
    "name": "Customer Support Bot",
    "framework": "crewai",
    "model": "claude-sonnet-4-20250514"
  },
  "guardrail": {
    "name": "pii-detector-v2",
    "type": "pii_detection",
    "action": "masked",
    "details": "Detected 2 PII entities in agent response; masked before delivery",
    "severity": "high",
    "matches": [
      {
        "type": "email",
        "value_hash": "sha256:3c5e2a1d...",
        "location": { "start": 142, "end": 167 },
        "confidence": 0.98
      },
      {
        "type": "phone",
        "value_hash": "sha256:7a8b9c0d...",
        "location": { "start": 203, "end": 217 },
        "confidence": 0.95
      }
    ]
  },
  "evidence": {
    "hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "previous_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "session_id": "session-20260324-103000",
    "sequence_number": 5
  }
}
```

### Cost Alert: Budget Threshold Crossed

```json
{
  "agef_version": "1.0.0",
  "event_id": "c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f",
  "timestamp": "2026-03-24T11:15:42.789Z",
  "event_type": "cost_alert",
  "agent": {
    "id": "research-agent-007",
    "name": "Deep Research Agent",
    "framework": "openai",
    "model": "gpt-4o",
    "parent_agent_id": "orchestrator-001",
    "chain_id": "chain-research-daily",
    "chain_depth": 1
  },
  "cost": {
    "model": "gpt-4o",
    "input_tokens": 45200,
    "output_tokens": 12800,
    "total_tokens": 58000,
    "estimated_cost_usd": 0.87,
    "cumulative_cost_usd": 8.54,
    "budget_remaining_usd": 1.46,
    "budget_limit_usd": 10.00,
    "budget_utilization_pct": 85.4
  },
  "evidence": {
    "hash": "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    "previous_hash": "sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    "session_id": "session-20260324-research",
    "sequence_number": 47
  },
  "metadata": {
    "alert_type": "budget_warning",
    "threshold_pct": 80
  }
}
```

## Relationship to Existing Standards

### OpenTelemetry (OTEL)

AGEF complements OTEL, it does not replace it. OTEL traces capture *what happened* across distributed services. AGEF captures *what governance decisions were made* about AI agent actions. The `context.trace_id` and `context.span_id` fields enable direct correlation between an AGEF governance event and the OTEL span that triggered it.

### SIEM (Splunk, Sentinel, Elastic)

AGEF events are designed to be ingested by SIEM systems. The flat top-level structure, ISO 8601 timestamps, and consistent field names enable straightforward field mapping. The `event_type` field maps naturally to SIEM event categories.

### SARIF (Static Analysis Results Interchange Format)

AGEF draws inspiration from SARIF's approach: define a rich, self-describing schema that tools can emit and consumers can parse without custom adapters. Where SARIF standardized static analysis results, AGEF standardizes AI governance events.

### Cloud Events

AGEF events can be wrapped in CloudEvents envelopes for transport over event buses (Kafka, EventBridge, Pub/Sub). The `event_id`, `timestamp`, and `event_type` fields map directly to CloudEvents required attributes.

## Schema

The complete JSON Schema is available at [`schema.json`](./schema.json).

Implementations SHOULD validate events against this schema before emitting or persisting them.

## Reference Implementation

[Aegis](https://github.com/Acacian/aegis) is the reference implementation of AGEF. Aegis emits AGEF-compliant events from its policy engine, guardrail pipeline, approval workflows, and cost tracker.
