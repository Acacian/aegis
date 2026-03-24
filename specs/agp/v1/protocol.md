# Agent Governance Protocol (AGP) v1

**Status:** Draft
**Version:** 1.0.0
**Date:** 2026-03-24

---

## 1. Abstract

The Agent Governance Protocol (AGP) defines a standard communication protocol between AI agents and governance systems. AGP provides a message-based interface through which agents declare intended actions, governance servers evaluate and respond with decisions, humans participate in approval workflows, and all interactions are recorded as tamper-evident audit trails. AGP is transport-agnostic and framework-agnostic.

## 2. Motivation

The AI agent ecosystem has matured around a critical asymmetry.

**The communication side is being standardized.** The Model Context Protocol (MCP) defines how AI agents connect to external tools, data sources, and services. MCP answers the question: *how does an AI agent interact with the external world?*

**The governance side has no standard.** Every framework implements governance differently -- or not at all. LangChain has callbacks, CrewAI has guardrails, OpenAI has usage limits, and custom agents have whatever their developers built. There is no common protocol for an external system to govern an AI agent's behavior at runtime.

These are two sides of the same coin:

| | Direction | Question | Protocol |
|---|---|---|---|
| **Communication** | Agent --> External World | "How do I call this tool?" | MCP |
| **Governance** | External World --> Agent | "Should you be allowed to?" | **AGP** |

Without a governance protocol, organizations face a dilemma: govern agents using framework-specific mechanisms (creating vendor lock-in and coverage gaps) or build custom governance layers for each framework (creating maintenance burden and inconsistency).

AGP resolves this by defining one protocol that any agent framework can implement and any governance system can serve. An agent that speaks AGP can be governed by any AGP-compatible governor. A governance policy written for AGP works across all AGP-compatible agents.

## 3. Architecture

```
                         AGP Messages
 ┌───────────────┐  ──────────────────────►  ┌───────────────────┐
 │               │  action.declare            │                   │
 │    Agent      │  guardrail.check           │    Governor       │
 │    (Client)   │                            │    (Server)       │
 │               │  ◄──────────────────────  │                   │
 │               │  action.evaluate           │                   │
 │               │  guardrail.result          │                   │
 └───────────────┘                            └─────────┬─────────┘
                                                        │
                                              ┌─────────▼─────────┐
                       approval.request       │                   │
                    ──────────────────────►    │   Human / UI      │
                       approval.response      │   (Approver)      │
                    ◄──────────────────────   │                   │
                                              └───────────────────┘
                                                        │
                                              ┌─────────▼─────────┐
                       evidence.record        │                   │
                    ──────────────────────►    │  Evidence Store   │
                                              │  (Audit Trail)    │
                                              └───────────────────┘
```

### 3.1 Roles

**Agent Client.** Any AI agent that integrates AGP. The agent MUST declare actions to the Governor before executing them. The agent MUST respect the Governor's decisions. An agent that ignores a `blocked` decision is non-compliant.

**Governor Server.** The governance system that evaluates agent actions against policies. The Governor receives action declarations, evaluates them against configured rules, and returns decisions. It may escalate decisions to a human approver. The Governor MUST record all interactions as evidence.

**Human Approver.** A human participant in the approval workflow. The Governor routes escalated decisions to the approver via the `approval.request` message. The approver's `approval.response` is relayed back to the agent through the Governor.

**Evidence Store.** A persistent, append-only store of governance events. The Governor writes `evidence.record` messages containing AGEF-formatted events. The evidence store MUST preserve ordering and SHOULD support tamper detection via hash chains.

### 3.2 Lifecycle of a Governed Action

```
Agent                     Governor                  Human           Evidence Store
  │                          │                        │                  │
  │  action.declare          │                        │                  │
  │─────────────────────────►│                        │                  │
  │                          │ evaluate policy        │                  │
  │                          │───────┐                │                  │
  │                          │◄──────┘                │                  │
  │                          │                        │                  │
  │                          │  [if escalated]        │                  │
  │                          │  approval.request      │                  │
  │                          │───────────────────────►│                  │
  │                          │  approval.response     │                  │
  │                          │◄───────────────────────│                  │
  │                          │                        │                  │
  │  action.evaluate         │                        │                  │
  │◄─────────────────────────│                        │                  │
  │                          │                        │                  │
  │  [execute or abort]      │  evidence.record       │                  │
  │                          │───────────────────────────────────────────►│
  │                          │                        │                  │
```

## 4. Message Types

All AGP messages are JSON objects. Every message includes a `type` field indicating the message type and a `correlation_id` field for request-response matching.

### 4.1 `action.declare`

**Direction:** Agent --> Governor
**Purpose:** The agent declares its intent to perform an action and requests a governance decision.

```json
{
  "type": "action.declare",
  "correlation_id": "uuid",
  "timestamp": "ISO 8601",
  "agent": {
    "id": "string",
    "name": "string",
    "framework": "string",
    "model": "string",
    "chain_id": "string",
    "chain_depth": 0
  },
  "action": {
    "type": "string",
    "target": "string",
    "params": {},
    "description": "string"
  }
}
```

The agent MUST NOT execute the declared action until it receives an `action.evaluate` response with a permissive outcome.

### 4.2 `action.evaluate`

**Direction:** Governor --> Agent
**Purpose:** The Governor communicates its governance decision for a previously declared action.

```json
{
  "type": "action.evaluate",
  "correlation_id": "uuid (matches action.declare)",
  "timestamp": "ISO 8601",
  "decision": {
    "outcome": "allowed | blocked | masked | warned | escalated",
    "risk_level": "LOW | MEDIUM | HIGH | CRITICAL",
    "rule": "string",
    "reason": "string",
    "approval_required": false
  },
  "constraints": {
    "timeout_seconds": 30,
    "max_retries": 1,
    "required_params": {},
    "forbidden_params": []
  }
}
```

If `outcome` is `escalated`, the agent MUST wait for a subsequent `action.evaluate` message after the human approval workflow completes.

### 4.3 `approval.request`

**Direction:** Governor --> Human Approver
**Purpose:** The Governor routes an action that requires human approval.

```json
{
  "type": "approval.request",
  "correlation_id": "uuid",
  "timestamp": "ISO 8601",
  "request_id": "uuid",
  "agent": { "..." },
  "action": { "..." },
  "decision": {
    "risk_level": "HIGH",
    "rule": "string",
    "reason": "string"
  },
  "timeout_seconds": 300
}
```

### 4.4 `approval.response`

**Direction:** Human Approver --> Governor
**Purpose:** The human communicates their approval decision.

```json
{
  "type": "approval.response",
  "correlation_id": "uuid",
  "request_id": "uuid (matches approval.request)",
  "timestamp": "ISO 8601",
  "approver": "string",
  "decision": "approved | denied",
  "reason": "string (optional)"
}
```

Upon receiving this message, the Governor MUST send a final `action.evaluate` to the agent with the resolved outcome.

### 4.5 `guardrail.check`

**Direction:** Agent --> Governor
**Purpose:** The agent submits content for guardrail inspection before using it.

```json
{
  "type": "guardrail.check",
  "correlation_id": "uuid",
  "timestamp": "ISO 8601",
  "agent": { "..." },
  "content": "string",
  "content_type": "prompt | response | tool_input | tool_output",
  "guardrails": ["pii_detection", "injection_detection"]
}
```

The optional `guardrails` array allows the agent to request specific guardrail checks. If omitted, all configured guardrails are run.

### 4.6 `guardrail.result`

**Direction:** Governor --> Agent
**Purpose:** The Governor returns the results of guardrail inspection.

```json
{
  "type": "guardrail.result",
  "correlation_id": "uuid (matches guardrail.check)",
  "timestamp": "ISO 8601",
  "passed": true,
  "results": [
    {
      "guardrail": "pii-detector",
      "action": "masked",
      "details": "2 PII entities detected and masked",
      "severity": "high"
    }
  ],
  "transformed_content": "string or null"
}
```

If any guardrail produced a `masked` action, `transformed_content` contains the sanitized version. The agent SHOULD use `transformed_content` in place of the original.

### 4.7 `evidence.record`

**Direction:** Governor --> Evidence Store
**Purpose:** Persist an AGEF-formatted governance event.

```json
{
  "type": "evidence.record",
  "timestamp": "ISO 8601",
  "event": {
    "<<< Full AGEF event object >>>"
  }
}
```

The event payload conforms to the [AGEF v1 schema](../agef/v1/schema.json). The evidence store MUST persist the event and SHOULD validate it against the schema.

## 5. Transport

AGP is transport-agnostic. The protocol defines message semantics, not transport mechanisms. Implementations may use any transport that supports ordered, reliable delivery of JSON messages.

### 5.1 Reference Transports

| Transport | Use Case | Notes |
|-----------|----------|-------|
| **In-process** | Same-process governance (library mode) | Direct function calls. Lowest latency. Used by Aegis core. |
| **HTTP** | Microservice governance | POST to `/agp/v1/{message_type}`. Standard REST semantics. |
| **WebSocket** | Real-time bidirectional governance | Single persistent connection. Supports streaming approval workflows. |
| **gRPC** | High-throughput production systems | Protocol buffer encoding. Streaming RPCs for approval workflows. |
| **Message Queue** | Async governance with guaranteed delivery | Kafka, RabbitMQ, SQS. Best for audit-heavy workloads. |

### 5.2 Transport Requirements

Any AGP transport implementation MUST provide:

1. **Ordered delivery** -- Messages within a correlation_id MUST be delivered in order.
2. **At-least-once delivery** -- Messages MUST NOT be silently dropped.
3. **Correlation** -- The transport MUST support matching responses to requests via `correlation_id`.
4. **Timeout** -- The transport MUST support configurable timeouts for request-response pairs.

## 6. Error Handling

### 6.1 Governor Unavailable

If the agent cannot reach the Governor, the agent MUST apply its **fail-safe policy**:

- **fail-closed** (RECOMMENDED): Block all actions until the Governor is reachable.
- **fail-open**: Allow actions but log locally for later reconciliation.

The fail-safe mode MUST be configured explicitly. There is no default -- implementations MUST require the deployer to choose.

### 6.2 Timeout

If the Governor does not respond within the configured timeout:

1. The agent applies the fail-safe policy.
2. The Governor SHOULD record the timeout as an AGEF `audit_entry` event when it recovers.

### 6.3 Invalid Messages

Recipients of invalid messages MUST respond with an error and MUST NOT silently ignore them:

```json
{
  "type": "error",
  "correlation_id": "uuid",
  "code": "INVALID_MESSAGE | UNKNOWN_TYPE | SCHEMA_VIOLATION | INTERNAL_ERROR",
  "message": "Human-readable error description"
}
```

## 7. Security Considerations

### 7.1 Agent Authentication

Agents MUST authenticate to the Governor. The protocol does not mandate a specific authentication mechanism, but implementations SHOULD support:

- API keys (for development)
- mTLS (for production)
- OAuth 2.0 / OIDC tokens (for multi-tenant deployments)

### 7.2 Message Integrity

All messages SHOULD be transmitted over TLS. For high-assurance deployments, individual messages MAY include cryptographic signatures in the AGEF `evidence.signature` field.

### 7.3 Evidence Tamper Detection

The AGEF evidence hash chain provides tamper detection. Consumers of the audit trail SHOULD verify the hash chain on read. A broken chain indicates either data corruption or tampering.

### 7.4 Sensitive Data

Action parameters MAY contain sensitive data (credentials, PII, financial data). Implementations MUST support configurable redaction of `action.params` before evidence recording. The AGEF `guardrail.input_content_hash` field supports correlation without storing raw sensitive content.

## 8. Relationship to MCP

AGP and MCP are complementary protocols that together provide complete governance for AI agents interacting with external systems.

```
                              ┌──────────────────────────┐
                              │     AI Agent Runtime      │
                              │                          │
                              │  ┌────────┐ ┌────────┐  │
                              │  │  MCP   │ │  AGP   │  │
                              │  │ Client │ │ Client │  │
                              │  └───┬────┘ └───┬────┘  │
                              └──────┼──────────┼───────┘
                                     │          │
                    "What tools       │          │    "Am I allowed to
                     are available?"  │          │     call this tool?"
                                     │          │
                              ┌──────▼────┐ ┌───▼──────────┐
                              │   MCP     │ │   AGP        │
                              │   Server  │ │   Governor   │
                              │  (Tools)  │ │  (Policies)  │
                              └───────────┘ └──────────────┘
```

**MCP** provides the capabilities: "Here are the tools you can use and how to call them."
**AGP** provides the constraints: "Here is whether you are allowed to use them, under what conditions, and with what oversight."

A governed MCP interaction looks like this:

1. Agent discovers a tool via MCP.
2. Agent prepares to call the tool.
3. Agent sends `action.declare` via AGP to the Governor.
4. Governor evaluates the action and responds via `action.evaluate`.
5. If allowed, the agent calls the tool via MCP.
6. Governor records the decision and outcome via `evidence.record`.

AGP does not require MCP. Agents that use direct API calls, custom tool frameworks, or no tools at all can still be governed via AGP. The protocols are independent but synergistic.

## 9. Relationship to AGEF

AGP messages describe the *communication* between agents and governors. AGEF events describe the *records* of what happened.

Every governance interaction that flows through AGP produces one or more AGEF events that are persisted via `evidence.record` messages. AGEF is the data format; AGP is the communication protocol.

| Aspect | AGP | AGEF |
|--------|-----|------|
| **What** | Message protocol | Event schema |
| **When** | Runtime communication | Persistent records |
| **Who** | Agent <--> Governor | Anyone reading the audit trail |
| **Where** | In-flight (transient) | Evidence store (permanent) |

## 10. Conformance Levels

Implementations MAY claim conformance at one of three levels:

### Level 1: Basic

- Supports `action.declare` / `action.evaluate` message exchange
- Records AGEF `policy_decision` events
- Implements fail-safe policy

### Level 2: Standard

- Level 1, plus:
- Supports `approval.request` / `approval.response` workflow
- Supports `guardrail.check` / `guardrail.result`
- Records all seven AGEF event types
- Implements evidence hash chains

### Level 3: Full

- Level 2, plus:
- Supports multi-agent chain governance (chain_id, chain_depth)
- Supports cost tracking and budget enforcement
- Supports cryptographic evidence signatures
- Passes the AGP conformance test suite

## 11. Reference Implementation

[Aegis](https://github.com/Acacian/aegis) is the reference implementation of AGP.

Aegis implements AGP Level 3 (Full) with:

- In-process transport (library mode) for zero-latency governance
- HTTP and WebSocket transports for distributed deployments
- YAML-based policy engine as the Governor
- SQLite and streaming evidence stores
- Adapters for LangChain, CrewAI, OpenAI Agents SDK, and Anthropic Claude
- Built-in guardrails for PII detection, prompt injection, and custom patterns
- Multi-agent cost attribution and budget enforcement

## 12. Future Work

- **AGP Discovery:** A mechanism for agents to discover available Governor endpoints, analogous to MCP's server discovery.
- **Policy Distribution:** A standard format for distributing governance policies across Governor instances.
- **Federation:** Protocol extensions for cross-organization governance, enabling governed agent-to-agent communication across trust boundaries.
- **Conformance Test Suite:** A reference test suite that implementations can run to verify AGP conformance at each level.

---

*AGP is an open specification. Contributions and feedback are welcome at [github.com/Acacian/aegis](https://github.com/Acacian/aegis).*
