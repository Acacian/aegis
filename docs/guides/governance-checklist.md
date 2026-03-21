# AI Agent Governance Checklist

Is your AI agent production-ready? Use this checklist to audit your agent's governance posture.

## Risk Classification

- [ ] Every action type has an assigned risk level (low/medium/high/critical)
- [ ] Destructive actions (delete, drop, transfer) are classified as critical
- [ ] Read-only actions are classified as low risk
- [ ] Bulk operations have risk escalation based on volume

## Access Control

- [ ] Actions are gated by approval level (auto/approve/block)
- [ ] Critical actions require human approval before execution
- [ ] Truly dangerous actions are hard-blocked (no override possible)
- [ ] Approval decisions are logged with approver identity

## Audit Trail

- [ ] Every action is logged with timestamp, type, target, and params
- [ ] Every decision (allow/block) is logged with the matched rule
- [ ] Approval outcomes are logged (who approved, when)
- [ ] Audit logs are immutable (append-only)
- [ ] Logs can be exported for compliance review (JSONL, CSV)

## Policy Management

- [ ] Policies are declarative (YAML/JSON, not hardcoded)
- [ ] Policies can be hot-reloaded without restarting the agent
- [ ] Policy changes are version-controlled
- [ ] Policies support conditions (time-based, parameter-based)

## Framework Coverage

- [ ] Governance applies to ALL tools the agent uses, not just some
- [ ] Multiple AI providers/frameworks are covered by one policy
- [ ] Custom tools/adapters are easy to integrate

## Error Handling

- [ ] Blocked actions fail safely (no partial execution)
- [ ] Failed approvals don't leave the system in an inconsistent state
- [ ] Retry logic has exponential backoff and max attempts
- [ ] Rollback is available for failed multi-step operations

## Operational

- [ ] Governance adds minimal latency (< 5ms for auto-approved actions)
- [ ] The governance layer has no external infrastructure dependencies
- [ ] Monitoring/alerting exists for blocked actions
- [ ] The system degrades gracefully if the audit backend is unavailable

---

## How Aegis Addresses Each Item

| Checklist Item | Aegis Feature |
|---------------|---------------|
| Risk classification | 4-tier model (LOW/MEDIUM/HIGH/CRITICAL) per YAML rule |
| Access control | 3-tier approval (auto/approve/block) with 7 handler options |
| Audit trail | SQLite + JSONL + webhook + Python logging backends |
| Policy management | YAML with hot-reload, merge, JSON Schema validation |
| Framework coverage | 7 adapters (LangChain, CrewAI, OpenAI, Anthropic, MCP, Playwright, httpx) |
| Error handling | Retry with backoff, rollback, fail-safe blocking |
| Operational | < 1ms evaluation, zero external deps, batch audit |

```bash
pip install agent-aegis
```

See the [Quick Start](../getting-started/quickstart.md) to get governed in 5 minutes.
