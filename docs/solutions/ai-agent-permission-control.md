---
description: "Control what AI agents can do at runtime. Declarative allow/deny/approve rules per action, tool, agent, and time window with human-in-the-loop review."
---

# AI Agent Permission Control: Allow, Deny, and Approve at Runtime

AI agents call tools, access databases, send messages, and modify files. Without permission control, every agent runs with full access to every tool — and a single prompt injection can turn that access into data exfiltration, unauthorized purchases, or destructive operations. Aegis enforces fine-grained permissions at runtime: declare which actions are allowed, denied, or require human approval — per agent, per tool, per time window.

## Quick Start

```bash
pip install agent-aegis
```

### Define Permissions in YAML

```yaml
# policy.yaml
version: "1"
defaults:
  risk_level: medium
  approval: approve          # Default: require human approval

rules:
  # Read operations — auto-approve
  - name: read_safe
    match: { type: "read*" }
    risk_level: low
    approval: auto

  # Write to database — require approval
  - name: db_write
    match: { type: "write*", target: "database" }
    risk_level: high
    approval: approve

  # Send external messages — block entirely
  - name: no_external_send
    match: { type: "send*", target: "external_*" }
    risk_level: critical
    approval: block

  # Bulk operations over 100 items — block
  - name: bulk_block
    match: { type: "bulk_*" }
    conditions:
      param_gt: { count: 100 }
    risk_level: critical
    approval: block

  # No deploys on weekends
  - name: weekday_deploys
    match: { type: "deploy*" }
    conditions:
      weekdays: [1, 2, 3, 4, 5]
    approval: approve
```

### Enforce in Python

```python
import aegis
aegis.auto_instrument()

# That's it. Every LangChain, CrewAI, OpenAI Agents SDK call
# now passes through your permission rules automatically.
```

Or apply permissions manually:

```python
from aegis.core import Policy, Action

policy = Policy.from_yaml("policy.yaml")
action = Action(type="send_email", target="external_api", params={"to": "user@example.com"})
decision = policy.evaluate(action)

if not decision.is_allowed:
    print(f"Blocked: {decision.rule_name} — {decision.approval}")
```

## Three Permission Levels

Aegis uses three permission states — not just allow/deny:

| Level | Behavior | Use Case |
|-------|----------|----------|
| **`auto`** | Execute immediately, no human involvement | Read operations, navigation, safe queries |
| **`approve`** | Pause execution, request human approval | Write operations, API calls, form submissions |
| **`block`** | Never execute, regardless of approval | Destructive operations, JavaScript eval, data exfiltration patterns |

This three-level model means you don't have to choose between "let the agent do everything" and "block everything." Most production deployments use all three: auto-approve safe operations for speed, require approval for sensitive ones, and hard-block dangerous patterns.

## Permission Matching

### Action Type Matching (Glob Patterns)

```yaml
rules:
  - name: block_all_deletes
    match: { type: "delete*" }      # Matches delete, delete_user, delete_file
    approval: block

  - name: allow_reads
    match: { type: "read" }          # Exact match only
    approval: auto
```

### Target-Based Matching

```yaml
rules:
  - name: protect_production_db
    match: { type: "write*", target: "prod_*" }
    approval: block

  - name: staging_writes_ok
    match: { type: "write*", target: "staging_*" }
    approval: auto
```

### Agent-Specific Permissions

```yaml
rules:
  - name: researcher_read_only
    match: { type: "*", agent: "researcher_*" }
    approval: auto
    conditions:
      param_matches: { action_category: "read" }

  - name: deployer_can_deploy
    match: { type: "deploy*", agent: "deployer" }
    approval: approve
```

### Conditional Permissions (Time, Parameters)

```yaml
rules:
  # Block writes after business hours
  - name: after_hours_block
    match: { type: "write*" }
    conditions:
      time_after: "18:00"
    approval: block

  # Block large batch operations
  - name: batch_size_limit
    match: { type: "batch_*" }
    conditions:
      param_gt: { batch_size: 1000 }
    approval: block
```

## Human-in-the-Loop Approval

When a rule requires `approve`, Aegis pauses execution and sends an approval request through your configured handler:

```python
from aegis.runtime.approval import SlackApprovalHandler
from aegis.runtime.engine import Runtime
from aegis.core import Policy

policy = Policy.from_yaml("policy.yaml")
handler = SlackApprovalHandler(
    webhook_url="https://hooks.slack.com/...",
    channel="#agent-approvals",
    timeout=300,  # 5 minute timeout
)
runtime = Runtime(policy=policy, approval_handler=handler)
```

**Available approval handlers** (`src/aegis/runtime/approval.py`):

| Handler | Channel |
|---------|---------|
| `CLIApprovalHandler` | Interactive terminal prompt |
| `SlackApprovalHandler` | Slack message with approve/deny buttons |
| `EmailApprovalHandler` | Email with approval link |
| `DiscordApprovalHandler` | Discord DM |
| `TelegramApprovalHandler` | Telegram message |
| `WebhookApprovalHandler` | Any HTTP endpoint |
| `CallbackApprovalHandler` | Custom async function |

## Agent Identity and Capability Delegation

Aegis tracks agent identity and enforces capability-based access control — agents can only perform actions within their declared capabilities:

```python
from aegis.core.agent_identity import AgentIdentity, AgentRegistry

registry = AgentRegistry()

# Register agents with explicit capabilities
orchestrator = AgentIdentity(
    agent_id="orchestrator",
    capabilities=frozenset(["read_*", "write_*", "deploy_*"]),
    trust_level=90,
)
registry.register(orchestrator)

# Delegate with least privilege — child gets intersection of parent's capabilities
worker = AgentIdentity(
    agent_id="data_worker",
    capabilities=frozenset(["read_*", "write_db"]),
    trust_level=60,
)
delegated = registry.delegate("orchestrator", worker)
# delegated.capabilities = {"read_*", "write_db"} (intersection)
# delegated.trust_level = 60 (minimum of parent and child)
```

## Policy Hierarchy (Org → Team → Agent)

Layer permissions so organizational policies always take precedence:

```python
from aegis.core.hierarchy import PolicyHierarchy

hierarchy = PolicyHierarchy()
hierarchy.add_layer("org", org_policy, priority=0)       # Highest priority
hierarchy.add_layer("team", team_policy, priority=1)
hierarchy.add_layer("agent", agent_policy, priority=2)    # Lowest priority

# BLOCK at org level cannot be overridden by team or agent policies
decision = hierarchy.evaluate(action)
```

This ensures security teams can set hard boundaries that individual agents or teams cannot weaken.

## Multi-Step Attack Detection

Individual permissions aren't enough — Aegis also detects dangerous sequences across multiple actions:

```yaml
plan_rules:
  sequence_patterns:
    # Block read-then-send patterns (data exfiltration)
    - name: data_exfiltration
      steps: ["read_*", "send_*"]
      window: 5
      approval: block
      risk_level: critical

    # Block credential access followed by external calls
    - name: credential_theft
      steps: ["read_credentials", "http_*"]
      window: 3
      approval: block
      risk_level: critical
```

Even if `read_credentials` and `http_post` are individually allowed, the sequence triggers a block — because the combination signals exfiltration.

## MCP Tool Permission Control

For MCP (Model Context Protocol) servers, Aegis adds a security layer that standard MCP lacks:

```python
from aegis.core.mcp_security import MCPSecurityGate

gate = MCPSecurityGate()

# Scans tool descriptions for hidden malicious instructions
scan_result = gate.scan_tool(tool_definition)

# Detects tool definition changes between sessions (rug pull attacks)
change_result = gate.detect_changes(previous_tools, current_tools)

# Sanitizes arguments to prevent path traversal and command injection
sanitized = gate.sanitize_arguments(tool_name, arguments)
```

**MCP Consent Protocol** — require explicit consent for high-risk MCP tool calls:

```python
from aegis.core.mcp_consent import MCPConsentManager, ConsentRule

consent = MCPConsentManager(rules=[
    ConsentRule(tool_pattern="file_*", action="approve"),
    ConsentRule(tool_pattern="database_delete*", action="block"),
])
```

## Audit Trail

Every permission decision is logged immutably — who requested what, which rule matched, whether it was allowed, and who approved it:

```python
from aegis.core.audit import AuditLogger

logger = AuditLogger(backend="sqlite", path="audit.db")

# Query audit trail
entries = logger.query(
    action_type="delete*",
    approval="block",
    time_range=("2025-01-01", "2025-12-31"),
)
```

Use `aegis plan` to preview how permission changes would affect past decisions:

```bash
aegis plan current.yaml proposed.yaml --audit-db audit.db
```

## Framework Integration

Aegis auto-instruments these frameworks — permission control works without code changes:

| Framework | Method |
|-----------|--------|
| **LangChain** | `aegis.auto_instrument()` or `AEGIS_INSTRUMENT=1` |
| **CrewAI** | `aegis.auto_instrument()` or `AEGIS_INSTRUMENT=1` |
| **OpenAI Agents SDK** | `aegis.auto_instrument()` or `AEGIS_INSTRUMENT=1` |
| **OpenAI API** | `aegis.auto_instrument()` or `AEGIS_INSTRUMENT=1` |
| **Anthropic API** | `aegis.auto_instrument()` or `AEGIS_INSTRUMENT=1` |
| **MCP Servers** | `MCPSecurityGate` + policy rules |

## What Makes Aegis Different

| Feature | Aegis | Guardrails AI | NeMo Guardrails |
|---------|-------|---------------|-----------------|
| **Permission model** | Allow / Approve / Block | Validate output | Conversational rails |
| **Scope** | Actions, tools, data access | LLM output text | Conversation flow |
| **Human-in-the-loop** | 7 built-in handlers | No | No |
| **Agent identity** | Capability-based delegation | No | No |
| **Multi-step detection** | Sequence patterns | No | No |
| **Policy hierarchy** | Org → Team → Agent | No | No |
| **MCP security** | Tool scanning, consent, sanitization | No | No |
| **Runtime overhead** | Sub-millisecond (deterministic) | LLM-dependent | LLM-dependent |

## Next Steps

- [Quick Start](../getting-started/quickstart.md) — Add permissions to your project in 30 seconds
- [Writing Policies](../guides/policies.md) — Full policy syntax reference
- [Approval Handlers](../guides/approval-handlers.md) — Configure human-in-the-loop
- [Policy Patterns](../guides/policy-patterns.md) — Common permission patterns
- [MCP Governance](../guides/mcp-governance.md) — Secure MCP tool calls
