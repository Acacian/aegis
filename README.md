# Aegis

**Open-source policy & approval runtime for AI agents acting on systems you don't own.**

Aegis is a governance layer that sits between AI agents and the external systems they operate on. It provides policy-based access control, human approval gates, and a complete audit trail — so you can let agents act on Salesforce, Stripe, or any SaaS, without giving up control.

## Why Aegis?

AI agents are getting browser access via tools like Playwright, Browser Use, and Stagehand. But **who decides what they're allowed to do?**

Aegis answers that question with a simple pipeline:

```
Agent action → Policy check → Approval gate → Execute → Verify → Audit log
```

- **Policy engine**: YAML rules that classify actions by risk level (low/medium/high/critical) and set approval requirements (auto/approve/block)
- **Approval gate**: Human-in-the-loop confirmation for sensitive operations
- **Audit trail**: Every decision and result logged to SQLite for compliance and debugging
- **Adapter pattern**: Pluggable executors — Playwright included, bring your own for APIs

## Quick start

```bash
pip install aegis
```

### 1. Define a policy

```yaml
# policy.yaml
version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  - name: read_operations
    match:
      type: read
    risk_level: low
    approval: auto

  - name: bulk_update
    match:
      type: bulk_update
    risk_level: high
    approval: approve

  - name: delete_blocked
    match:
      type: delete
    risk_level: critical
    approval: block
```

### 2. Use the runtime

```python
from aegis import Action, Policy, Runtime
from aegis.adapters.playwright import PlaywrightExecutor

runtime = Runtime(
    executor=PlaywrightExecutor(),
    policy=Policy.from_yaml("policy.yaml"),
)

# Plan: evaluate actions against the policy
plan = runtime.plan([
    Action("read", target="salesforce", params={"selector": ".contacts"}),
    Action("bulk_update", target="salesforce", params={"field": "status", "value": "active"}),
    Action("delete", target="salesforce", params={"selector": "#nuke"}),
])

print(plan.summary())
#   1. [   AUTO] Action(read -> salesforce)        (risk=LOW, rule=read_operations)
#   2. [APPROVE] Action(bulk_update -> salesforce)  (risk=HIGH, rule=bulk_update)
#   3. [  BLOCK] Action(delete -> salesforce)       (risk=CRITICAL, rule=delete_blocked)

# Execute: auto-runs reads, prompts for bulk_update, blocks delete
results = await runtime.execute(plan)
```

### 3. Review the audit log

```bash
aegis audit
#   ID      Session          Action          Target     Risk   Decision     Result
# ----  -----------  ---------------  ---------------  ------  ----------  ----------
#    1  a1b2c3d4e5f6            read       salesforce     LOW       auto     success
#    2  a1b2c3d4e5f6     bulk_update       salesforce    HIGH   approved     success
#    3  a1b2c3d4e5f6          delete       salesforce CRITICAL      block     blocked
```

## Architecture

```
aegis/
  core/        Action, RiskLevel, Policy engine, Result, ExecutionPlan
  adapters/    BaseExecutor, PlaywrightExecutor
  runtime/     Runtime engine, ApprovalHandler, AuditLogger
  cli/         CLI entry point (aegis audit, aegis validate)
```

### Key concepts

| Concept | Description |
|---------|-------------|
| **Action** | A single operation an agent wants to perform (type + target + params) |
| **Policy** | YAML rules mapping action patterns to risk levels and approval requirements |
| **ExecutionPlan** | Actions evaluated against policy, ready for execution |
| **Runtime** | Orchestrator: plan -> approve -> execute -> verify -> audit |
| **Adapter** | Pluggable executor (Playwright for browsers, custom for APIs) |

### Policy rules

Rules are evaluated in order — first match wins. Each rule specifies:

- **match**: Glob patterns for `type` and `target`
- **risk_level**: `low`, `medium`, `high`, `critical`
- **approval**: `auto` (no human needed), `approve` (human must confirm), `block` (never execute)

## CLI

```bash
# Validate a policy file
aegis validate policy.yaml

# View the audit log
aegis audit
aegis audit --session abc123 --format json
```

## Adapters

### Playwright (included)

```python
from aegis.adapters.playwright import PlaywrightExecutor

executor = PlaywrightExecutor(headless=True, browser_type="chromium")
```

Supports: `navigate`, `click`, `fill`, `read`, `screenshot`

### Custom adapters

```python
from aegis.adapters.base import BaseExecutor
from aegis.core.action import Action
from aegis.core.result import Result, ResultStatus

class MyAPIExecutor(BaseExecutor):
    async def execute(self, action: Action) -> Result:
        # Your execution logic here
        return Result(action=action, status=ResultStatus.SUCCESS, data={...})
```

## Development

```bash
git clone https://github.com/Acacian/aegis.git
cd aegis
pip install -e ".[dev]"
pytest
```

## License

MIT
