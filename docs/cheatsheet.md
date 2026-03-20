# Cheatsheet

Quick reference for common Aegis patterns.

## Install

```bash
pip install agent-aegis                  # Core only
pip install 'agent-aegis[langchain]'     # + LangChain
pip install 'agent-aegis[all]'           # Everything
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `aegis init` | Generate starter `policy.yaml` |
| `aegis validate policy.yaml` | Check policy syntax |
| `aegis schema` | Print JSON Schema (for editor autocomplete) |
| `aegis audit` | View audit log (table format) |
| `aegis audit --format json` | JSON output |
| `aegis audit --format jsonl -o out.jsonl` | Export as JSONL |
| `aegis audit --session abc123` | Filter by session |

## Policy YAML

```yaml
version: "1"
defaults:
  risk_level: medium    # low | medium | high | critical
  approval: approve     # auto | approve | block

rules:                  # First match wins
  - name: rule_name
    match:
      type: "glob*"     # Action type pattern
      target: "glob*"   # Action target pattern
    risk_level: low
    approval: auto
    conditions:          # Optional
      time_after: "09:00"
      time_before: "18:00"
      weekdays: [1, 2, 3, 4, 5]
      param_gt: { count: 100 }
      param_eq: { status: "active" }
      param_contains: { tags: "urgent" }
      param_matches: { name: "^[A-Z]" }
```

## Python API

```python
from aegis import Action, Policy, Runtime

# Create runtime
runtime = Runtime(
    executor=MyExecutor(),
    policy=Policy.from_yaml("policy.yaml"),
)

# Context manager (recommended)
async with runtime:
    # Single action
    result = await runtime.run_one(
        Action("read", "crm", params={"id": 123})
    )

    # Multiple actions
    plan = runtime.plan([
        Action("read", "crm"),
        Action("write", "crm", params={"data": "..."}),
    ])
    print(plan.summary())
    results = await runtime.execute(plan)
```

## Risk Levels

| Level | Value | Typical Use |
|-------|-------|-------------|
| `low` | 1 | Read operations |
| `medium` | 2 | Single writes |
| `high` | 3 | Bulk operations |
| `critical` | 4 | Destructive / irreversible |

## Approval Modes

| Mode | Behavior |
|------|----------|
| `auto` | Execute immediately |
| `approve` | Ask human first |
| `block` | Never execute |

## Adapters

```python
# httpx (REST APIs)
from aegis.adapters.httpx_adapter import HttpxExecutor
executor = HttpxExecutor(base_url="https://api.example.com")

# Playwright (browser)
from aegis.adapters.playwright import PlaywrightExecutor
executor = PlaywrightExecutor(headless=True)

# LangChain
from aegis.adapters.langchain import LangChainExecutor
executor = LangChainExecutor(tools=[...])

# Custom
from aegis.adapters.base import BaseExecutor
class MyExecutor(BaseExecutor):
    async def execute(self, action): ...
```

## Audit Backends

```python
# SQLite (default)
from aegis.runtime.audit import AuditLogger
audit = AuditLogger("my_audit.db")

# Python logging
from aegis.runtime.audit_logging import LoggingAuditLogger
audit = LoggingAuditLogger()

# Use with runtime
runtime = Runtime(executor=..., policy=..., audit_logger=audit)
```
