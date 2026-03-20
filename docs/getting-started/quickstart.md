# Quick Start

This guide walks you through a complete Aegis workflow in under 5 minutes.

## 1. Create a Policy

Generate a starter policy with the CLI:

```bash
aegis init
```

Or create `policy.yaml` manually:

```yaml
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

  - name: delete_blocked
    match:
      type: delete
    risk_level: critical
    approval: block
```

## 2. Write Your Agent Code

```python
import asyncio
from aegis import Action, Policy, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.core.result import Result, ResultStatus

class MyExecutor(BaseExecutor):
    async def execute(self, action):
        print(f"Executing: {action}")
        return Result(action=action, status=ResultStatus.SUCCESS)

async def main():
    runtime = Runtime(
        executor=MyExecutor(),
        policy=Policy.from_yaml("policy.yaml"),
    )

    plan = runtime.plan([
        Action("read", "salesforce", description="Fetch contacts"),
        Action("write", "salesforce", description="Update record"),
        Action("delete", "salesforce", description="Delete record"),
    ])

    print(plan.summary())
    results = await runtime.execute(plan)

    for r in results:
        print(r)

asyncio.run(main())
```

## 3. Run It

```bash
python my_agent.py
```

You'll see:

- **read** auto-executes (low risk, matches `read_operations` rule)
- **write** prompts for approval (medium risk, matches default)
- **delete** is blocked (critical risk, matches `delete_blocked` rule)

## 4. Check the Audit Log

```bash
aegis audit
```

Every action, decision, and result is recorded in `aegis_audit.db`.

## Next Steps

- [Writing Policies](../guides/policies.md) — learn the full policy syntax
- [Integrations](../guides/integrations.md) — connect to LangChain, CrewAI, or OpenAI
- [Custom Adapters](../guides/custom-adapters.md) — build your own executor
