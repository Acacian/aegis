---
description: "Add AI agent security in under 2 minutes. Auto-instrument your AI framework with one line of code using Aegis guardrails."
---

# Quick Start

This guide walks you through adding AI safety to your project in under 2 minutes.

## Option A: Auto-Instrument (Recommended)

The fastest way. One line governs all AI framework calls in your application.

### 1. Install

```bash
pip install agent-aegis
```

### 2. Add One Line

```python
import aegis
aegis.auto_instrument()

# Every LangChain, CrewAI, OpenAI Agents SDK, OpenAI API, and Anthropic API
# call in your application now passes through guardrails automatically.
```

Or use an environment variable (zero code changes):

```bash
AEGIS_INSTRUMENT=1 python my_agent.py
```

### 3. What Happens

Every AI call is now checked on both input and output:

- **Prompt injection** -- blocked (13 attack categories, 109 patterns)
- **Toxicity** -- blocked (harmful/abusive content)
- **PII** -- warned (12 categories: email, credit card, SSN, API keys, etc.)
- **Prompt leak** -- warned (system prompt extraction attempts)

If a guardrail blocks, `AegisGuardrailError` is raised. You can change this:

```python
# Warn instead of raising
aegis.auto_instrument(on_block="warn")

# Only log, don't interrupt
aegis.auto_instrument(on_block="log")

# Audit only, no guardrails
aegis.auto_instrument(guardrails="none")
```

### 4. Check What's Instrumented

```python
from aegis.instrument import status
print(status())
# {"active": True, "frameworks": {"langchain": {"patched": True, ...}}, "guardrails": 4}
```

---

## Option B: Policy Engine (Full Control)

For when you need YAML-based rules, approval gates, and custom executors.

### 1. Create a Policy

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

### 2. Write Your Agent Code

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

### 3. Run It

```bash
python my_agent.py
```

You'll see:

- **read** auto-executes (low risk, matches `read_operations` rule)
- **write** prompts for approval (medium risk, matches default)
- **delete** is blocked (critical risk, matches `delete_blocked` rule)

### 4. Check the Audit Log

```bash
aegis audit
```

Every action, decision, and result is recorded in `aegis_audit.db`.

## Next Steps

- [Writing Policies](../guides/policies.md) -- learn the full policy syntax
- [Integrations](../guides/integrations.md) -- connect to LangChain, CrewAI, or OpenAI
- [Custom Adapters](../guides/custom-adapters.md) -- build your own executor
