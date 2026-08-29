---
description: "Build vs buy AI agent guardrails: how 30+ lines of scattered if/else checks become 2 lines with Aegis. Compare time, maintenance, and coverage."
---

# DIY Guardrails vs Aegis: Build vs Buy for AI Agent Security

## TL;DR

Every team starts with hand-rolled `if/else` checks. They work for prototypes. But as your agent grows -- more tools, more frameworks, compliance requirements, team handoffs -- DIY governance becomes a maintenance burden. Aegis replaces scattered checks with a single YAML policy and two lines of code.

## What DIY Looks Like

DIY governance means writing custom checks directly in your agent code. It typically starts simple and grows organically.

**Common patterns:**

- `if/else` blocks before each tool call
- Custom logging scattered across the codebase
- Ad-hoc approval flows (Slack messages, email confirmations)
- Per-framework wrappers that do similar things differently
- Environment-variable-based feature flags for enabling/disabling checks

**Where DIY works well:**

- Single tool, single framework, single developer
- Prototype or internal demo with no compliance requirements
- Very specific business logic that no library would cover
- You need full control and have time to maintain it

**Where DIY breaks down:**

- Multiple tools and frameworks -- each needs its own checks
- Audit trail requirements -- you have to build logging, storage, and export
- Human approval -- Slack/email integration is a project in itself
- Team growth -- new developers need to understand scattered checks
- Compliance -- auditors want structured evidence, not `grep` through git history

## What Aegis Does

Aegis replaces scattered `if/else` checks with a centralized YAML policy that applies to all frameworks.

**What you get out of the box:**

- YAML policy engine with glob matching and conditional rules
- 4-tier risk model (low / medium / high / critical)
- Auto-instrumentation for LangChain, CrewAI, OpenAI Agents SDK, OpenAI, Anthropic
- Runtime guardrails: prompt injection (109 patterns), PII (12 categories), toxicity, prompt leak
- 7 approval handlers (CLI, Slack, Discord, Telegram, email, webhook, custom)
- Audit trail with SQLite, JSONL, webhook, and Python logging backends
- Sub-millisecond policy evaluation, no LLM dependency

## The 30-Lines-to-2-Lines Comparison

Here is a typical DIY approach for governing a CRM agent:

```python
# DIY: 30+ lines, scattered across your codebase

import logging
from datetime import datetime

logger = logging.getLogger("agent_audit")

async def governed_tool_call(action, target, params):
    # Block dangerous operations
    if action == "delete" and "all" in target:
        logger.warning(f"BLOCKED: {action} {target}")
        raise PermissionError(f"Bulk delete blocked: {target}")

    # Require approval for writes to production
    if action in ("update", "create") and "prod" in target:
        logger.info(f"APPROVAL NEEDED: {action} {target}")
        approved = await ask_for_approval_somehow(action, target)
        if not approved:
            logger.warning(f"DENIED: {action} {target}")
            raise PermissionError("Not approved")

    # Block after-hours operations
    hour = datetime.now().hour
    if action == "transfer" and (hour < 9 or hour > 17):
        logger.warning(f"BLOCKED: {action} outside business hours")
        raise PermissionError("Transfers blocked outside 9-17")

    # Log everything (but where? how? what format?)
    logger.info(f"ALLOWED: {action} {target} {params}")

    # Actually execute
    return await execute(action, target, params)

# And you need to wrap every framework separately...
# LangChain tools? Write a callback handler.
# CrewAI? Write a hook.
# OpenAI Agents? Write a runner wrapper.
# Each one reimplements the same logic slightly differently.
```

The same governance with Aegis:

```python
# Aegis: 2 lines in your code + 1 YAML file

import aegis
aegis.auto_instrument()
```

```yaml
# policy.yaml
rules:
  - name: block_bulk_delete
    match: { type: delete, target: "*all*" }
    approval: block

  - name: approve_prod_writes
    match: { type: "{update,create}", target: "prod_*" }
    approval: approve
    risk: high

  - name: block_after_hours_transfers
    match: { type: transfer }
    conditions:
      - { field: time_after, value: "17:00" }
      - { field: time_before, value: "09:00" }
    approval: block

  - name: allow_reads
    match: { type: "{get,list,read}" }
    approval: auto
    risk: low
```

## Side-by-Side Comparison

| Aspect | DIY (`if/else`) | Aegis |
|--------|-----------------|-------|
| **Time to implement** | Hours to days (per framework) | Minutes (one-time setup) |
| **Lines of code** | 30+ per framework, growing | 2 lines + YAML policy |
| **Policy location** | Scattered across codebase | Single YAML file |
| **Adding a new rule** | Find all check points, add code, redeploy | Add a line to YAML |
| **Removing a rule** | Find and delete scattered checks | Delete a line from YAML |
| **Multi-framework** | Rewrite checks per framework | One policy covers all frameworks |
| **Human approval** | Build your own (Slack API, email, etc.) | 7 built-in handlers |
| **Audit trail** | Build your own (logging, storage, export) | Built-in (SQLite, JSONL, webhook, logging) |
| **Prompt injection detection** | Write your own regex or call an LLM | Built-in (109 patterns, 13 categories) |
| **PII detection** | Write your own or find a library | Built-in (12 categories) |
| **Conditional rules** | Implement each condition type | Built-in (`time_after`, `time_before`, `weekdays`, `param_gt/lt/eq/contains/matches`) |
| **Risk levels** | Define your own classification | Built-in 4-tier model (low/medium/high/critical) |
| **Compliance readiness** | Depends on your logging | Auditor-ready evidence export |
| **Maintenance** | You maintain all check logic | Community-maintained, tested (3,860+ tests) |
| **Type safety** | Depends on your implementation | `mypy --strict` clean |
| **Testing** | Write your own tests for each check | Tested upstream (3,860+ tests) |
| **Cost** | Your engineering time | Free, open-source (MIT) |

## When to Stick with DIY

DIY is the right choice when:

- You have a **single tool** with **one or two checks** -- the overhead of a library is not worth it
- Your checks encode **complex business logic** that is specific to your domain and not expressible as pattern/condition rules
- You are building a **throwaway prototype** with no plans for production
- You have **no audit trail or compliance requirements**
- You enjoy building infrastructure and have the time budget for it

## When to Switch to Aegis

Consider Aegis when any of these become true:

- You are governing **more than one tool or framework**
- You need an **audit trail** for debugging or compliance
- You need **human approval** for sensitive operations
- **Multiple developers** work on the agent and need to understand the governance rules
- You want to **change policies without code changes** (edit YAML, not Python)
- You are spending **more time on governance code than on your actual agent**

The migration is straightforward -- your existing `if/else` logic maps directly to YAML rules:

| DIY Pattern | Aegis YAML Equivalent |
|------------|----------------------|
| `if action == "delete": raise` | `match: { type: delete }` + `approval: block` |
| `if "prod" in target: get_approval()` | `match: { target: "prod_*" }` + `approval: approve` |
| `if hour < 9: raise` | `conditions: [{ field: time_before, value: "09:00" }]` |
| `if amount > 10000: get_approval()` | `conditions: [{ field: param_gt, param: amount, value: 10000 }]` |

## Try Aegis

```bash
pip install agent-aegis
```

```python
import aegis
aegis.auto_instrument()

# Every AI call is now governed with prompt injection detection,
# PII masking, toxicity filtering, and full audit trail.
```

[Try it live in your browser](../playground/) -- no install needed.
