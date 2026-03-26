<!-- Internal draft. Add DEVTO_ARTICLE.md to .gitignore before committing. -->

---
title: "I Stopped Writing if/else for AI Agent Permissions. Here's What I Use Instead."
published: false
description: "Every developer deploying AI agents writes the same permission checks. I replaced mine with a YAML file and 3 lines of Python."
tags: ai, python, opensource, devops
# cover_image: (see note at bottom)
---

My LangChain agent bulk-deleted 2,000 CRM contacts at 2am on a Tuesday.

It wasn't malicious. The LLM decided "clean up inactive contacts" was a reasonable next step in a data hygiene workflow. There was no permission check. No approval gate. No audit log. Just a for-loop and a DELETE endpoint. I found out from a Slack message the next morning.

## The Pattern Everyone Writes

If you've deployed an agent with real tool access, you've written this code:

```python
if action == "delete" and target == "production":
    raise PermissionError("nope")
if action.startswith("bulk_") and count > 100:
    approval = input("Are you sure? [y/N] ")
    if approval.lower() != "y":
        return
print(f"[LOG] {action} on {target} at {datetime.now()}")
```

Then you copy-paste it for the next framework. Then you realize you need Slack approvals instead of terminal prompts. Then you need an audit trail for compliance. Then you switch from OpenAI to Anthropic and none of your checks transfer.

I got tired of writing the same governance logic for every project. So I built a library.

## Aegis: One Policy File, Any Framework

[Aegis](https://github.com/Acacian/aegis) is a Python middleware that sits between your AI agent and the actions it takes. You define rules in YAML. Aegis enforces them.

```bash
pip install agent-aegis
```

Create a policy file:

```yaml
# policy.yaml
version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  - name: reads_are_safe
    match: { type: "read*" }
    risk_level: low
    approval: auto

  - name: bulk_ops_need_human
    match: { type: "bulk_*" }
    conditions:
      param_gt: { count: 100 }
    risk_level: high
    approval: approve

  - name: no_deletes_ever
    match: { type: "delete*" }
    risk_level: critical
    approval: block
```

Add three lines to your agent:

```python
from aegis import Action, Policy, Runtime

runtime = Runtime(executor=your_executor, policy=Policy.from_yaml("policy.yaml"))
result = await runtime.run_one(Action("delete", "crm"))  # --> BLOCKED
```

That's it. No server to deploy. No Kubernetes. No vendor account.

## Working Example You Can Run Right Now

Copy this into a file and run it. You'll see governance in action in about 10 seconds.

```python
import asyncio
from aegis import Action, Policy, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.core.result import Result, ResultStatus

class MyExecutor(BaseExecutor):
    async def execute(self, action):
        print(f"  Executing: {action.type} -> {action.target}")
        return Result(action=action, status=ResultStatus.SUCCESS)

async def main():
    policy = Policy.from_yaml("policy.yaml")
    async with Runtime(executor=MyExecutor(), policy=policy) as runtime:
        actions = [
            Action("read", "crm", description="Fetch contacts"),
            Action("bulk_update", "crm", params={"count": 150}),
            Action("delete", "crm", description="Drop table"),
        ]
        plan = runtime.plan(actions)
        print(plan.summary())
        results = await runtime.execute(plan)
        for r in results:
            print(f"  {r.action.type}: {r.status.value}")

asyncio.run(main())
```

Output:

```
Plan: 3 actions
  read       crm  -> LOW    (auto)
  bulk_update crm -> HIGH   (approve)
  delete     crm  -> CRITICAL (block)

  read: success
  bulk_update: success     # after human approval
  delete: blocked          # never executed
```

The read went through automatically. The bulk update paused for human approval. The delete was blocked before it could execute. Every decision was logged to SQLite.

Check the audit trail:

```bash
aegis audit
```

```
ID  Session     Action        Target  Risk      Decision   Result
1   a1b2c3...   read          crm     LOW       auto       success
2   a1b2c3...   bulk_update   crm     HIGH      approved   success
3   a1b2c3...   delete        crm     CRITICAL  block      blocked
```

## "Why Not Just Use [X]?"

**Platform guardrails (OpenAI, Anthropic, Google):** They only govern their own ecosystem. If your agent calls OpenAI for reasoning and Anthropic for tool use, you need two sets of guardrails. If you add MCP tools on top, you need a third. Aegis is one policy across all of them.

**Enterprise platforms (Galileo, JetStream, HumanLayer):** They're control planes that need cloud infrastructure, Kubernetes clusters, and procurement cycles. If you're an enterprise with a CISO and a budget, use them. If you're a developer who needs governance before lunch, use Aegis.

**DIY if/else:** This is actually who Aegis competes with. You're already writing permission checks. Aegis is the same thing, except it's a tested library (420 tests, 92% coverage) with approval handlers, audit logs, smart conditions, retry/rollback, and adapters for seven frameworks. Instead of maintaining your own, use the one that already exists.

## The Cross-Platform Problem

This is the part that made me build Aegis instead of just writing better helper functions.

Real agents don't use one provider. A single workflow might call OpenAI for planning, use LangChain tools for execution, hit Anthropic for verification, and interact with MCP servers for file and database access. Each provider has its own permission model (or none at all).

Aegis sits underneath all of them. One YAML policy governs every action regardless of which framework initiated it:

```python
# Same policy governs all of these
from aegis.adapters.langchain import LangChainExecutor
from aegis.adapters.openai_agents import governed_tool
from aegis.adapters.anthropic import govern_tool_call
from aegis.adapters.mcp import govern_mcp_tool_call
```

Switch frameworks, swap providers, add MCP servers -- the governance layer doesn't change. Your policy file stays the same.

## What's Shipped, What's Planned

I want to be honest about where this is.

**Shipped (v0.1.3):**
- Policy engine with glob matching and smart conditions (time windows, param thresholds, weekday schedules)
- 7 adapters: LangChain, CrewAI, OpenAI Agents SDK, Anthropic, Playwright, httpx, MCP
- 7 approval handlers: CLI, Slack, Discord, Telegram, email, webhook, custom
- Audit trail: SQLite + JSONL export + webhook
- REST API server, hot-reload, retry/rollback, dry-run, policy merge
- CLI: `aegis init`, `aegis simulate`, `aegis audit`, `aegis stats`

**Planned:**
- Dashboard UI (v0.2)
- Agent identity and policy hierarchy (v0.3)
- Multi-agent governance with cross-agent audit correlation (v0.4)

It's a real library that works today for single-agent and multi-framework governance. The multi-agent and enterprise features are coming but aren't here yet.

## Try It

```bash
pip install agent-aegis
aegis init          # generates a starter policy.yaml
aegis simulate policy.yaml read:crm delete:db
```

That last command dry-runs your policy without executing anything. You'll see exactly what would be allowed, approved, or blocked.

- **GitHub:** [github.com/Acacian/aegis](https://github.com/Acacian/aegis)
- **Docs:** [acacian.github.io/aegis](https://acacian.github.io/aegis/)
- **PyPI:** `pip install agent-aegis`

If it's useful, a star helps others find it. If something's missing, [open an issue](https://github.com/Acacian/aegis/issues) -- I read all of them.

MIT licensed. 420 tests. No vendor lock-in. No infrastructure required.

---

<!-- COVER IMAGE SUGGESTION:
A minimal, dark-themed terminal screenshot (or illustration mimicking one) showing:

  $ aegis simulate policy.yaml delete:crm
  CRITICAL | BLOCKED | delete -> crm | rule: no_deletes_ever

Use a monospace font on a #1e1e2e or similar dark background.
Green text for "auto/allowed," amber for "approve," red for "BLOCKED."
The Aegis name or logo small in the corner.

Style: clean, developer-oriented. No stock photos, no gradients,
no "AI brain" imagery. Think of how Vercel or Tailwind do cover images --
the product IS the visual.

Dimensions: 1000x420 (Dev.to recommended).
-->
