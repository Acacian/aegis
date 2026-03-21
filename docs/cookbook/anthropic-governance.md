# Govern Anthropic Claude Tool Calls in 5 Minutes

Claude's tool_use feature lets the model call your functions autonomously. Aegis wraps those calls with policy checks, approval gates, and audit logging.

**What you will build:** A Claude-powered agent where read tool calls run freely, write operations require approval, and dangerous operations are blocked — all with a full audit trail.

**Time:** 5 minutes.

---

## Prerequisites

```bash
pip install 'agent-aegis[anthropic]' anthropic
```

---

## Step 1: Write Your Policy

```yaml
# policy.yaml
version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  - name: search_auto
    match: { type: "search*" }
    risk_level: low
    approval: auto

  - name: read_auto
    match: { type: "read*" }
    risk_level: low
    approval: auto

  - name: write_approve
    match: { type: "write*" }
    risk_level: medium
    approval: approve

  - name: delete_block
    match: { type: "delete*" }
    risk_level: critical
    approval: block
```

## Step 2: Govern Claude's Tool Calls

```python
import anthropic
from aegis import Policy, Runtime
from aegis.adapters.anthropic import govern_tool_call
from aegis.adapters.base import BaseExecutor
from aegis.core.result import Result, ResultStatus
from aegis.core.action import Action


class MyToolExecutor(BaseExecutor):
    """Execute the actual tool call after governance check."""

    async def execute(self, action: Action) -> Result:
        # Your real tool implementation here
        print(f"  Executing: {action.type}({action.params})")
        return Result(action=action, status=ResultStatus.SUCCESS, data={"ok": True})


async def main():
    # Set up Aegis
    policy = Policy.from_yaml("policy.yaml")
    async with Runtime(
        executor=MyToolExecutor(), policy=policy
    ) as runtime:
        # Call Claude with tools
        client = anthropic.Anthropic()
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            tools=[
                {
                    "name": "search_contacts",
                    "description": "Search CRM contacts",
                    "input_schema": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                    },
                },
                {
                    "name": "delete_contact",
                    "description": "Delete a CRM contact",
                    "input_schema": {
                        "type": "object",
                        "properties": {"id": {"type": "string"}},
                    },
                },
            ],
            messages=[
                {"role": "user", "content": "Search for John, then delete contact C-123"}
            ],
        )

        # Govern each tool call
        for block in response.content:
            if block.type == "tool_use":
                result = await govern_tool_call(
                    runtime=runtime,
                    tool_name=block.name,
                    tool_input=block.input,
                    target="crm",
                )
                print(f"  {block.name}: {'ALLOWED' if result.ok else 'BLOCKED'}")


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
```

## What Happens

1. Claude decides to call `search_contacts` → Aegis evaluates → **AUTO-APPROVED** (matches `search_auto` rule, low risk)
2. Claude decides to call `delete_contact` → Aegis evaluates → **BLOCKED** (matches `delete_block` rule, critical risk)
3. Both decisions are logged to the audit trail

## Step 3: Check the Audit Trail

```bash
aegis audit
```

```
ID  Action            Target   Risk      Decision    Result
1   search_contacts   crm      LOW       auto        success
2   delete_contact    crm      CRITICAL  block       blocked
```

## Advanced: Govern Multiple Tool Calls in a Loop

```python
async def agent_loop(runtime, client, messages):
    """Run a multi-turn agent loop with governance."""
    while True:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            tools=MY_TOOLS,
            messages=messages,
        )

        if response.stop_reason == "end_turn":
            break

        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                result = await govern_tool_call(
                    runtime=runtime,
                    tool_name=block.name,
                    tool_input=block.input,
                    target="my_system",
                )
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": str(result.data) if result.ok else "BLOCKED by policy",
                })

        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})
```

## Next Steps

- [Writing Policies](../guides/policies.md) — full YAML policy syntax
- [Approval Handlers](../guides/approval-handlers.md) — Slack, Discord, Telegram, etc.
- [Security Model](../guides/security-model.md) — defense in depth
- [Try the Playground](../playground/) — experiment in your browser
