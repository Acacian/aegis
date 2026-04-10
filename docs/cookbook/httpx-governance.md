---
description: "Govern REST API calls from AI agents with httpx and Aegis. Policy-check every external request, approve sensitive endpoints, and log the full chain."
---

# Govern REST API Calls with httpx in 5 Minutes

Your agent calls external APIs. Aegis ensures those calls are policy-checked, approved, and logged.

**What you will build:** HTTP client governance where GET requests run freely, POST/PUT need approval, DELETE is blocked.

**Time:** 5 minutes.

---

## Prerequisites

```bash
pip install 'agent-aegis[httpx]'
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
  - name: get_auto
    match: { type: "get" }
    risk_level: low
    approval: auto

  - name: post_approve
    match: { type: "post" }
    risk_level: medium
    approval: approve

  - name: put_approve
    match: { type: "put" }
    risk_level: medium
    approval: approve

  - name: delete_block
    match: { type: "delete" }
    risk_level: critical
    approval: block
```

## Step 2: Use the httpx Executor

```python
import asyncio
from aegis import Action, Policy, Runtime
from aegis.adapters.httpx_adapter import HttpxExecutor

async def main():
    executor = HttpxExecutor(
        base_url="https://httpbin.org",
        default_headers={"Accept": "application/json"},
    )
    policy = Policy.from_yaml("policy.yaml")

    async with Runtime(executor=executor, policy=policy) as runtime:
        # GET: auto-approved
        result = await runtime.run_one(Action("get", "/get"))
        print(f"GET /get: {result.status}")

        # POST: needs approval
        result = await runtime.run_one(
            Action("post", "/post", params={"json": {"name": "test"}})
        )
        print(f"POST /post: {result.status}")

        # DELETE: blocked
        result = await runtime.run_one(Action("delete", "/delete"))
        print(f"DELETE /delete: {result.status}")

asyncio.run(main())
```

## HTTP Method to Action Type Mapping

| HTTP Method | Action Type | Typical Risk |
|-------------|-------------|-------------|
| GET | `get` | Low (read-only) |
| POST | `post` | Medium (create) |
| PUT | `put` | Medium (update) |
| PATCH | `patch` | Medium (partial update) |
| DELETE | `delete` | Critical (destructive) |

## Next Steps

- [Writing Policies](../guides/policies.md) — full YAML policy syntax
- [Custom Adapters](../guides/custom-adapters.md) — build your own executor
- [Try the Playground](../playground/) — experiment in your browser
