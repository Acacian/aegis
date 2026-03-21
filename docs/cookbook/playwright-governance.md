# Govern Browser Automation with Playwright in 5 Minutes

Browser agents can navigate pages, fill forms, click buttons, and execute JavaScript. Aegis ensures they stay within policy.

**What you will build:** Browser governance where navigation is free, form fills need approval, and JavaScript execution is blocked.

**Time:** 5 minutes.

---

## Prerequisites

```bash
pip install 'agent-aegis[playwright]'
playwright install chromium
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
  - name: navigate_auto
    match: { type: "navigate" }
    risk_level: low
    approval: auto

  - name: screenshot_auto
    match: { type: "screenshot" }
    risk_level: low
    approval: auto

  - name: click_approve
    match: { type: "click" }
    risk_level: medium
    approval: approve

  - name: fill_approve
    match: { type: "fill" }
    risk_level: medium
    approval: approve

  - name: submit_high
    match: { type: "submit" }
    risk_level: high
    approval: approve

  - name: eval_block
    match: { type: "eval" }
    risk_level: critical
    approval: block
```

## Step 2: Use the Playwright Executor

```python
import asyncio
from aegis import Action, Policy, Runtime
from aegis.adapters.playwright import PlaywrightExecutor

async def main():
    executor = PlaywrightExecutor(headless=True)
    policy = Policy.from_yaml("policy.yaml")

    async with Runtime(executor=executor, policy=policy) as runtime:
        # Navigate: auto-approved
        result = await runtime.run_one(
            Action("navigate", "browser", params={"url": "https://example.com"})
        )
        print(f"Navigate: {result.status}")

        # Screenshot: auto-approved
        result = await runtime.run_one(
            Action("screenshot", "browser", params={"path": "page.png"})
        )
        print(f"Screenshot: {result.status}")

        # Click: needs approval
        result = await runtime.run_one(
            Action("click", "browser", params={"selector": "a"})
        )
        print(f"Click: {result.status}")

asyncio.run(main())
```

## Browser Action Types

| Action | Risk | Use Case |
|--------|------|----------|
| `navigate` | Low | Open a URL |
| `screenshot` | Low | Capture page state |
| `scroll` | Low | Scroll page |
| `click` | Medium | Click buttons, links |
| `fill` | Medium | Enter data in forms |
| `submit` | High | Submit forms (irreversible) |
| `upload` | High | Upload files |
| `download` | Medium | Download files |
| `eval` | Critical | Execute arbitrary JavaScript |

## Next Steps

- [Browser Agent Policy Template](https://github.com/Acacian/aegis/blob/main/policies/browser-agent.yaml) — pre-built policy
- [Writing Policies](../guides/policies.md) — full YAML policy syntax
- [Try the Playground](../playground/) — experiment in your browser
