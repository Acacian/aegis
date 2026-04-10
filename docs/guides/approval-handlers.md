---
description: "Approval handlers guide: connect human-in-the-loop review to Slack, Discord, Telegram, CLI, email, and webhooks. Full configuration reference."
---

# Approval Handlers

Approval handlers control how humans are asked to approve or deny actions.

## Built-in Handlers

### CLIApprovalHandler (default)

Prompts interactively in the terminal:

```
============================================================
  APPROVAL REQUIRED
============================================================
  Action:  bulk_update
  Target:  salesforce
  Risk:    HIGH
  Params:  {'count': 150}
============================================================
  Approve? [y/n]:
```

### AutoApprovalHandler

Approves everything automatically. **For testing only.**

```python
from aegis.runtime.approval import AutoApprovalHandler

runtime = Runtime(
    executor=my_executor,
    policy=my_policy,
    approval_handler=AutoApprovalHandler(),
)
```

### CallbackApprovalHandler

Use a sync or async callback function for programmatic approval:

```python
from aegis.runtime.approval_callback import CallbackApprovalHandler

# Sync callback
handler = CallbackApprovalHandler(
    callback=lambda decision: decision.risk_level.value <= 2  # Auto-approve low/medium
)

# Async callback
async def check_approval(decision):
    # Query your approval system
    return await my_approval_api.check(decision.action.type)

handler = CallbackApprovalHandler(callback=check_approval)

runtime = Runtime(
    executor=my_executor,
    policy=my_policy,
    approval_handler=handler,
)
```

## Custom Handlers

Implement the `ApprovalHandler` interface:

```python
from aegis.runtime.approval import ApprovalHandler
from aegis.core.policy import PolicyDecision

class SlackApprovalHandler(ApprovalHandler):
    def __init__(self, channel: str, bot_token: str):
        self._channel = channel
        self._token = bot_token

    async def request_approval(self, decision: PolicyDecision) -> bool:
        # Post to Slack and wait for reaction
        message = (
            f"*Approval Required*\n"
            f"Action: `{decision.action.type}` on `{decision.action.target}`\n"
            f"Risk: {decision.risk_level.name}\n"
            f"React with :white_check_mark: to approve or :x: to deny"
        )
        # ... send message, wait for reaction ...
        return approved
```

```python
runtime = Runtime(
    executor=my_executor,
    policy=my_policy,
    approval_handler=SlackApprovalHandler(
        channel="#agent-approvals",
        bot_token="xoxb-...",
    ),
)
```

## Handler Contract

Your handler must implement one async method:

```python
async def request_approval(self, decision: PolicyDecision) -> bool
```

- Receives the full `PolicyDecision` (action, risk level, matched rule)
- Returns `True` to approve, `False` to deny
- Can be async — take as long as needed (wait for human input)
- Should display enough context for an informed decision
