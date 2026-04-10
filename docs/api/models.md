---
description: "Action and Result data models: Aegis core types for policy evaluation. Action, Decision, Approval, Risk levels, and Result field reference."
---

# Action & Result

## Action

```python
from aegis import Action

action = Action(
    type="write",
    target="salesforce",
    params={"field": "name", "value": "Alice"},
    description="Update contact name",
)
```

| Field | Type | Description |
|-------|------|-------------|
| `type` | `str` | Operation kind (e.g. "read", "write", "delete") |
| `target` | `str` | System being acted upon (e.g. "salesforce") |
| `params` | `dict` | Arbitrary parameters |
| `description` | `str` | Human-readable description |

Actions are **frozen** (immutable) dataclasses.

## Result

```python
from aegis import Result, ResultStatus

result = Result(
    action=action,
    status=ResultStatus.SUCCESS,
    data={"id": 123},
)
```

| Field | Type | Description |
|-------|------|-------------|
| `action` | `Action` | The action that was executed |
| `status` | `ResultStatus` | Outcome of the execution |
| `data` | `Any` | Returned data (on success) |
| `error` | `str \| None` | Error message (on failure) |
| `started_at` | `datetime` | When execution started |
| `completed_at` | `datetime \| None` | When execution finished |
| `ok` | `bool` | Property: `True` if status is SUCCESS |

## ResultStatus

```python
class ResultStatus(StrEnum):
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"    # Blocked by policy
    DENIED = "denied"      # Denied by human
    SKIPPED = "skipped"    # Skipped (prior failure)
```
