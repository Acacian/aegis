# Runtime

::: aegis.runtime.engine.Runtime

## Constructor

```python
Runtime(
    *,
    executor: BaseExecutor,
    policy: Policy,
    approval_handler: ApprovalHandler | None = None,
    audit_logger: AuditLogger | None = None,
    session_id: str | None = None,
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `executor` | `BaseExecutor` | required | Adapter that executes actions |
| `policy` | `Policy` | required | Policy rules for governance |
| `approval_handler` | `ApprovalHandler` | `CLIApprovalHandler()` | How to ask humans for approval |
| `audit_logger` | `AuditLogger` | `AuditLogger()` | Where to log the audit trail |
| `session_id` | `str` | auto-generated | Identifier for grouping audit entries |

## Methods

### `plan(actions) -> ExecutionPlan`

Evaluate a list of actions against the policy without executing anything.

```python
plan = runtime.plan([
    Action("read", "salesforce"),
    Action("delete", "salesforce"),
])
print(plan.summary())
```

### `await execute(plan) -> list[Result]`

Execute a plan through the full governance pipeline. Returns one `Result` per action.

```python
results = await runtime.execute(plan)
for r in results:
    print(r.status, r.action.type)
```

**Fail-fast behavior:** If an action fails (not blocked/skipped), all remaining actions are skipped.
