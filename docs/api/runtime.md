# Runtime

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

## Context Manager

Runtime supports async context manager for automatic setup/teardown:

```python
async with Runtime(executor=..., policy=...) as runtime:
    results = await runtime.execute(plan)
# executor.teardown() and audit.close() called automatically
```

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

### `await run_one(action) -> Result`

Convenience method: evaluate + execute a single action.

```python
result = await runtime.run_one(Action("read", "salesforce"))
assert result.ok
```

Equivalent to `plan([action])` + `execute(plan)` but returns a single `Result`.

## Approval Handlers

Aegis ships with three approval handlers:

| Handler | Use Case |
|---------|----------|
| `CLIApprovalHandler` | Interactive terminal prompt (default) |
| `AutoApprovalHandler` | Auto-approve everything (testing only) |
| `CallbackApprovalHandler` | Programmatic approval via sync/async callback |

```python
from aegis.runtime.approval import AutoApprovalHandler, CLIApprovalHandler
from aegis.runtime.approval_callback import CallbackApprovalHandler

# Auto-approve low/medium risk
handler = CallbackApprovalHandler(
    callback=lambda d: d.risk_level.value <= 2
)
runtime = Runtime(executor=..., policy=..., approval_handler=handler)
```

See [Approval Handlers guide](../guides/approval-handlers.md) for custom handlers.

## Audit Backends

| Backend | Import | Storage |
|---------|--------|---------|
| `AuditLogger` | `aegis.runtime.audit` | SQLite database (default) |
| `LoggingAuditLogger` | `aegis.runtime.audit_logging` | Python `logging` module |

Both support `.export_jsonl(path)` for JSONL export.

```python
from aegis.runtime.audit_logging import LoggingAuditLogger

runtime = Runtime(
    executor=..., policy=...,
    audit_logger=LoggingAuditLogger(),  # Logs to aegis.audit logger
)
```
