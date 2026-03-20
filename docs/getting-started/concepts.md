# Core Concepts

## Action

An `Action` represents a single operation an AI agent wants to perform.

```python
Action(
    type="write",           # What kind of operation
    target="salesforce",    # Which system
    params={"field": "name", "value": "Alice"},
    description="Update contact name",
)
```

## Risk Level

Every action is assigned a risk level by the policy engine:

| Level | Value | Meaning |
|-------|-------|---------|
| `LOW` | 1 | Read-only, no side effects |
| `MEDIUM` | 2 | Single write, generally reversible |
| `HIGH` | 3 | Bulk operations, hard to reverse |
| `CRITICAL` | 4 | Destructive or irreversible |

## Approval

Each risk level maps to an approval requirement:

| Approval | Behavior |
|----------|----------|
| `auto` | Execute immediately, no human needed |
| `approve` | Pause and ask a human for confirmation |
| `block` | Never execute, always reject |

## Policy

A YAML file that maps action patterns to risk levels and approval requirements.

Rules are evaluated **in order** — first match wins:

```yaml
rules:
  - name: read_safe
    match:
      type: read        # Glob pattern
      target: "*"       # Matches any target
    risk_level: low
    approval: auto
```

## Execution Plan

When you call `runtime.plan(actions)`, the policy engine evaluates every action and produces an `ExecutionPlan` — a list of decisions showing what will happen to each action before anything executes.

## Runtime Pipeline

The `Runtime` orchestrates the full governance pipeline:

```
1. Plan    — evaluate actions against policy
2. Approve — prompt humans for approve-required actions
3. Execute — run allowed actions via the adapter
4. Verify  — check that actions completed correctly
5. Audit   — log everything to the audit trail
```

## Adapter

An adapter (executor) is the bridge between Aegis and the actual system. Aegis ships with:

- **PlaywrightExecutor** — browser automation
- **LangChainExecutor** — LangChain tool wrapping
- **AegisCrewAITool** — CrewAI integration
- **@governed_tool** — OpenAI Agents SDK decorator

You can create your own by subclassing `BaseExecutor`.
