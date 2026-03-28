---
description: "Write YAML policies for AI agent governance. Define rules, risk levels, approval gates, and pattern matching for tool calls."
---

# Writing Policies

Policies are YAML files that tell Aegis how to handle each action an AI agent wants to perform.

## Structure

```yaml
version: "1"

defaults:
  risk_level: medium    # Fallback for unmatched actions
  approval: approve     # Fallback approval requirement

rules:
  - name: rule_name       # Human-readable identifier
    match:
      type: "pattern"     # Glob pattern for action type
      target: "pattern"   # Glob pattern for action target
    risk_level: low       # low | medium | high | critical
    approval: auto        # auto | approve | block
```

## Rule Matching

Rules are evaluated **top to bottom** — first match wins. Use this to create specific rules before general ones:

```yaml
rules:
  # Specific: block deletes on production
  - name: block_prod_delete
    match:
      type: delete
      target: "prod_*"
    risk_level: critical
    approval: block

  # General: allow deletes on staging
  - name: allow_staging_delete
    match:
      type: delete
      target: "staging_*"
    risk_level: medium
    approval: approve

  # Catch-all for other deletes
  - name: default_delete
    match:
      type: delete
    risk_level: high
    approval: approve
```

## Glob Patterns

Both `type` and `target` support glob patterns:

| Pattern | Matches |
|---------|---------|
| `read` | Exactly "read" |
| `*` | Anything |
| `bulk_*` | "bulk_update", "bulk_delete", etc. |
| `prod_*` | "prod_salesforce", "prod_stripe", etc. |

## Risk Levels

| Level | When to use |
|-------|-------------|
| `low` | Read-only queries, screenshots, navigation |
| `medium` | Single record updates, form fills |
| `high` | Bulk operations, multi-record changes |
| `critical` | Deletions, irreversible operations |

## Approval Modes

| Mode | Behavior |
|------|----------|
| `auto` | Execute immediately. Best for read-only actions. |
| `approve` | Pause and show the action details to a human. |
| `block` | Always reject. Use for dangerous operations. |

## Conditions

Rules can include conditions that go beyond glob matching. All conditions must pass for the rule to match.

### Time-based conditions

```yaml
rules:
  - name: after_hours_block
    match: { type: "write*" }
    conditions:
      time_after: "18:00"    # Current time >= 18:00
    risk_level: critical
    approval: block

  - name: morning_only
    match: { type: "deploy*" }
    conditions:
      time_after: "09:00"
      time_before: "12:00"
    risk_level: medium
    approval: approve
```

### Weekday conditions

```yaml
rules:
  - name: weekday_deploys
    match: { type: "deploy*" }
    conditions:
      weekdays: [1, 2, 3, 4, 5]  # 1=Monday, 7=Sunday
    risk_level: medium
    approval: approve
```

### Param-based conditions

```yaml
rules:
  - name: bulk_ops_require_approval
    match: { type: "update*" }
    conditions:
      param_gt: { count: 100 }   # Only when count > 100
    risk_level: high
    approval: approve

  - name: admin_only_ops
    match: { type: "*" }
    conditions:
      param_eq: { role: "admin" }
    risk_level: low
    approval: auto
```

### Available condition operators

| Condition | Description | Example |
|-----------|-------------|---------|
| `time_after` | Current time >= HH:MM | `time_after: "18:00"` |
| `time_before` | Current time < HH:MM | `time_before: "08:00"` |
| `weekdays` | Current day in list | `weekdays: [1, 2, 3, 4, 5]` |
| `param_eq` | Param equals value | `param_eq: { status: "active" }` |
| `param_gt` | Param > value | `param_gt: { count: 100 }` |
| `param_lt` | Param < value | `param_lt: { count: 10 }` |
| `param_gte` | Param >= value | `param_gte: { count: 100 }` |
| `param_lte` | Param <= value | `param_lte: { count: 10 }` |
| `param_contains` | Value in param | `param_contains: { tags: "admin" }` |
| `param_matches` | Regex match | `param_matches: { email: "@corp\\.com$" }` |

All conditions in a rule are AND-combined — every condition must pass for the rule to match. If a condition fails, evaluation continues to the next rule.

## Validation

Validate your policy file before deploying:

```bash
aegis validate policy.yaml
```

## Loading Policies

```python
# From a YAML file
policy = Policy.from_yaml("policy.yaml")

# From a Python dict
policy = Policy.from_dict({
    "defaults": {"risk_level": "medium", "approval": "approve"},
    "rules": [...]
})
```

## Tips

1. **Start restrictive, loosen over time.** Default to `approve`, add `auto` rules for actions you trust.
2. **Use descriptive rule names.** They appear in audit logs and approval prompts.
3. **Order matters.** Put specific rules before general ones.
4. **Test your policies.** Write unit tests that verify your policy evaluates actions correctly.
