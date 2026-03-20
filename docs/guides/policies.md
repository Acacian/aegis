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
