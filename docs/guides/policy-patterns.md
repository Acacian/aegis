---
description: "Practical Aegis policy recipes: risk-based approval, time windows, budget limits, PII redaction, and framework-specific patterns from real policies."
---

# Policy Patterns

Practical recipes for writing Aegis policies. Each pattern is drawn from real-world policy files in the `policies/` directory.

!!! tip "Prerequisites"
    Read [Writing Policies](policies.md) first for the YAML structure, rule matching, and condition operators.

---

## Fail-Closed vs Fail-Open

The most important design decision in any policy is the **default behavior** -- what happens when no rule matches.

### Fail-closed (recommended)

Block or require approval for any action not explicitly allowed. Use this for production systems, regulated environments, and any agent that touches sensitive data.

```yaml
version: "1"
defaults:
  risk_level: high
  approval: approve        # Nothing runs without human sign-off

rules:
  # Explicitly allow safe operations
  - name: view_auto
    match: { type: "view" }
    risk_level: low
    approval: auto

  - name: read_auto
    match: { type: "read" }
    risk_level: low
    approval: auto
```

Every policy in `policies/` (devops, financial, healthcare) uses fail-closed defaults. This is deliberate -- unknown actions are dangerous by default.

### Fail-open

Auto-approve by default, block only known-dangerous actions. Use this only for development, sandboxes, or low-risk internal tools.

```yaml
version: "1"
defaults:
  risk_level: low
  approval: auto            # Everything runs unless blocked

rules:
  - name: block_deletes
    match: { type: "delete*" }
    risk_level: critical
    approval: block
```

!!! warning
    Fail-open policies are risky in production. A new action type the agent discovers will run without any gate. Prefer fail-closed and add `auto` rules as you gain confidence.

### When to choose which

| Scenario | Default | Why |
|----------|---------|-----|
| Production agent | `approval: approve` | Unknown actions need human review |
| Healthcare / Finance | `approval: approve` | Regulatory mandate |
| Internal dev tool | `approval: auto` | Speed matters, blast radius is small |
| Prototype / sandbox | `approval: auto` | Iterate fast, worry later |

---

## Time-Based Rules

Control when actions can execute. Useful for deployment windows, business-hours-only operations, and after-hours lockdowns.

### Business hours deployment window

Allow staging deploys during work hours, require approval for production, block everything after hours.

```yaml
rules:
  # Staging: auto during business hours
  - name: staging_deploy_hours
    match: { type: "deploy" }
    conditions:
      param_eq: { env: "staging" }
      time_after: "09:00"
      time_before: "18:00"
      weekdays: [1, 2, 3, 4, 5]      # Mon-Fri
    risk_level: medium
    approval: auto

  # Production: approval required, daytime only
  - name: prod_deploy_approve
    match: { type: "deploy" }
    conditions:
      param_eq: { env: "production" }
      time_after: "09:00"
      time_before: "17:00"
      weekdays: [1, 2, 3, 4, 5]
    risk_level: high
    approval: approve

  # Production after hours: hard block
  - name: prod_deploy_afterhours
    match: { type: "deploy" }
    conditions:
      param_eq: { env: "production" }
      time_after: "17:00"
    risk_level: critical
    approval: block
```

This pattern comes directly from `policies/devops-agent.yaml`. Notice how rules go from **specific** (staging + time window) to **restrictive** (after-hours block). First match wins, so order matters.

### After-hours lockdown

Block all write operations outside business hours. Useful for financial agents.

```yaml
rules:
  # ... your normal rules above ...

  # Catch-all: block everything after 8 PM
  - name: after_hours_block
    match: { type: "*" }
    conditions:
      time_after: "20:00"
    risk_level: critical
    approval: block
```

!!! note
    Place after-hours catch-all rules **last**. Since first match wins, specific rules above will take priority during business hours.

### Weekday-only operations

```yaml
conditions:
  weekdays: [1, 2, 3, 4, 5]   # 1=Monday ... 7=Sunday
```

Combine with `time_after` / `time_before` for precise windows. All conditions are AND-combined -- every condition must pass.

---

## Parameter Thresholds

Gate actions based on their parameters. Useful for amount limits, row counts, and role-based controls.

### Tiered payment approval

Small payments get lighter gates, large payments require human approval.

```yaml
rules:
  # Small payments: approve with review
  - name: payment_small
    match: { type: "payment" }
    conditions:
      param_lte: { amount: 100 }
    risk_level: medium
    approval: approve

  # Large payments: high risk, needs approval
  - name: payment_large
    match: { type: "payment" }
    conditions:
      param_gt: { amount: 100 }
    risk_level: high
    approval: approve
```

From `policies/financial-agent.yaml`. You can add more tiers:

```yaml
rules:
  # Micro-payments: auto
  - name: payment_micro
    match: { type: "payment" }
    conditions:
      param_lte: { amount: 10 }
    risk_level: low
    approval: auto

  # Standard: approve
  - name: payment_standard
    match: { type: "payment" }
    conditions:
      param_lte: { amount: 1000 }
    risk_level: medium
    approval: approve

  # Large: critical, needs approval
  - name: payment_large
    match: { type: "payment" }
    conditions:
      param_gt: { amount: 1000 }
    risk_level: critical
    approval: approve
```

### Bulk operation guards

Prevent agents from modifying too many records at once.

```yaml
rules:
  # Single record update: auto
  - name: update_single
    match: { type: "update" }
    conditions:
      param_lte: { row_count: 1 }
    risk_level: low
    approval: auto

  # Moderate batch: needs approval
  - name: update_batch
    match: { type: "update" }
    conditions:
      param_gt: { row_count: 1 }
      param_lte: { row_count: 100 }
    risk_level: medium
    approval: approve

  # Large batch: block
  - name: update_bulk_block
    match: { type: "update" }
    conditions:
      param_gt: { row_count: 100 }
    risk_level: critical
    approval: block
```

### Available comparison operators

| Operator | Meaning | Example |
|----------|---------|---------|
| `param_eq` | Equals | `param_eq: { env: "staging" }` |
| `param_gt` | Greater than | `param_gt: { amount: 100 }` |
| `param_lt` | Less than | `param_lt: { count: 10 }` |
| `param_gte` | Greater or equal | `param_gte: { priority: 3 }` |
| `param_lte` | Less or equal | `param_lte: { amount: 100 }` |
| `param_contains` | Value in collection | `param_contains: { tags: "urgent" }` |
| `param_matches` | Regex match | `param_matches: { email: "@corp\\.com$" }` |

---

## Industry Compliance Patterns

### HIPAA (Healthcare)

Key principles: PHI access requires approval, modifications are blocked, everything is audited.

```yaml
version: "1"
defaults:
  risk_level: high
  approval: approve           # Fail-closed

rules:
  # Non-PHI: safe
  - name: view_schedule_auto
    match: { type: "view_schedule" }
    risk_level: low
    approval: auto

  # PHI read: needs approval
  - name: view_patient_approve
    match: { type: "view_patient" }
    risk_level: medium
    approval: approve

  # Sensitive PHI fields (SSN, DOB): high risk
  - name: access_phi_high
    match: { type: "access_phi" }
    risk_level: high
    approval: approve

  # After-hours PHI: escalate to critical
  - name: after_hours_phi
    match: { type: "access_phi" }
    conditions:
      time_after: "22:00"
    risk_level: critical
    approval: approve

  # Append-only clinical notes
  - name: create_note
    match: { type: "create_note" }
    risk_level: medium
    approval: approve

  # Modifications: always blocked
  - name: modify_patient_block
    match: { type: "modify_patient" }
    risk_level: critical
    approval: block

  # Deletions: always blocked
  - name: delete_block
    match: { type: "delete" }
    risk_level: critical
    approval: block
```

From `policies/healthcare-agent.yaml`. The HIPAA pattern relies on three pillars:

1. **Approval for all PHI access** -- no auto-approve for patient data
2. **Block all modifications** -- agents can read and append, never mutate or delete
3. **Audit trail** -- Aegis logs every action automatically; export with `aegis audit --format jsonl`

### SOC 2

SOC 2 requires access controls, audit logging, and change management. Map these to Aegis:

```yaml
version: "1"
defaults:
  risk_level: high
  approval: approve

rules:
  # Read-only: auto (access logged by Aegis)
  - name: read_auto
    match: { type: "read*" }
    risk_level: low
    approval: auto

  # Config changes: approval required (change management)
  - name: config_change
    match: { type: "update_config" }
    risk_level: high
    approval: approve

  # User management: critical
  - name: user_management
    match: { type: "create_user" }
    risk_level: critical
    approval: approve

  # Permission changes: blocked for agents
  - name: permission_block
    match: { type: "modify_permissions" }
    risk_level: critical
    approval: block
```

### PCI DSS

For agents that interact with payment systems:

```yaml
version: "1"
defaults:
  risk_level: critical
  approval: block              # Maximum restriction by default

rules:
  # Read transaction history: allowed with approval
  - name: read_transactions
    match: { type: "read" }
    risk_level: medium
    approval: approve

  # Process payment: strict approval
  - name: process_payment
    match: { type: "payment" }
    risk_level: critical
    approval: approve

  # Access cardholder data: always blocked for agents
  - name: cardholder_data_block
    match: { type: "access_cardholder*" }
    risk_level: critical
    approval: block

  # Refunds: approval with amount guard
  - name: refund_small
    match: { type: "refund" }
    conditions:
      param_lte: { amount: 50 }
    risk_level: high
    approval: approve

  - name: refund_large
    match: { type: "refund" }
    conditions:
      param_gt: { amount: 50 }
    risk_level: critical
    approval: approve
```

---

## Layered Policies

Aegis supports merging multiple policy files. This lets you compose policies from reusable building blocks.

### Loading multiple files

```python
from aegis.core.policy import Policy

# Merge: base rules + team-specific overrides
policy = Policy.from_yaml_files(
    "policies/base.yaml",           # Company-wide defaults
    "policies/healthcare-agent.yaml" # Domain-specific rules
)
```

Rules from later files are appended after earlier files. Since first-match-wins, **put higher-priority rules in earlier files**.

### Example: base + domain layers

**`policies/base.yaml`** -- company-wide safety net:

```yaml
version: "1"
defaults:
  risk_level: high
  approval: approve

rules:
  # Every team gets read access
  - name: read_auto
    match: { type: "read*" }
    risk_level: low
    approval: auto

  # Block destructive ops everywhere
  - name: delete_block
    match: { type: "delete*" }
    risk_level: critical
    approval: block
```

**`policies/team-payments.yaml`** -- payment-team additions:

```yaml
version: "1"
defaults:
  risk_level: high
  approval: approve

rules:
  - name: small_payment
    match: { type: "payment" }
    conditions:
      param_lte: { amount: 100 }
    risk_level: medium
    approval: approve
```

When merged, the base `delete_block` rule fires first (it comes from the earlier file), so payment-team agents still cannot delete records.

### Merge with Python API

```python
base = Policy.from_yaml("policies/base.yaml")
team = Policy.from_yaml("policies/team-payments.yaml")

# merge() returns a new Policy; originals are unchanged
combined = base.merge(team)
```

### Layering strategy

| Layer | Contains | Example |
|-------|----------|---------|
| **Base** | Company-wide safety defaults, destructive-op blocks | `base.yaml` |
| **Domain** | Industry compliance rules (HIPAA, PCI) | `healthcare.yaml` |
| **Team** | Team-specific action types and thresholds | `team-payments.yaml` |
| **Environment** | Time windows, after-hours rules | `prod-hours.yaml` |

---

## Testing Policies

Always test policies before deploying. Aegis provides two approaches: the CLI simulator and Python unit tests.

### CLI: `aegis simulate`

Test actions against a policy without executing anything.

```bash
# Syntax: aegis simulate <policy_file> <type:target> [type:target ...]
aegis simulate policies/devops-agent.yaml deploy:staging destroy:infra

# Output shows the decision for each action:
#   deploy:staging  -> MEDIUM / APPROVE (matched: staging_deploy_hours)
#   destroy:infra   -> CRITICAL / BLOCK (matched: destroy_block)
```

### CLI: `aegis validate`

Check policy syntax before loading.

```bash
aegis validate policies/healthcare-agent.yaml
# OK: 11 rules loaded
```

### Python unit tests

Write pytest tests that verify your policy logic.

```python
import pytest
from aegis.core.action import Action
from aegis.core.policy import Policy

@pytest.fixture
def devops_policy():
    return Policy.from_yaml("policies/devops-agent.yaml")

def test_monitoring_is_auto(devops_policy):
    decision = devops_policy.evaluate(Action("monitor", "cpu"))
    assert decision.approval.value == "auto"
    assert decision.risk_level.value == "low"

def test_destroy_is_blocked(devops_policy):
    decision = devops_policy.evaluate(Action("destroy", "vpc"))
    assert decision.approval.value == "block"
    assert decision.risk_level.value == "critical"

def test_force_push_blocked(devops_policy):
    decision = devops_policy.evaluate(Action("force_push", "main"))
    assert decision.approval.value == "block"
```

### Testing parameter conditions

```python
def test_small_payment_approved():
    policy = Policy.from_yaml("policies/financial-agent.yaml")
    action = Action("payment", "vendor", params={"amount": 50})
    decision = policy.evaluate(action)
    assert decision.approval.value == "approve"
    assert decision.risk_level.value == "medium"

def test_large_payment_high_risk():
    policy = Policy.from_yaml("policies/financial-agent.yaml")
    action = Action("payment", "vendor", params={"amount": 5000})
    decision = policy.evaluate(action)
    assert decision.risk_level.value == "high"
```

### Testing with the runtime

For end-to-end tests that verify the full governance pipeline:

```python
@pytest.mark.asyncio
async def test_blocked_action_never_executes(tmp_path):
    from aegis.runtime.engine import Runtime
    from aegis.runtime.approval import AutoApprovalHandler
    from aegis.runtime.audit import AuditLogger

    policy = Policy.from_yaml("policies/devops-agent.yaml")
    executor = FakeExecutor()
    runtime = Runtime(
        executor=executor,
        policy=policy,
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "test.db"),
    )

    result = await runtime.run_one(Action("destroy", "production"))
    assert not result.ok
    assert len(executor.executed) == 0  # Never reached the executor
```

---

## Quick Reference

| Pattern | Key Idea | Default |
|---------|----------|---------|
| Fail-closed | Block unknown actions | `approval: approve` |
| Fail-open | Allow unknown actions | `approval: auto` |
| Time windows | Combine `time_after` + `time_before` + `weekdays` | -- |
| Amount tiers | Chain `param_lte` / `param_gt` rules | -- |
| HIPAA | Approve PHI reads, block all mutations | `approval: approve` |
| SOC 2 | Audit everything, approve config changes | `approval: approve` |
| PCI | Block cardholder data access, tier refunds | `approval: block` |
| Layered | `Policy.from_yaml_files()` or `.merge()` | Base file wins |

See also: [Writing Policies](policies.md) | [Governance Checklist](governance-checklist.md) | [Cheatsheet](../cheatsheet.md)
