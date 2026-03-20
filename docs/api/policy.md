# Policy

## Policy

```python
from aegis import Policy
```

### `Policy.from_yaml(path) -> Policy`

Load a policy from a YAML file.

### `Policy.from_dict(data) -> Policy`

Load a policy from a Python dictionary.

### `policy.evaluate(action) -> PolicyDecision`

Evaluate a single action against the rules. Returns a `PolicyDecision`.

## PolicyDecision

```python
@dataclass(frozen=True)
class PolicyDecision:
    action: Action
    risk_level: RiskLevel
    approval: Approval
    matched_rule: str
```

| Property | Type | Description |
|----------|------|-------------|
| `is_allowed` | `bool` | `True` unless the action is blocked |

## Approval

```python
class Approval(StrEnum):
    AUTO = "auto"
    APPROVE = "approve"
    BLOCK = "block"
```

## RiskLevel

```python
class RiskLevel(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
```

## PolicyRule

```python
@dataclass
class PolicyRule:
    match_type: str = "*"      # Glob pattern
    match_target: str = "*"    # Glob pattern
    risk_level: RiskLevel = RiskLevel.MEDIUM
    approval: Approval = Approval.APPROVE
    name: str = ""
```

## ExecutionPlan

```python
plan = runtime.plan(actions)
plan.summary()          # Human-readable plan
plan.has_blocked        # Any actions blocked?
plan.requires_approval  # Any actions need human approval?
len(plan)               # Number of actions
```
