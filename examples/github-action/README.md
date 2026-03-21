# Aegis GitHub Action

Validate your AI agent governance policies in CI. Catches policy errors before they hit production.

## Usage

```yaml
# .github/workflows/aegis.yml
name: Aegis Policy Check
on: [push, pull_request]

jobs:
  aegis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Acacian/aegis/examples/github-action@main
        with:
          policy: "policy.yaml"
          simulate: "read:crm write:crm delete:crm"
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `policy` | Path to policy YAML file(s). Supports globs. | `policy.yaml` |
| `python-version` | Python version | `3.11` |
| `simulate` | Actions to simulate (space-separated) | _(empty)_ |

## What it does

1. Installs `agent-aegis`
2. Validates your policy YAML (schema check, rule conflicts)
3. Optionally simulates actions against the policy to verify expected behavior

## Example output

```
Validating: policy.yaml
  ✓ Schema valid
  ✓ 12 rules loaded
  ✓ No conflicts detected

Simulating: read:crm → LOW / auto
Simulating: write:crm → MEDIUM / approve
Simulating: delete:crm → CRITICAL / block
```
