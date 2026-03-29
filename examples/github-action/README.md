# Aegis GitHub Action

Validate and test AI agent governance policies in CI/CD. The Terraform plan for AI agent security.

## Quick Start

**1. Add a policy to your repo:**

```bash
pip install agent-aegis
aegis init --with-tests
```

**2. Add the workflow** (`.github/workflows/aegis.yml`):

```yaml
name: Aegis Policy CI
on:
  pull_request:
    paths: ['aegis.yaml', 'policy/**', 'tests/policy_tests.yaml']

jobs:
  policy-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Acacian/aegis@main
        with:
          command: all
          policy-file: aegis.yaml
          min-score: 80
```

**3. Push.** Aegis validates, scores, and gates your policy on every PR.

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `command` | `scan`, `score`, `validate`, `plan`, `test`, or `all` | `all` |
| `policy-file` | Path to policy YAML | `policy.yaml` |
| `scan-directory` | Directory to scan for ungoverned AI calls | `.` |
| `min-score` | Minimum governance score to pass (0-100) | `0` |
| `fail-on-ungoverned` | Fail if ungoverned AI calls found | `false` |
| `python-version` | Python version | `3.11` |
| `old-policy` | Current policy YAML (for `plan`) | |
| `new-policy` | Proposed policy YAML (for `plan`) | |
| `audit-db` | SQLite audit DB for plan replay | |
| `replay` | JSONL file of recorded actions for replay | |
| `test-suite` | Test suite YAML (for `test`) | |
| `regression-policy` | Old policy for test regression comparison | |

## Example: Policy Test + Plan

```yaml
name: Aegis Policy CI
on:
  pull_request:
    paths: ['policy*.yaml', 'tests/*.yaml']

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Test policy
        uses: Acacian/aegis@main
        with:
          command: test
          policy-file: policy.yaml
          test-suite: tests/policy_tests.yaml

      - name: Plan policy change
        uses: Acacian/aegis@main
        with:
          command: plan
          old-policy: policy-v1.yaml
          new-policy: policy-v2.yaml
          replay: audit.jsonl
```
