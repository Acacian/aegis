---
description: "Validate AI governance policies in CI/CD pipelines. Add policy-as-code checks to GitHub Actions, pre-commit hooks, and PR workflows."
---

# CI/CD Policy Governance with Aegis

Governance policies are code. They belong in version control, get reviewed in
pull requests, and are validated on every push -- just like application code.

This cookbook shows how to integrate Aegis policy validation into your CI/CD
pipeline so that broken or conflicting rules never reach production.

**What you will set up:**

- Policy validation as a required PR check
- Action simulation to verify expected behavior
- Pre-commit hooks for instant local feedback
- A policy-as-code review workflow

**Time:** 10--15 minutes per CI system.

---

## Prerequisites

```bash
pip install agent-aegis
```

Make sure your policy files are committed to the repository (e.g., `policy.yaml`
or `policies/*.yaml`).

---

## GitHub Actions

The Aegis project ships a composite action at
[`Acacian/aegis/examples/github-action`](https://github.com/Acacian/aegis/tree/main/examples/github-action).
It installs `agent-aegis`, validates your policy YAML, and optionally simulates
actions against the policy.

### Basic validation

```yaml
# .github/workflows/aegis.yml
name: Aegis Policy Check
on:
  pull_request:
    paths:
      - "policy.yaml"
      - "policies/**"

jobs:
  aegis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Acacian/aegis/examples/github-action@main
        with:
          policy: "policy.yaml"
```

### Validation + simulation

Add `simulate` to test specific actions against the policy. The step fails if
any simulated action produces an unexpected result:

```yaml
# .github/workflows/aegis.yml
name: Aegis Policy Check
on:
  pull_request:
    paths:
      - "policy.yaml"
      - "policies/**"
  push:
    branches: [main]

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

Expected output:

```
Validating: policy.yaml
  Policy valid: 6 rule(s) loaded.

Policy: policy.yaml (6 rules)
Actions: 3

  1. read:crm  [AUTO]  risk=LOW  rule=read_auto  -> ALLOWED
  2. write:crm  [APPROVE]  risk=MEDIUM  rule=write_approve  -> ALLOWED
  3. delete:crm  [BLOCK]  risk=CRITICAL  rule=delete_block  -> BLOCKED

Summary: 3 actions
  1 auto-execute, 1 need approval, 1 blocked
```

### Multiple policy files

If you maintain separate policies per environment or service, validate them all
with a glob pattern:

```yaml
      - uses: Acacian/aegis/examples/github-action@main
        with:
          policy: "policies/*.yaml"
```

### Make the check required

Go to **Settings > Branches > Branch protection rules** for your `main` branch
and add the `aegis` job as a required status check. PRs that introduce invalid
policies will be blocked from merging.

---

## GitLab CI

GitLab does not use the composite action, but the CLI commands are the same.

### Basic pipeline

```yaml
# .gitlab-ci.yml
stages:
  - governance

aegis-validate:
  stage: governance
  image: python:3.11-slim
  before_script:
    - pip install agent-aegis
  script:
    - aegis validate policy.yaml
  rules:
    - changes:
        - policy.yaml
        - policies/**
```

### Validation + simulation

```yaml
# .gitlab-ci.yml
stages:
  - governance

aegis-validate:
  stage: governance
  image: python:3.11-slim
  before_script:
    - pip install agent-aegis
  script:
    - aegis validate policy.yaml
    - aegis simulate policy.yaml read:crm write:crm delete:crm
  rules:
    - changes:
        - policy.yaml
        - policies/**
```

### Multiple policies with parallel jobs

```yaml
# .gitlab-ci.yml
stages:
  - governance

.aegis-base:
  stage: governance
  image: python:3.11-slim
  before_script:
    - pip install agent-aegis

aegis-validate-prod:
  extends: .aegis-base
  script:
    - aegis validate policies/prod.yaml
    - aegis simulate policies/prod.yaml read:db write:db delete:db
  rules:
    - changes:
        - policies/prod.yaml

aegis-validate-staging:
  extends: .aegis-base
  script:
    - aegis validate policies/staging.yaml
    - aegis simulate policies/staging.yaml read:db write:db delete:db
  rules:
    - changes:
        - policies/staging.yaml
```

### JSON output for downstream jobs

Use `--format json` to produce machine-readable output for further processing:

```yaml
aegis-simulate-json:
  extends: .aegis-base
  script:
    - aegis simulate policy.yaml read:crm delete:crm --format json > simulation.json
  artifacts:
    paths:
      - simulation.json
    expire_in: 7 days
```

---

## Pre-commit Hooks

Validate policy YAML locally before it ever reaches CI. This gives instant
feedback and keeps your commit history clean.

### Using the pre-commit framework

Add this to your `.pre-commit-config.yaml`:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: aegis-validate
        name: Aegis policy validation
        language: system
        entry: aegis validate
        files: ^(policy\.yaml|policies/.+\.yaml)$
        types: [yaml]
```

Install the hooks:

```bash
pip install pre-commit
pre-commit install
```

Now every commit that touches a policy file will run `aegis validate`
automatically. Invalid policies are rejected before the commit is created.

### Manual Git hook (no framework)

If you prefer not to use the pre-commit framework, add a script directly:

```bash
#!/usr/bin/env bash
# .git/hooks/pre-commit
# Validate all staged policy YAML files

POLICY_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '^(policy\.yaml|policies/.+\.yaml)$')

if [ -z "$POLICY_FILES" ]; then
  exit 0
fi

echo "Aegis: validating policy files..."
for f in $POLICY_FILES; do
  if ! aegis validate "$f"; then
    echo "FAILED: $f"
    exit 1
  fi
done
echo "Aegis: all policies valid."
```

Make it executable:

```bash
chmod +x .git/hooks/pre-commit
```

---

## Policy-as-Code Workflow

Treat policy files like application code. Changes go through pull requests,
are validated by CI, and require review before merging.

### Recommended directory layout

```
repo/
  policies/
    base.yaml           # Shared defaults and read-only rules
    prod.yaml           # Production overrides (stricter)
    staging.yaml        # Staging overrides (more permissive)
  tests/
    test_policy.py      # Simulation-based policy tests
  .github/
    workflows/
      aegis.yml         # CI validation
    CODEOWNERS          # Require review for policy changes
```

### CODEOWNERS for policy review

Require specific team members to approve policy changes:

```
# .github/CODEOWNERS
policies/    @security-team @platform-lead
policy.yaml  @security-team @platform-lead
```

This ensures that no policy change merges without review from the security
team, even if CI passes.

### Pull request template

Add a checklist to your PR template for policy changes:

```markdown
<!-- .github/PULL_REQUEST_TEMPLATE/policy-change.md -->
## Policy Change

**What changed:**
- [ ] New rule(s) added
- [ ] Existing rule(s) modified
- [ ] Rule(s) removed
- [ ] Defaults changed

**Verification:**
- [ ] `aegis validate` passes
- [ ] `aegis simulate` confirms expected behavior
- [ ] No unintended rule conflicts (first-match-wins ordering checked)
- [ ] Audit trail reviewed for affected actions

**Risk assessment:**
- [ ] This change does NOT relax any `block` rules
- [ ] This change does NOT lower risk levels for critical operations
```

---

## Automated Testing

Go beyond validation: write tests that simulate real action sequences against
your policy and assert specific outcomes.

### pytest-based policy tests

```python
# tests/test_policy.py
"""Policy simulation tests -- run in CI to catch regressions."""

import pytest
from aegis import Action, Policy


@pytest.fixture
def policy():
    return Policy.from_yaml("policy.yaml")


def test_reads_are_auto_approved(policy):
    decision = policy.evaluate(Action("read", "crm"))
    assert decision.approval.value == "auto"
    assert decision.risk_level.name == "LOW"


def test_writes_require_approval(policy):
    decision = policy.evaluate(Action("write", "crm"))
    assert decision.approval.value == "approve"
    assert decision.risk_level.name in ("MEDIUM", "HIGH")


def test_deletes_are_blocked(policy):
    decision = policy.evaluate(Action("delete", "database"))
    assert decision.approval.value == "block"
    assert decision.risk_level.name == "CRITICAL"


def test_bulk_operations_are_high_risk(policy):
    decision = policy.evaluate(Action("bulk_update", "database"))
    assert decision.risk_level.name in ("HIGH", "CRITICAL")


def test_unknown_action_uses_defaults(policy):
    decision = policy.evaluate(Action("unknown_action", "unknown_target"))
    assert decision.risk_level.name == "MEDIUM"
    assert decision.approval.value == "approve"
```

Run locally:

```bash
pytest tests/test_policy.py -v
```

### Adding policy tests to CI

=== "GitHub Actions"

    ```yaml
    # .github/workflows/aegis.yml
    jobs:
      aegis:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          - uses: actions/setup-python@v5
            with:
              python-version: "3.11"
          - run: pip install agent-aegis pytest
          - run: aegis validate policy.yaml
          - run: aegis simulate policy.yaml read:crm write:crm delete:crm
          - run: pytest tests/test_policy.py -v
    ```

=== "GitLab CI"

    ```yaml
    # .gitlab-ci.yml
    aegis-test:
      stage: governance
      image: python:3.11-slim
      before_script:
        - pip install agent-aegis pytest
      script:
        - aegis validate policy.yaml
        - aegis simulate policy.yaml read:crm write:crm delete:crm
        - pytest tests/test_policy.py -v
      rules:
        - changes:
            - policy.yaml
            - policies/**
            - tests/test_policy.py
    ```

### CLI simulation in scripts

For quick smoke tests without writing Python, use `aegis simulate` directly
and check the exit code:

```bash
#!/usr/bin/env bash
# scripts/test-policy.sh
set -euo pipefail

POLICY="policy.yaml"

echo "=== Validating policy ==="
aegis validate "$POLICY"

echo ""
echo "=== Simulating expected behaviors ==="
aegis simulate "$POLICY" \
  read:crm \
  write:crm \
  delete:crm \
  bulk_update:database

echo ""
echo "=== JSON output for auditing ==="
aegis simulate "$POLICY" read:crm delete:crm --format json
```

The `aegis simulate` command exits with code 0 regardless of blocked actions
(blocking is a valid policy outcome). Combine it with the pytest tests above
to assert on specific expected outcomes.

---

## Putting It All Together

A complete governance pipeline combines all the pieces:

```
Developer edits policy.yaml
        |
        v
Pre-commit hook: aegis validate  -----> FAIL: fix locally
        |
        v (pass)
Push / open PR
        |
        v
CI job: aegis validate           -----> FAIL: PR blocked
CI job: aegis simulate           -----> output visible in PR
CI job: pytest test_policy.py    -----> FAIL: PR blocked
        |
        v (all pass)
CODEOWNERS review                -----> security team approves
        |
        v
Merge to main
        |
        v
Deploy: new policy is live
```

This workflow ensures that:

1. Invalid policies never leave the developer's machine (pre-commit).
2. Unexpected behavior is caught before review (CI simulation).
3. Policy regressions are detected by tests (pytest).
4. Human review is required for all policy changes (CODEOWNERS).

---

## Quick Reference

| Task | Command |
|------|---------|
| Validate a policy | `aegis validate policy.yaml` |
| Simulate actions | `aegis simulate policy.yaml read:crm delete:db` |
| Simulation as JSON | `aegis simulate policy.yaml read:crm --format json` |
| Generate starter policy | `aegis init` |
| Print policy JSON schema | `aegis schema` |
| View audit log | `aegis audit` |
| Audit stats | `aegis stats` |

---

## Next Steps

- [Writing Policies](../guides/policies.md) -- rule syntax, glob patterns, conditions
- [Policy Patterns](../guides/policy-patterns.md) -- base + override, per-environment strategies
- [Testing](../guides/testing.md) -- comprehensive testing guide
- [Deployment](../guides/deployment.md) -- production deployment patterns
- [Governance Checklist](../guides/governance-checklist.md) -- pre-launch verification
