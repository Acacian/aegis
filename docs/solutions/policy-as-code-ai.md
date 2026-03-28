---
description: "Terraform plan for AI agent policies. Preview impact of policy changes, run regression tests, and replay against audit history before deploying."
---

# Policy as Code for AI Agents: Preview, Test, and Deploy Safely

Changing AI agent policies is risky. Loosening a rule might allow actions that should be blocked. Tightening a rule might break production workflows. There is no way to preview the impact before deploying -- unless you treat policies as code. Aegis provides `aegis plan` (like terraform plan) and `aegis test` (like pytest for policies) so you can see exactly what would change before it goes live.

## Quick Start

```bash
pip install agent-aegis
```

Preview the impact of a policy change:

```bash
aegis plan current.yaml proposed.yaml --replay audit.jsonl
```

Run regression tests against a policy:

```bash
aegis test policy.yaml test_suite.yaml
```

Auto-generate a test suite from a policy:

```bash
aegis test policy.yaml --generate --generate-output test_suite.yaml
```

## How It Works

### `aegis plan` -- Preview Impact Before Deploying

`aegis plan` compares two YAML policies and shows what would change. When you provide audit history (via `--replay` or `--audit-db`), it replays every recorded action against both policies to show which actions would get a different governance decision.

```bash
# Basic diff: show rule changes
aegis plan current.yaml proposed.yaml

# Replay against JSONL audit history
aegis plan current.yaml proposed.yaml --replay audit.jsonl

# Replay against SQLite audit database
aegis plan current.yaml proposed.yaml --audit-db audit.db

# Filter replay to a specific session
aegis plan current.yaml proposed.yaml --audit-db audit.db --session prod-042

# JSON output for CI/CD pipelines
aegis plan current.yaml proposed.yaml --replay audit.jsonl --format json

# CI mode: exit code 1 if any actions would be newly blocked
aegis plan current.yaml proposed.yaml --replay audit.jsonl --ci
```

Example output:

```
Policy Diff: current.yaml → proposed.yaml
═══════════════════════════════════════════

Rules Added:
  + block_bulk_operations    [approval: block, risk: critical]

Rules Removed:
  - allow_all_writes         [approval: auto, risk: low]

Rules Modified:
  ~ approve_updates          [approval: auto → approve, risk: low → medium]

Replay Impact (247 historical actions):
═══════════════════════════════════════════

  Action                  Old Decision    New Decision    Impact
  ─────────────────────   ────────────    ────────────    ──────
  bulk_delete@prod_db     auto            block           BREAKING
  update_user@crm         auto            approve         STRICTER
  read_report@analytics   auto            auto            no change
  write_config@staging    approve         approve         no change

Summary:
  12 actions newly blocked (BREAKING)
   8 actions now require approval (stricter)
 227 actions unchanged
```

### `aegis test` -- Regression Testing for Policies

Define test cases that verify your policy evaluates actions correctly. Run them in CI to catch regressions when policies change.

```yaml
# test_suite.yaml
version: "1"

cases:
  - name: reads_are_auto_allowed
    action:
      type: read_report
      target: analytics
    expect:
      approval: auto
      risk_level: low

  - name: deletes_are_blocked
    action:
      type: delete_user
      target: production_db
    expect:
      approval: block
      risk_level: critical

  - name: writes_require_approval
    action:
      type: update_contact
      target: crm
    expect:
      approval: approve
      risk_level: medium
```

Run the tests:

```bash
aegis test policy.yaml test_suite.yaml
```

Output:

```
Policy Test Results: policy.yaml
═════════════════════════════════

  Test                        Expected         Actual           Result
  ────────────────────────    ────────────     ────────────     ──────
  reads_are_auto_allowed      auto/low         auto/low         PASS
  deletes_are_blocked         block/critical   block/critical   PASS
  writes_require_approval     approve/medium   approve/medium   PASS

3/3 tests passed
```

### Auto-Generate Test Suites

Generate a test suite from an existing policy. Aegis creates test cases for every rule plus edge cases:

```bash
# Print to stdout
aegis test policy.yaml --generate

# Write to file
aegis test policy.yaml --generate --generate-output test_suite.yaml
```

This generates test cases that exercise each rule in your policy, giving you baseline coverage without writing tests manually.

### Regression Detection

Compare test outcomes between an old and new policy to detect regressions:

```bash
aegis test proposed.yaml test_suite.yaml --regression current.yaml
```

This runs the test suite against both policies and flags any test case where the outcome differs.

### CI/CD Integration

Add policy testing and impact preview to your CI pipeline:

```yaml
# .github/workflows/policy-check.yml
name: Policy Check
on:
  pull_request:
    paths:
      - 'policies/**'

jobs:
  policy-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - run: pip install agent-aegis

      # Run policy tests
      - name: Test policy
        run: aegis test policies/policy.yaml policies/test_suite.yaml

      # Preview impact against audit history
      - name: Plan impact
        run: |
          aegis plan policies/current.yaml policies/proposed.yaml \
            --replay audit/production.jsonl \
            --ci
        # --ci exits with code 1 if any actions would be newly blocked
```

### Policy Validation

Before testing or deploying, validate the policy syntax:

```bash
aegis validate policy.yaml
```

This checks:
- YAML syntax
- Required fields (version, defaults, rules)
- Valid risk levels and approval modes
- Glob pattern syntax
- Condition operator validity

### Programmatic API

Use the plan and replay APIs from Python:

```python
from aegis.core.diff import diff_policies, analyze_impact
from aegis.core.policy import Policy
from aegis.core.replay import ReplayEngine, load_events_from_jsonl

# Load policies
old = Policy.from_yaml("current.yaml")
new = Policy.from_yaml("proposed.yaml")

# Diff rules
diff = diff_policies(old, new)
print(f"Rules added: {len(diff.added)}")
print(f"Rules removed: {len(diff.removed)}")
print(f"Rules modified: {len(diff.modified)}")

# Replay against audit history
events = load_events_from_jsonl("audit.jsonl")
engine = ReplayEngine(old)
report = engine.what_if(events, new)

print(f"Total events: {report.total}")
print(f"Changed decisions: {report.changed}")
print(f"Newly blocked: {report.newly_blocked}")
```

## Comparison

| Feature | Aegis | OPA (Open Policy Agent) | Manual Review |
|---------|-------|------------------------|---------------|
| **Domain** | AI agent governance | Infrastructure/API authorization | Any |
| **Policy language** | YAML (declarative, simple) | Rego (general-purpose, steep learning curve) | N/A |
| **Impact preview** | `aegis plan` with audit replay | No built-in equivalent | Spreadsheet analysis |
| **Regression testing** | `aegis test` with YAML test suites | `opa test` with Rego tests | Manual QA |
| **Auto-generate tests** | `aegis test --generate` | No | No |
| **AI agent integration** | Built-in (LangChain, CrewAI, OpenAI, ...) | Custom integration | N/A |
| **Audit trail** | Built-in (SQLite + JSONL) | External (decision logs) | None |
| **CI mode** | `--ci` flag (exit code on breaking changes) | Via custom scripting | PR review |
| **Learning curve** | YAML rules, glob patterns | Rego language | N/A |

**When to use OPA:** You need a general-purpose policy engine for infrastructure authorization (Kubernetes, Terraform, API gateways) with Rego's full expressiveness.

**When to use Aegis:** You need policy-as-code specifically for AI agent governance, with built-in impact preview, audit replay, and regression testing that understands AI agent actions.

## Try It Now

- [**Interactive Playground**](https://acacian.github.io/aegis/playground/) -- try Aegis in your browser, no install needed
- [**GitHub**](https://github.com/Acacian/aegis) -- source code, examples, and documentation
- [**PyPI**](https://pypi.org/project/agent-aegis/) -- `pip install agent-aegis`
