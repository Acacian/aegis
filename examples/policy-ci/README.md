# Policy CI Example

Test and preview policy changes before deploying them — like `terraform plan` for AI agent governance.

## Files

| File | Description |
|------|-------------|
| `policy-v1.yaml` | Current policy (permissive: read/get auto, write approve, delete block) |
| `policy-v2.yaml` | Proposed policy (stricter: adds bulk_* rules, production write block, time windows) |
| `tests.yaml` | 8 test cases validating policy-v1 behavior |
| `audit-sample.jsonl` | 15 recorded agent actions for replay simulation |
| `.github-workflow-example.yml` | Copy-pasteable GitHub Actions workflow |

## Quick Start

```bash
pip install agent-aegis
cd examples/policy-ci
```

### 1. Test a policy against its test suite

```bash
aegis test policy-v1.yaml tests.yaml
```

Runs each test case in `tests.yaml` against `policy-v1.yaml` and reports pass/fail. Exits with code 1 if any test fails.

### 2. Preview a policy change

```bash
aegis plan policy-v1.yaml policy-v2.yaml
```

Shows a diff of rule changes between v1 and v2 (added, removed, modified rules).

### 3. Replay historical actions against a new policy

```bash
aegis plan policy-v1.yaml policy-v2.yaml --replay audit-sample.jsonl
```

Replays the 15 recorded actions through both policies and reports which actions would change: promoted (less restrictive), restricted (more restrictive), or newly blocked.

With `--ci`, exits 1 if any previously-allowed action would be blocked:

```bash
aegis plan policy-v1.yaml policy-v2.yaml --replay audit-sample.jsonl --ci
```

### 4. Regression check between two policies

```bash
aegis test policy-v2.yaml tests.yaml --regression policy-v1.yaml
```

Runs the test suite against both policies and highlights where outcomes diverge.

### 5. JSON output

Both commands support `--format json` for CI pipelines:

```bash
aegis test policy-v1.yaml tests.yaml --format json
aegis plan policy-v1.yaml policy-v2.yaml --replay audit-sample.jsonl --format json
```

## What changes in v1 to v2?

| Change | Effect |
|--------|--------|
| Added `bulk_*` rule | `bulk_update`, `bulk_import` etc. now require approval at high risk |
| Added `write*` to `production*` block | Writes targeting production systems are blocked |
| Added time window rules | Writes outside 09:00-18:00 UTC are blocked |

Running `aegis plan` with `--replay audit-sample.jsonl` will show that actions like `write -> production-db` and `write -> production-cache` would be newly blocked, and after-hours writes (19:20, 20:00 timestamps) would also be blocked.

## CI Integration

Copy `.github-workflow-example.yml` into your `.github/workflows/` directory. It runs on PRs that touch policy files.
