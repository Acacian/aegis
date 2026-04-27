---
description: "Aegis governance server: 37 REST endpoints for multi-agent governance. Policy versioning, trust scoring, drift detection, cost governance, session replay."
---

# Governance Server

Aegis includes a built-in governance server (`aegis-server`) for centralized multi-agent governance over HTTP. Any language that can make HTTP calls can use it — Go, TypeScript, Java, Rust, etc.

## Quick Start

```bash
pip install 'agent-aegis[server]'
aegis-server --init       # Generate aegis-server.yaml template
aegis-server              # Start on :8000 with dashboard
```

## Configuration

The server is configured via `aegis-server.yaml` (auto-detected in the current directory):

```yaml
server:
  host: 127.0.0.1
  port: 8000

policy:
  path: policy.yaml
  watch: true             # Hot-reload on file change

auth:
  api_key: ${AEGIS_API_KEY}
  admin_key: ${AEGIS_ADMIN_KEY}

guardrails:
  injection: true
  pii: true
  toxicity: false
  prompt_leak: false

dashboard:
  enabled: true

agents:
  heartbeat_timeout: 60

webhooks:
  enabled: true
  endpoints:
    - url: https://hooks.slack.com/services/xxx/yyy/zzz
      name: slack-alerts
      events: [action_blocked, rate_limited]
      min_severity: warning
      format: slack

rate_limit:
  enabled: true
  rules:
    - name: default
      match_type: "*"
      match_target: "*"
      max_requests: 100
      window_seconds: 60
      per_agent: true

cost:
  enabled: true
  max_budget: 100.0
```

See `aegis-server.example.yaml` in the repository for a fully commented template.

## Client SDKs

### Python (Sync)

```python
from aegis import AegisClient

with AegisClient("http://localhost:8000", agent_id="my-agent") as client:
    result = client.evaluate("delete", "user_data")
    print(result["approval"])  # "block"

    policy = client.get_policy()
    status = client.status()
```

### Python (Async)

```python
from aegis import AsyncAegisClient

async with AsyncAegisClient("http://localhost:8000", agent_id="a") as client:
    result = await client.evaluate("read", "reports")
    await client.execute("read", "reports")
```

Install the async client with: `pip install 'agent-aegis[httpx]'`

### curl

```bash
curl -X POST http://localhost:8000/api/v1/evaluate \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $AEGIS_API_KEY" \
    -d '{"action_type": "delete", "target": "db"}'
```

## Endpoints (37 total)

### Core (13 endpoints)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check with agent/guardrail status |
| `POST` | `/api/v1/evaluate` | Evaluate action(s) against policy (dry-run) |
| `POST` | `/api/v1/execute` | Execute through full governance pipeline |
| `GET` | `/api/v1/audit` | Query audit log (filter by action_type, risk_level, etc.) |
| `GET` | `/api/v1/policy` | Inspect current policy rules |
| `PUT` | `/api/v1/policy` | Hot-reload policy from YAML string |
| `POST` | `/api/v1/agents` | Register an agent |
| `GET` | `/api/v1/agents` | List registered agents |
| `GET` | `/api/v1/agents/{agent_id}` | Get agent details |
| `DELETE` | `/api/v1/agents/{agent_id}` | Unregister agent |
| `POST` | `/api/v1/agents/{agent_id}/heartbeat` | Agent heartbeat |
| `GET` | `/api/v1/guardrails` | List active guardrails |
| `POST` | `/api/v1/guardrails/check` | Run content through guardrails |

### Policy Versioning (6 endpoints)

Git-like version control for policy changes.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/policy/versions` | List all policy versions |
| `GET` | `/api/v1/policy/versions/{version_id}` | Get specific version (or tag name) |
| `POST` | `/api/v1/policy/commit` | Commit current policy as a new version |
| `POST` | `/api/v1/policy/diff` | Diff two policy versions |
| `POST` | `/api/v1/policy/rollback` | Rollback to a previous version |
| `POST` | `/api/v1/policy/tag` | Tag a version (e.g., "stable", "prod") |

```bash
# Commit current policy
curl -X POST http://localhost:8000/api/v1/policy/commit \
    -H "Content-Type: application/json" \
    -d '{"author": "ops", "message": "tighten delete rules"}'

# Diff two versions
curl -X POST http://localhost:8000/api/v1/policy/diff \
    -H "Content-Type: application/json" \
    -d '{"version_a": "v1-id", "version_b": "v2-id"}'

# Rollback
curl -X POST http://localhost:8000/api/v1/policy/rollback \
    -H "Content-Type: application/json" \
    -d '{"version_id": "v1-id"}'
```

### Crypto Audit (3 endpoints)

Tamper-evident SHA-256 hash chain verification.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/audit/crypto/verify` | Verify audit chain integrity |
| `GET` | `/api/v1/audit/crypto/entries` | List chain entries (paginated) |
| `GET` | `/api/v1/audit/crypto/evidence` | Get chain metadata for compliance |

### Behavioral Drift (2 endpoints)

5-axis drift detection (distribution, risk, target, velocity, repetition).

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/drift` | Global drift report |
| `GET` | `/api/v1/drift/{agent_id}` | Per-agent drift findings + baseline |

### Trust Scoring (3 endpoints)

5-level per-agent trust with time decay and threshold policies.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/trust` | Global trust report |
| `GET` | `/api/v1/trust/{agent_id}` | Agent trust score + recent events |
| `GET` | `/api/v1/trust/{agent_id}/check?risk_level=MEDIUM` | Check if agent meets threshold |

### Cost Governance (3 endpoints)

Budget tracking with per-agent attribution.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/cost` | Budget status (spent, remaining, utilization) |
| `GET` | `/api/v1/cost/report` | Detailed cost report |
| `POST` | `/api/v1/cost/check` | Pre-flight budget check for estimated cost |

### Session Replay (3 endpoints)

Record and forensically rescan agent sessions.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/sessions` | List recorded sessions |
| `GET` | `/api/v1/sessions/{session_id}` | Get session events |
| `POST` | `/api/v1/sessions/{session_id}/replay` | Replay session through current policy |

### Compliance & Regulatory (2 endpoints)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/compliance/report?type=governance` | Generate compliance report (governance, soc2, gdpr) |
| `GET` | `/api/v1/compliance/gaps?framework=eu_ai_act` | Regulatory gap analysis (eu_ai_act, nist) |

## Graceful Degradation

Extended features (versioning, drift, trust, cost, sessions) degrade gracefully. If a feature's backing object isn't configured, its endpoints return `501 Not Implemented` instead of crashing.

## Programmatic Usage

```python
from aegis.server import create_app

app = create_app(
    policy_path="policy.yaml",
    audit_db_path="audit.db",
    enable_dashboard=True,
)

# Run with uvicorn
import uvicorn
uvicorn.run(app, host="0.0.0.0", port=8000)
```

With all extended features:

```python
from aegis.core.versioning import PolicyStore
from aegis.core.crypto_audit import CryptoAuditChain
from aegis.core.behavioral_drift import DriftDetector
from aegis.core.trust_score import TrustScorer
from aegis.core.budget import CostTracker
from aegis.server import create_app

app = create_app(
    policy_path="policy.yaml",
    policy_store=PolicyStore(),
    crypto_chain=CryptoAuditChain(),
    drift_detector=DriftDetector(),
    trust_scorer=TrustScorer(),
    cost_tracker=CostTracker(max_budget=100.0),
    enable_policy_watcher=True,
)
```

## Authentication

Set environment variables before starting:

```bash
export AEGIS_API_KEY="your-api-key"
export AEGIS_ADMIN_KEY="your-admin-key"
aegis-server
```

- `AEGIS_API_KEY` — required for all endpoints (timing-safe comparison)
- `AEGIS_ADMIN_KEY` — required for policy updates (`PUT /api/v1/policy`)
