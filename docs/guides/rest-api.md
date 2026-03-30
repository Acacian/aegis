# REST API Server

Aegis includes a built-in REST API server for governing actions from any language -- Go, TypeScript, Java, Rust, or anything that can make HTTP calls.

## Setup

```bash
pip install 'agent-aegis[server]'
```

## Start the Server

```bash
aegis serve policy.yaml --port 8000
```

The server starts on `http://localhost:8000` with auto-approval mode enabled.

## Endpoints

### `GET /health`

Health check.

```bash
curl http://localhost:8000/health
# => {"status": "ok", "version": "0.6.1"}
```

### `POST /api/v1/evaluate`

Evaluate action(s) against policy without executing. Use this for dry-run checks.

```bash
curl -X POST http://localhost:8000/api/v1/evaluate \
    -H "Content-Type: application/json" \
    -d '{"action_type": "delete", "target": "db"}'
```

Response:

```json
{
  "action_type": "delete",
  "target": "db",
  "risk_level": "CRITICAL",
  "approval": "block",
  "is_allowed": false,
  "matched_rule": "no_deletes"
}
```

Batch evaluation:

```bash
curl -X POST http://localhost:8000/api/v1/evaluate \
    -H "Content-Type: application/json" \
    -d '{"actions": [
        {"action_type": "read", "target": "crm"},
        {"action_type": "delete", "target": "db"}
    ]}'
```

### `POST /api/v1/execute`

Execute action through the full governance pipeline (policy check + approval + execution + audit).

```bash
curl -X POST http://localhost:8000/api/v1/execute \
    -H "Content-Type: application/json" \
    -d '{"action_type": "read", "target": "crm"}'
```

Response:

```json
{
  "action_type": "read",
  "target": "crm",
  "status": "success",
  "data": {"executed": true},
  "error": null
}
```

### `GET /api/v1/audit`

Query audit log with optional filters.

```bash
# All entries
curl http://localhost:8000/api/v1/audit

# Filter by action type
curl http://localhost:8000/api/v1/audit?action_type=delete

# Filter by risk level
curl http://localhost:8000/api/v1/audit?risk_level=HIGH

# Combine filters
curl "http://localhost:8000/api/v1/audit?action_type=write&risk_level=CRITICAL&limit=10"
```

Supported query parameters: `session_id`, `action_type`, `risk_level`, `result_status`, `limit`.

### `GET /api/v1/policy`

Inspect current policy rules.

```bash
curl http://localhost:8000/api/v1/policy
```

### `PUT /api/v1/policy`

Hot-reload policy without restarting the server.

```bash
# From YAML string
curl -X PUT http://localhost:8000/api/v1/policy \
    -H "Content-Type: application/json" \
    -d '{"yaml": "rules:\n  - name: block_all\n    match: {type: \"*\"}\n    approval: block"}'

# From policy dict
curl -X PUT http://localhost:8000/api/v1/policy \
    -H "Content-Type: application/json" \
    -d '{"rules": [{"name": "allow_reads", "match": {"type": "read*"}, "approval": "auto"}]}'
```

## Programmatic Usage

```python
from aegis.server import create_app

app = create_app(
    policy_path="policy.yaml",
    audit_db_path="audit.db",
)

# Run with uvicorn
import uvicorn
uvicorn.run(app, host="0.0.0.0", port=8000)
```

## Custom Executor

By default the server uses a no-op executor. To connect real actions:

```python
from aegis.server import create_app

app = create_app(
    policy_path="policy.yaml",
    executor=MyExecutor(),  # Your custom executor
)
```
