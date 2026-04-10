---
description: "Deploy Aegis as a policy evaluation REST API in Docker. Language-agnostic governance for Go, TypeScript, Java, or any service via HTTP in 5 minutes."
---

# Deploy Aegis as a REST API via Docker

Run Aegis as a standalone governance server in Docker. Any service --
Python, Go, TypeScript, Java, Rust -- can evaluate actions over HTTP.
No SDK integration required.

This guide walks through building the image, using the API endpoints,
customizing policies, and hardening for production.

**What you will build:** A containerized REST API that evaluates agent
actions against YAML policies, with health checks, hot-reload, and an
audit trail.

**Time:** 10 minutes.

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) installed and running
- The Aegis repository cloned (or just the `examples/docker/` directory)

```bash
git clone https://github.com/Acacian/aegis.git
cd aegis
```

---

## Building and Running the Docker Image

### Quick Start

```bash
docker build -t aegis-server examples/docker/
docker run -p 8000:8000 aegis-server
```

The server starts on `http://localhost:8000` with the default policy
from `examples/docker/policy.yaml`.

Verify it works:

```bash
curl http://localhost:8000/health
# => {"status": "ok", "version": "..."}
```

### Mount Your Own Policy

The default policy is baked into the image. Override it by mounting
your own `policy.yaml`:

```bash
docker run -p 8000:8000 \
  -v $(pwd)/policy.yaml:/app/policy.yaml \
  aegis-server
```

### Docker Compose

For repeatable deployments, use Compose:

```yaml
# docker-compose.yaml
services:
  aegis:
    build: examples/docker/
    ports:
      - "8000:8000"
    volumes:
      - ./policy.yaml:/app/policy.yaml
      - aegis-data:/app/data
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/v1/health"]
      interval: 30s
      timeout: 5s
      retries: 3

volumes:
  aegis-data:
```

```bash
docker compose up -d
docker compose logs -f aegis
```

### What the Dockerfile Does

The image ([`examples/docker/Dockerfile`](https://github.com/Acacian/aegis/blob/main/examples/docker/Dockerfile))
is minimal by design:

1. Starts from `python:3.12-slim` (~120 MB).
2. Installs `agent-aegis[server]` (includes Starlette + Uvicorn).
3. Copies the default `policy.yaml` into `/app/`.
4. Exposes port 8000 with a built-in health check.
5. Runs `aegis serve /app/policy.yaml --host 0.0.0.0 --port 8000`.

No application code to maintain -- the CLI `aegis serve` command handles
everything.

---

## API Endpoints

The server exposes six endpoints. All request/response bodies are JSON.

### `GET /health`

Health check. Use for Docker `HEALTHCHECK`, load balancers, and uptime
monitors.

```bash
curl http://localhost:8000/health
```

```json
{"status": "ok", "version": "0.9.1"}
```

### `POST /api/v1/evaluate`

Evaluate an action against the policy without executing it. This is a
**dry-run** -- no side effects, no audit entry.

```bash
curl -X POST http://localhost:8000/api/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"action_type": "read", "target": "crm"}'
```

```json
{
  "action_type": "read",
  "target": "crm",
  "risk_level": "LOW",
  "approval": "auto",
  "is_allowed": true,
  "matched_rule": "read_auto"
}
```

**Batch evaluation** -- send multiple actions in one request:

```bash
curl -X POST http://localhost:8000/api/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"actions": [
    {"action_type": "read", "target": "crm"},
    {"action_type": "write", "target": "database"},
    {"action_type": "delete", "target": "storage"}
  ]}'
```

Returns an array of decision objects.

### `POST /api/v1/execute`

Execute an action through the **full governance pipeline**: policy check,
approval gate, execution, and audit logging.

```bash
curl -X POST http://localhost:8000/api/v1/execute \
  -H "Content-Type: application/json" \
  -d '{"action_type": "read", "target": "crm"}'
```

```json
{
  "action_type": "read",
  "target": "crm",
  "status": "success",
  "data": {"executed": true},
  "error": null
}
```

!!! note "Default No-Op Executor"
    The built-in server uses a no-op executor -- `/execute` runs the full
    governance pipeline but does not perform real side effects. To connect
    real actions, use the [programmatic API](#programmatic-usage) with a
    custom executor.

### `GET /api/v1/audit`

Query the audit log. Supports filtering by multiple parameters.

```bash
# All entries
curl http://localhost:8000/api/v1/audit

# Filter by action type
curl "http://localhost:8000/api/v1/audit?action_type=delete"

# Filter by risk level
curl "http://localhost:8000/api/v1/audit?risk_level=CRITICAL"

# Combine filters with a limit
curl "http://localhost:8000/api/v1/audit?result_status=blocked&limit=20"
```

Supported query parameters:

| Parameter | Example | Description |
|-----------|---------|-------------|
| `session_id` | `a3f1b2c4` | Filter by session |
| `action_type` | `delete` | Filter by action type |
| `risk_level` | `HIGH` | Filter by risk level |
| `result_status` | `blocked` | Filter by execution result |
| `limit` | `50` | Max entries to return |

### `GET /api/v1/policy`

Inspect the currently active policy rules.

```bash
curl http://localhost:8000/api/v1/policy
```

```json
{
  "default_risk_level": "MEDIUM",
  "default_approval": "approve",
  "rules": [
    {
      "name": "read_auto",
      "match_type": "read*",
      "match_target": null,
      "risk_level": "LOW",
      "approval": "auto",
      "conditions": null
    }
  ]
}
```

### `PUT /api/v1/policy`

Hot-reload the policy without restarting the server. Send either a YAML
string or a policy dict.

```bash
# From a YAML string
curl -X PUT http://localhost:8000/api/v1/policy \
  -H "Content-Type: application/json" \
  -d '{"yaml": "version: \"1\"\nrules:\n  - name: block_all\n    match: {type: \"*\"}\n    approval: block"}'
```

```bash
# From a policy dict
curl -X PUT http://localhost:8000/api/v1/policy \
  -H "Content-Type: application/json" \
  -d '{
    "defaults": {"risk_level": "high", "approval": "block"},
    "rules": [
      {"name": "allow_reads", "match": {"type": "read*"}, "approval": "auto"}
    ]
  }'
```

```json
{"status": "updated", "rule_count": 1}
```

---

## Custom Policy Configuration

### Default Policy

The image ships with a default policy (`examples/docker/policy.yaml`)
that covers basic CRUD governance:

```yaml
version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  - name: read_auto
    match: { type: "read*" }
    risk_level: low
    approval: auto

  - name: write_approve
    match: { type: "write*" }
    risk_level: medium
    approval: approve

  - name: delete_block
    match: { type: "delete*" }
    risk_level: critical
    approval: block
```

### Writing Your Own Policy

Create a `policy.yaml` tailored to your use case and mount it into the
container:

```yaml
# policy.yaml -- E-commerce agent governance
version: "1"
defaults:
  risk_level: high
  approval: block          # Fail closed: unknown actions are blocked

rules:
  - name: product_search
    match: { type: "search_*", target: "catalog" }
    risk_level: low
    approval: auto

  - name: cart_operations
    match: { type: "cart_*", target: "session" }
    risk_level: low
    approval: auto

  - name: place_order
    match: { type: "place_order" }
    conditions:
      param_lte: { total: 500 }
    risk_level: medium
    approval: approve

  - name: block_large_orders
    match: { type: "place_order" }
    conditions:
      param_gt: { total: 500 }
    risk_level: critical
    approval: block

  - name: refund
    match: { type: "refund" }
    risk_level: high
    approval: approve
```

```bash
docker run -p 8000:8000 \
  -v $(pwd)/policy.yaml:/app/policy.yaml \
  aegis-server
```

### Policy Validation

Validate your policy before deploying:

```bash
pip install agent-aegis
aegis validate policy.yaml
```

Or validate via the API after deployment:

```bash
# Inspect active rules
curl http://localhost:8000/api/v1/policy | python -m json.tool

# Test a specific action
curl -X POST http://localhost:8000/api/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"action_type": "place_order", "target": "checkout", "params": {"total": 1000}}'
```

---

## Programmatic Usage

For tighter integration, create the ASGI app directly in Python:

```python
from aegis.server import create_app

app = create_app(
    policy_path="policy.yaml",
    audit_db_path="/data/audit.db",  # Persistent audit storage
)

# Run with uvicorn
import uvicorn
uvicorn.run(app, host="0.0.0.0", port=8000)
```

To connect real tool execution (not just policy evaluation):

```python
from aegis.server import create_app

app = create_app(
    policy_path="policy.yaml",
    executor=MyCustomExecutor(),   # Your executor handles real actions
    audit_db_path="/data/audit.db",
)
```

---

## Production Deployment Tips

### Run as Non-Root

The default Dockerfile runs as root. For production, create a dedicated user:

```dockerfile
FROM python:3.12-slim

RUN useradd -m aegis
WORKDIR /home/aegis

RUN pip install --no-cache-dir 'agent-aegis[server]'

COPY policy.yaml .

USER aegis
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')" || exit 1

ENTRYPOINT ["aegis", "serve", "policy.yaml", "--host", "0.0.0.0", "--port", "8000"]
```

### Pin the Version

Avoid surprises by pinning the exact Aegis version:

```dockerfile
RUN pip install --no-cache-dir 'agent-aegis[server]==0.9.1'
```

### Harden the Container

Apply defense-in-depth settings in your Compose file:

```yaml
services:
  aegis:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./policy.yaml:/app/policy.yaml:ro
      - aegis-data:/app/data
    read_only: true
    tmpfs: /tmp
    security_opt:
      - no-new-privileges
    cap_drop:
      - ALL
    environment:
      - AEGIS_LOG_LEVEL=INFO
```

Key settings:

| Setting | Purpose |
|---------|---------|
| `read_only: true` | Container filesystem is immutable |
| `tmpfs: /tmp` | Writable temp space without persisting to disk |
| `cap_drop: ALL` | Drop all Linux capabilities |
| `no-new-privileges` | Prevent privilege escalation |
| `:ro` on policy mount | Policy file is read-only inside the container |

### Deploy Behind a Reverse Proxy

The Aegis server has no built-in authentication or TLS. In production,
place it behind a reverse proxy:

```nginx
# nginx.conf
upstream aegis {
    server aegis:8000;
}

server {
    listen 443 ssl;
    server_name aegis.yourcompany.com;

    ssl_certificate     /etc/ssl/certs/aegis.crt;
    ssl_certificate_key /etc/ssl/private/aegis.key;

    location / {
        proxy_pass http://aegis;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

!!! warning "Auto-Approval Default"
    The REST server uses `AutoApprovalHandler` by default -- all
    approval-required actions are auto-approved. For production, deploy
    behind an authenticating reverse proxy and consider implementing a
    custom approval handler.

### Persistent Audit Storage

By default, the audit log lives in an in-memory SQLite database and is
lost when the container stops. Mount a volume for persistence:

```bash
docker run -p 8000:8000 \
  -v $(pwd)/policy.yaml:/app/policy.yaml \
  -v aegis-data:/app/data \
  -e AEGIS_AUDIT_DB=/app/data/audit.db \
  aegis-server
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AEGIS_POLICY_PATH` | `policy.yaml` | Path to the YAML policy file |
| `AEGIS_LOG_LEVEL` | `WARNING` | Log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `AEGIS_AUDIT_DB` | `aegis_audit.db` | Path to the SQLite audit database |

### Health Check Integration

The Dockerfile includes a built-in health check. For orchestrators:

**Docker Compose:**

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8000/api/v1/health"]
  interval: 30s
  timeout: 5s
  retries: 3
```

**Kubernetes:**

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8000
  initialDelaySeconds: 5
  periodSeconds: 30
readinessProbe:
  httpGet:
    path: /health
    port: 8000
  initialDelaySeconds: 3
  periodSeconds: 10
```

---

## End-to-End Example

A complete workflow from build to test:

```bash
# 1. Build the image
docker build -t aegis-server examples/docker/

# 2. Start the server with a custom policy
docker run -d --name aegis -p 8000:8000 \
  -v $(pwd)/policy.yaml:/app/policy.yaml \
  aegis-server

# 3. Verify health
curl http://localhost:8000/health

# 4. Evaluate a safe action
curl -X POST http://localhost:8000/api/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"action_type": "read", "target": "crm"}'
# => {"risk_level": "LOW", "approval": "auto", "is_allowed": true, ...}

# 5. Evaluate a blocked action
curl -X POST http://localhost:8000/api/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"action_type": "delete", "target": "crm"}'
# => {"risk_level": "CRITICAL", "approval": "block", "is_allowed": false, ...}

# 6. Hot-reload a stricter policy
curl -X PUT http://localhost:8000/api/v1/policy \
  -H "Content-Type: application/json" \
  -d '{"defaults": {"risk_level": "high", "approval": "block"}, "rules": []}'
# => {"status": "updated", "rule_count": 0}

# 7. Now everything is blocked
curl -X POST http://localhost:8000/api/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"action_type": "read", "target": "crm"}'
# => {"risk_level": "HIGH", "approval": "block", "is_allowed": false, ...}

# 8. Clean up
docker stop aegis && docker rm aegis
```

---

## Next Steps

- [REST API reference](../guides/rest-api.md) -- full endpoint documentation
- [Production deployment](../guides/deployment.md) -- Kubernetes, monitoring, and checklists
- [Security Model](../guides/security-model.md) -- defense-in-depth with container isolation
- [Gradio playground](gradio-playground.md) -- interactive browser-based policy testing
- [Policy syntax reference](../guides/policies.md) -- all match patterns, conditions, and operators
