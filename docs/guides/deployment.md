---
description: "Deploy Aegis in production with Docker, Kubernetes, or pip. Includes monitoring, hardening, and REST API server configuration."
---

# Production Deployment

This guide covers deploying Aegis in production -- from a minimal pip install to Kubernetes manifests with monitoring and hardening.

## Quick Deploy

The fastest path to a running Aegis server:

```bash
pip install 'agent-aegis[server]'
aegis init                          # generates policy.yaml
aegis validate policy.yaml          # verify before serving
aegis serve policy.yaml --port 8000
```

Test that it works:

```bash
curl http://localhost:8000/health
# => {"status": "ok", "version": "0.6.1"}

curl -X POST http://localhost:8000/api/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"action_type": "read", "target": "crm"}'
# => {"risk_level": "LOW", "approval": "auto", "is_allowed": true}
```

!!! warning "Auto-Approval Default"
    The REST server uses `AutoApprovalHandler` by default -- all approval-required
    actions are auto-approved. For production, deploy behind an authenticating
    reverse proxy and implement a custom approval handler.

---

## Docker Deployment

Aegis ships with a production-ready Dockerfile at `examples/docker/`.

### Build and Run

```bash
docker build -t aegis-server examples/docker/
docker run -p 8000:8000 aegis-server
```

### Mount Your Own Policy

```bash
docker run -p 8000:8000 \
  -v $(pwd)/policy.yaml:/app/policy.yaml \
  aegis-server
```

### Docker Compose

```yaml
services:
  aegis:
    build: examples/docker/
    ports:
      - "8000:8000"
    volumes:
      - ./policy.yaml:/app/policy.yaml
      - aegis-data:/app/data          # persistent audit DB
    environment:
      - AEGIS_LOG_LEVEL=INFO
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/v1/health"]
      interval: 30s
      timeout: 5s
      retries: 3
    read_only: true
    tmpfs: /tmp
    security_opt:
      - no-new-privileges
    cap_drop:
      - ALL

volumes:
  aegis-data:
```

!!! tip "Defense in Depth"
    The `read_only`, `cap_drop`, and `no-new-privileges` settings add OS-level
    isolation on top of Aegis policy governance. See the
    [Security Model](security-model.md) guide for the full layering strategy.

### Custom Image

For production images, pin the version and run as non-root:

```dockerfile
FROM python:3.12-slim

RUN useradd -m aegis
WORKDIR /home/aegis

RUN pip install --no-cache-dir 'agent-aegis[server]==0.6.1'

COPY policy.yaml .

USER aegis
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')" || exit 1

ENTRYPOINT ["aegis", "serve", "policy.yaml", "--host", "0.0.0.0", "--port", "8000"]
```

---

## Kubernetes

A minimal Kubernetes deployment for Aegis.

### Deployment + Service

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aegis-server
  labels:
    app: aegis
spec:
  replicas: 2
  selector:
    matchLabels:
      app: aegis
  template:
    metadata:
      labels:
        app: aegis
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      containers:
        - name: aegis
          image: your-registry/aegis-server:0.6.1
          ports:
            - containerPort: 8000
          env:
            - name: AEGIS_LOG_LEVEL
              value: "INFO"
          volumeMounts:
            - name: policy
              mountPath: /app/policy.yaml
              subPath: policy.yaml
              readOnly: true
            - name: audit-data
              mountPath: /app/data
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
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 256Mi
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
      volumes:
        - name: policy
          configMap:
            name: aegis-policy
        - name: audit-data
          persistentVolumeClaim:
            claimName: aegis-audit-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: aegis-server
spec:
  selector:
    app: aegis
  ports:
    - port: 8000
      targetPort: 8000
  type: ClusterIP
```

### Policy as ConfigMap

```bash
kubectl create configmap aegis-policy --from-file=policy.yaml
```

To update the policy without restarting pods, use the hot-reload endpoint:

```bash
curl -X PUT http://aegis-server:8000/api/v1/policy \
  -H "Content-Type: application/json" \
  -d '{"yaml": "'"$(cat policy.yaml)"'"}'
```

!!! note "Scaling Considerations"
    Each Aegis replica maintains its own in-process policy and SQLite audit DB.
    For multi-replica deployments, use `LoggingAuditLogger` to send structured
    audit events to a centralized log aggregator (DataDog, CloudWatch, ELK)
    instead of local SQLite.

---

## Environment Variables

Aegis uses these environment variables for configuration:

| Variable | Default | Description |
|----------|---------|-------------|
| `AEGIS_POLICY_PATH` | `policy.yaml` | Path to the YAML policy file |
| `AEGIS_LOG_LEVEL` | `WARNING` | Python log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `AEGIS_AUDIT_DB` | `aegis_audit.db` | Path to the SQLite audit database |
| `NO_COLOR` | _(unset)_ | Disable colored CLI output ([no-color.org](https://no-color.org/)) |

### CLI Flag Equivalents

```bash
# These are equivalent:
export AEGIS_LOG_LEVEL=DEBUG
aegis serve policy.yaml --port 8000

aegis serve policy.yaml --port 8000  # with AEGIS_LOG_LEVEL=DEBUG in env
```

### Python Logging Configuration

For fine-grained control, configure Python's logging directly:

```python
import logging

logging.basicConfig(level=logging.INFO)
logging.getLogger("aegis").setLevel(logging.DEBUG)       # Aegis internals
logging.getLogger("aegis.audit").setLevel(logging.INFO)  # Audit events
logging.getLogger("aegis.server").setLevel(logging.INFO) # Server requests
```

---

## Monitoring

### Health Checks

The `/health` endpoint returns the server status and version:

```bash
curl http://localhost:8000/health
# => {"status": "ok", "version": "0.6.1"}
```

Use this for:

- Docker `HEALTHCHECK` (built into the provided Dockerfile)
- Kubernetes `livenessProbe` and `readinessProbe`
- Load balancer health checks
- Uptime monitoring (Pingdom, UptimeRobot, etc.)

### Metrics via Audit Log

Aegis does not expose a `/metrics` endpoint, but the audit log provides full observability. Query it programmatically or via the CLI:

```bash
# Summary statistics per rule
aegis stats

# Tail the audit log (1-second polling)
aegis audit --tail

# Filter high-risk decisions
aegis audit --risk-level HIGH --format json

# Export for analysis
aegis audit --format jsonl -o audit_export.jsonl
```

For the REST API:

```bash
# Query blocked actions
curl "http://localhost:8000/api/v1/audit?result_status=blocked&limit=50"

# Query by risk level
curl "http://localhost:8000/api/v1/audit?risk_level=CRITICAL"
```

### Cloud-Native Audit Pipeline

For production, use `LoggingAuditLogger` to route audit events to your log aggregator instead of local SQLite:

```python
import logging
from aegis import Runtime, Policy
from aegis.runtime.audit_logging import LoggingAuditLogger

# Configure root logger for your aggregator (DataDog, CloudWatch, ELK, etc.)
logging.basicConfig(level=logging.INFO, format="%(message)s")

audit = LoggingAuditLogger()  # Emits structured JSON to "aegis.audit" logger

runtime = Runtime(
    executor=my_executor,
    policy=Policy.from_yaml("policy.yaml"),
    audit_logger=audit,
)
```

Risk levels map to Python log levels:

| Risk Level | Log Level |
|-----------|-----------|
| LOW | DEBUG |
| MEDIUM | INFO |
| HIGH | WARNING |
| CRITICAL | ERROR |

### Audit Log Rotation

For SQLite-based audit (the default), manage database size with periodic export and rotation:

```bash
#!/bin/bash
# rotate-audit.sh -- run via cron (e.g., daily at midnight)

AUDIT_DB="/app/data/aegis_audit.db"
ARCHIVE_DIR="/app/data/archive"
DATE=$(date +%Y-%m-%d)

mkdir -p "$ARCHIVE_DIR"

# Export current entries to JSONL
aegis audit --db "$AUDIT_DB" --format jsonl -o "$ARCHIVE_DIR/audit-$DATE.jsonl"

# Compress the archive
gzip "$ARCHIVE_DIR/audit-$DATE.jsonl"

# Optional: prune old entries (keep last 30 days in active DB)
sqlite3 "$AUDIT_DB" "DELETE FROM audit_log WHERE timestamp < datetime('now', '-30 days');"
sqlite3 "$AUDIT_DB" "VACUUM;"
```

!!! tip "Prefer LoggingAuditLogger in Production"
    If you use a centralized log aggregator, `LoggingAuditLogger` eliminates the
    need for SQLite rotation entirely. Let your aggregator handle retention,
    search, and alerting.

---

## Production Checklist

Use this checklist before going live. See the [Governance Checklist](governance-checklist.md) for the full agent-level audit.

### Policy

- [ ] **Fail-closed defaults** -- set `defaults.approval: block` so unmatched actions are denied:

    ```yaml
    defaults:
      risk_level: high
      approval: block    # unknown actions are blocked, not approved
    ```

- [ ] **Validate before deploy** -- run `aegis validate policy.yaml` in CI
- [ ] **Version control** -- policy YAML is checked into git with change history
- [ ] **Policy backup** -- store a copy of the active policy alongside audit archives

### Audit

- [ ] **Persistent storage** -- audit DB is on a mounted volume, not ephemeral container FS
- [ ] **Export pipeline** -- JSONL exports run on a schedule for compliance archival
- [ ] **Retention policy** -- define how long audit data is kept (e.g., 90 days active, 1 year archived)

### Security

- [ ] **Non-root container** -- run as unprivileged user (`USER aegis` in Dockerfile)
- [ ] **Read-only filesystem** -- container FS is read-only with `/tmp` as tmpfs
- [ ] **Drop all capabilities** -- `cap_drop: ALL` in Docker / `drop: ["ALL"]` in K8s
- [ ] **No privilege escalation** -- `no-new-privileges` / `allowPrivilegeEscalation: false`
- [ ] **Reverse proxy** -- deploy behind nginx/Caddy/cloud LB with TLS termination
- [ ] **Network policy** -- restrict which services can reach the Aegis server

### Operational

- [ ] **Health checks** -- liveness and readiness probes configured
- [ ] **Resource limits** -- CPU and memory limits set to prevent runaway processes
- [ ] **Pin versions** -- use exact version (`agent-aegis==0.6.1`), not ranges
- [ ] **Hot-reload tested** -- verify `PUT /api/v1/policy` works without downtime
- [ ] **Alerting** -- set up alerts on blocked/critical audit events

### Pre-Flight Validation

Run this before each deployment:

```bash
# 1. Validate policy syntax
aegis validate policy.yaml

# 2. Simulate key scenarios
aegis simulate policy.yaml --action '{"type": "read", "target": "crm"}'
aegis simulate policy.yaml --action '{"type": "delete", "target": "db"}'

# 3. Verify the image starts and responds
docker run --rm -d --name aegis-test -p 8001:8000 aegis-server
curl -sf http://localhost:8001/health && echo "OK" || echo "FAIL"
docker stop aegis-test
```

---

## Further Reading

- [Security Model](security-model.md) -- defense-in-depth with container isolation
- [REST API Server](rest-api.md) -- full endpoint reference
- [Audit Logger](../api/audit.md) -- audit schema and export formats
- [Policy Patterns](policy-patterns.md) -- production policy examples
- [Governance Checklist](governance-checklist.md) -- full agent governance audit
