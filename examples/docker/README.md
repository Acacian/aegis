# Aegis Docker Deployment

Run the Aegis REST API server in a Docker container.

## Quick Start

```bash
cd examples/docker
docker build -t aegis-server .
docker run -p 8000:8000 aegis-server
```

## With Your Own Policy

```bash
docker run -p 8000:8000 -v $(pwd)/policy.yaml:/app/policy.yaml aegis-server
```

## Test It

```bash
# Evaluate an action (dry-run)
curl -X POST http://localhost:8000/api/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"action_type": "read", "target": "crm"}'
# => {"risk_level": "LOW", "approval": "auto", "is_allowed": true}

curl -X POST http://localhost:8000/api/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"action_type": "delete", "target": "crm"}'
# => {"risk_level": "CRITICAL", "approval": "block", "is_allowed": false}
```

## Docker Compose

```yaml
services:
  aegis:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./policy.yaml:/app/policy.yaml
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/v1/health"]
      interval: 30s
      timeout: 5s
      retries: 3
```
