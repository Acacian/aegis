# Security Model

Aegis is an **application-level middleware**, not an OS-level sandbox. Understanding this boundary helps you build the right defense-in-depth strategy.

## What Aegis Controls

Aegis governs every action that flows through `runtime.run_one()` or `runtime.execute()`:

| Layer | What Aegis Does |
|---|---|
| **Action classification** | Maps actions to risk levels via YAML policy rules |
| **Approval gates** | Blocks, auto-approves, or requests human approval |
| **Audit trail** | Logs every decision and result to SQLite/JSONL/webhook |
| **Execution control** | Only executes actions that pass policy + approval |

## What Aegis Does NOT Control

Aegis does **not** prevent code that bypasses the runtime:

```python
# Governed by Aegis
result = await runtime.run_one(Action("delete", "database"))  # -> BLOCKED

# NOT governed - direct call bypasses Aegis entirely
os.system("rm -rf /data")
```

This is by design. Aegis is a **governance layer**, not a sandbox. It's the developer's responsibility to route all agent actions through the Aegis runtime.

## Defense in Depth: Aegis + Container Isolation

For production deployments, combine Aegis with OS-level isolation:

```
┌─────────────────────────────────────────┐
│  Container (Docker / gVisor / VM)       │  <- OS-level isolation
│  ┌───────────────────────────────────┐  │
│  │  AI Agent Process                 │  │
│  │  ┌─────────────────────────────┐  │  │
│  │  │  Aegis Runtime              │  │  │  <- Action-level governance
│  │  │  Policy → Approve → Execute │  │  │
│  │  └─────────────────────────────┘  │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

### Docker Example

```dockerfile
FROM python:3.12-slim

# Run as non-root
RUN useradd -m agent
USER agent

# Install only what the agent needs
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY policy.yaml agent.py ./

# No shell access, no filesystem write outside /tmp
CMD ["python", "agent.py"]
```

```yaml
# docker-compose.yml
services:
  agent:
    build: .
    read_only: true           # Read-only filesystem
    tmpfs: /tmp                # Writable temp only
    security_opt:
      - no-new-privileges      # No privilege escalation
    networks:
      - agent-net              # Restricted network
    cap_drop:
      - ALL                    # Drop all Linux capabilities

networks:
  agent-net:
    driver: bridge
```

### What Each Layer Handles

| Threat | Aegis | Container |
|---|---|---|
| Agent calls dangerous API | Policy blocks or requires approval | - |
| Agent tries bulk delete | Risk level = critical, blocked | - |
| Agent runs at 3am | Time condition blocks | - |
| Agent tries `os.system()` | Not governed (bypasses runtime) | Blocked by seccomp/capabilities |
| Agent tries network escape | Not governed | Blocked by network policy |
| Agent tries filesystem write | Not governed | Blocked by read-only FS |
| Prompt injection → tool abuse | Governed if routed through runtime | Limits blast radius |

## Recommendations by Environment

### Development / Prototyping

Aegis alone is sufficient:

```python
runtime = Runtime(executor=my_executor, policy=Policy.from_yaml("policy.yaml"))
```

### Staging / Internal Tools

Add basic container isolation:

```bash
docker run --read-only --cap-drop=ALL --network=agent-net agent-image
```

### Production / Customer-Facing

Full defense in depth:

1. **Aegis** -- action governance, approval gates, audit trail
2. **Container** -- OS isolation, filesystem restrictions, network policy
3. **IAM** -- least-privilege API credentials (only what the agent needs)
4. **Monitoring** -- alert on blocked actions, unusual patterns

## Summary

Think of it like corporate security:

- **Aegis** = the approval process ("you need manager sign-off for purchases over $1000")
- **Container** = the building security ("you can't access the server room")
- **IAM** = the badge system ("you only have access to floor 3")

Each layer catches what the others miss. Aegis is the governance brain; containers and IAM are the physical locks.
