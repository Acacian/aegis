# Audit Logger

## AuditLogger (SQLite)

```python
from aegis.runtime.audit import AuditLogger

logger = AuditLogger(db_path="aegis_audit.db")
```

### `log(session_id, decision, *, result=None, human_decision=None) -> int`

Write one audit entry. Returns the row ID.

### `get_log(session_id=None) -> list[dict]`

Retrieve entries, optionally filtered by session.

### `export_jsonl(path, session_id=None) -> int`

Export entries as JSON Lines (one JSON object per line). Returns the count of exported entries.

```python
count = logger.export_jsonl("audit.jsonl", session_id="session-123")
```

### `close()`

Close the database connection.

## LoggingAuditLogger (Python logging)

Drop-in replacement that emits structured JSON to Python's `logging` module instead of SQLite.

```python
import logging
from aegis.runtime.audit_logging import LoggingAuditLogger

logging.basicConfig(level=logging.DEBUG)
audit = LoggingAuditLogger()  # Uses logger "aegis.audit"

runtime = Runtime(executor=..., policy=..., audit_logger=audit)
```

Risk levels map to log levels:

| Risk Level | Log Level |
|-----------|-----------|
| LOW | DEBUG |
| MEDIUM | INFO |
| HIGH | WARNING |
| CRITICAL | ERROR |

This is ideal for cloud-native deployments where you want to pipe audit data to log aggregators (DataDog, CloudWatch, ELK) instead of local SQLite.

## Schema

Each audit entry contains:

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Auto-incrementing primary key |
| `session_id` | TEXT | Groups related actions |
| `timestamp` | TEXT | ISO 8601 UTC timestamp |
| `action_type` | TEXT | The action type |
| `action_target` | TEXT | The target system |
| `action_params` | TEXT | JSON-serialized params |
| `action_desc` | TEXT | Human-readable description |
| `risk_level` | TEXT | LOW, MEDIUM, HIGH, CRITICAL |
| `approval` | TEXT | auto, approve, block |
| `matched_rule` | TEXT | Which policy rule matched |
| `human_decision` | TEXT | approved, denied, or NULL |
| `result_status` | TEXT | success, failed, blocked, denied, skipped |
| `result_data` | TEXT | JSON-serialized result data |
| `result_error` | TEXT | Error message if failed |

## CLI

```bash
# Table format
aegis audit

# JSON format
aegis audit --format json

# JSONL export
aegis audit --format jsonl -o audit_export.jsonl

# Filter by session
aegis audit --session abc123

# Custom database
aegis audit --db /path/to/audit.db
```

## In-Memory Database

For testing, use SQLite's in-memory mode:

```python
logger = AuditLogger(db_path=":memory:")
```
