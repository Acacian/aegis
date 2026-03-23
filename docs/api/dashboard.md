# Dashboard API

REST endpoints for the Aegis governance dashboard. All routes are created via `get_dashboard_routes()` and mounted as Starlette routes.

```python
from aegis.server.dashboard_api import get_dashboard_routes

routes = get_dashboard_routes(
    policy=policy,
    audit_logger=audit_logger,
    anomaly_detector=detector,  # optional
)
```

## Endpoints

### `GET /api/v1/dashboard/overview`

Top-level KPIs for the dashboard home page.

**Response:**

| Field | Type | Description |
|-------|------|-------------|
| `total_actions` | `int` | Total audit entries |
| `risk_distribution` | `dict` | Counts by risk level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) |
| `approval_distribution` | `dict` | Counts by approval type (`auto`, `approve`, `block`) |
| `status_distribution` | `dict` | Counts by result status |
| `compliance_score` | `int` | Governance compliance score (0--100) |
| `compliance_grade` | `str` | Letter grade |
| `policy_rule_count` | `int` | Number of policy rules loaded |
| `active_agents` | `int` | Distinct agent IDs in audit log |

### `GET /api/v1/dashboard/stats/timeline`

Action volume over time, bucketed for charting.

**Query params:**

| Param | Default | Description |
|-------|---------|-------------|
| `period` | `"24h"` | `"24h"` (hourly), `"7d"` (6-hour), or `"30d"` (daily) |

**Response:** `{"period": "24h", "buckets": [{"timestamp": "...", "total": N, "blocked": N, "approved": N, "auto": N}, ...]}`

### `GET /api/v1/dashboard/audit/recent`

Paginated audit log entries (newest first).

**Query params:**

| Param | Default | Description |
|-------|---------|-------------|
| `limit` | `50` | Page size |
| `offset` | `0` | Offset for pagination |
| `risk_level` | -- | Filter by risk level |
| `action_type` | -- | Filter by action type |
| `agent_id` | -- | Filter by agent ID |
| `result_status` | -- | Filter by result status |

**Response:** `{"entries": [...], "total": N, "offset": N, "limit": N}`

### `GET /api/v1/dashboard/audit/stats`

Aggregate statistics across all audit entries.

**Response:**

| Field | Type | Description |
|-------|------|-------------|
| `total` | `int` | Total entries |
| `by_risk_level` | `dict` | Counts by risk level |
| `by_approval` | `dict` | Counts by approval type |
| `by_action_type` | `dict` | Top 20 action types by count |
| `by_agent` | `dict` | Counts by agent ID |

### `GET /api/v1/dashboard/policy/summary`

Current policy rules and coverage metadata.

**Response:**

| Field | Type | Description |
|-------|------|-------------|
| `default_risk_level` | `str` | Default risk level |
| `default_approval` | `str` | Default approval mode |
| `rule_count` | `int` | Total rules |
| `rules` | `list` | Array of rule objects (`name`, `match_type`, `match_target`, `risk_level`, `approval`, `conditions`) |
| `has_destructive_blocks` | `bool` | Whether any rule blocks destructive actions |
| `has_approval_gates` | `bool` | Whether any rule requires human approval |

### `GET /api/v1/dashboard/policy/score`

Governance score based on policy configuration.

**Response:** `{"score": N, "grade": "B+", "checks": [{"name": "...", "passed": true, "points": N}, ...]}`

Checks evaluated (100 points total):

| Check | Points |
|-------|--------|
| Has policy rules | 15 |
| Blocks destructive actions | 20 |
| Approval gates for sensitive ops | 15 |
| 3+ policy rules | 10 |
| Target-specific rules | 10 |
| Conditional rules | 10 |
| Non-permissive defaults | 10 |
| All rules named | 10 |

### `GET /api/v1/dashboard/compliance/report`

Generate a compliance report.

**Query params:**

| Param | Default | Description |
|-------|---------|-------------|
| `type` | `"governance"` | `"soc2"`, `"gdpr"`, or `"governance"` |

**Response:** Full `ComplianceReport` as JSON (see [Compliance API](compliance.md#compliancereport)).

### `GET /api/v1/dashboard/compliance/regulatory`

Regulatory gap analysis against a framework.

**Query params:**

| Param | Default | Description |
|-------|---------|-------------|
| `framework` | `"eu_ai_act"` | Regulatory framework identifier |

**Response:**

| Field | Type | Description |
|-------|------|-------------|
| `framework` | `str` | Framework identifier |
| `total_requirements` | `int` | Total requirements in the framework |
| `fully_covered` | `int` | Requirements fully covered by Aegis |
| `partially_covered` | `int` | Partially covered |
| `not_covered` | `int` | Not covered |
| `coverage_score` | `float` | Coverage percentage |
| `gaps` | `list` | Uncovered requirements with details |
| `recommendations` | `list` | Suggested next steps |

### `GET /api/v1/dashboard/anomalies/profiles`

Behavioral profiles for all tracked agents. Returns `{"configured": false}` when no `AnomalyDetector` is configured.

**Response:**

```json
{
  "configured": true,
  "profiles": [
    {
      "agent_id": "agent-1",
      "total_actions": 150,
      "blocked_count": 3,
      "block_rate": 0.02,
      "action_types": {"read_file": 100, "write_file": 50},
      "targets": {"docs": 80, "config": 70},
      "first_seen": "2026-01-01T00:00:00+00:00",
      "last_seen": "2026-03-23T12:00:00+00:00"
    }
  ]
}
```

### `GET /api/v1/dashboard/anomalies/alerts`

Active anomaly alerts derived from agent profiles. Currently flags agents with block rate > 50%.

**Response:** `{"configured": true, "alerts": [{"type": "high_block_rate", "severity": 0.8, "agent_id": "...", "message": "...", "timestamp": "..."}]}`

### `GET /api/v1/dashboard/system/health`

System health check.

**Response:**

| Field | Type | Description |
|-------|------|-------------|
| `status` | `str` | `"ok"` |
| `version` | `str` | Aegis package version |
| `audit_entries` | `int` | Total audit entries in database |
| `policy_rules` | `int` | Number of loaded policy rules |
| `anomaly_detector` | `bool` | Whether anomaly detection is configured |
