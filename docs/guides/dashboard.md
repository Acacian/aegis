---
description: "Aegis governance dashboard: built-in web UI for real-time AI agent monitoring. No frontend build, no npm, no webpack — just start the Python server."
---

# Governance Dashboard

Aegis includes a built-in web dashboard for real-time monitoring of AI agent governance. No separate frontend build, no npm, no webpack — just start the server.

## Quick Start

```bash
pip install 'agent-aegis[server]'
aegis serve policy.yaml
# Open http://localhost:8000
```

Or programmatically:

```python
from aegis.server.app import create_app

app = create_app(
    policy_path="policy.yaml",
    audit_db_path="audit.db",
    enable_dashboard=True,
)
# Run with any ASGI server: uvicorn, hypercorn, daphne
```

## Dashboard Pages

### Overview

The landing page shows key governance metrics at a glance:

- **KPI Cards**: Total actions, blocked threats, compliance grade, active agents
- **Action Volume Chart**: Time-series of actions over the last 24h/7d/30d
- **Risk Distribution**: Doughnut chart showing LOW/MEDIUM/HIGH/CRITICAL breakdown
- **Approval Distribution**: Progress bars for auto/approve/block ratios

### Audit Log

Complete history of every agent action and policy decision:

- Filter by risk level, action type, agent ID, result status
- Paginated results with newest-first ordering
- Each entry shows timestamp, action, target, agent, risk, approval, matched rule, status

### Policy

View and assess your current policy configuration:

- **Governance Score**: 0-100 score with letter grade (A+ through F)
- **Score Breakdown**: Checklist showing which governance criteria are met
- **Rules Table**: All policy rules with match patterns, risk levels, and approval settings

### Anomalies

Behavioral profiling and anomaly detection (requires `AnomalyDetector`):

- **Agent Profiles**: Per-agent action counts, block rates, action types, last seen
- **Alerts**: Active anomalies like high block rates or rate spikes

```python
from aegis.core.anomaly import AnomalyDetector
from aegis.server.app import create_app

detector = AnomalyDetector()
app = create_app(
    policy_path="policy.yaml",
    anomaly_detector=detector,  # Enable anomaly pages
)
```

### Compliance

Generate compliance reports directly from your audit data:

- **Report Types**: SOC2, GDPR, Governance
- **Findings**: Each finding shows severity, status (PASS/WARN/FAIL), and recommendations
- **Scoring**: Numeric score (0-100) with letter grade

### Regulatory

Gap analysis against major regulatory frameworks:

- **EU AI Act** (Regulation 2024/1689)
- **NIST AI RMF** (AI 100-1)
- **SOC2** Trust Services Criteria
- **ISO 42001** AI Management System

Shows coverage percentage, gaps, and actionable recommendations.

### System

Infrastructure health and configuration status.

## API Endpoints

All dashboard data is available via REST API:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/dashboard/overview` | KPI metrics |
| GET | `/api/v1/dashboard/stats/timeline` | Time-series data |
| GET | `/api/v1/dashboard/audit/recent` | Paginated audit log |
| GET | `/api/v1/dashboard/audit/stats` | Audit statistics |
| GET | `/api/v1/dashboard/policy/summary` | Current policy rules |
| GET | `/api/v1/dashboard/policy/score` | Governance score |
| GET | `/api/v1/dashboard/compliance/report` | Compliance report |
| GET | `/api/v1/dashboard/compliance/regulatory` | Regulatory gap analysis |
| GET | `/api/v1/dashboard/anomalies/profiles` | Agent behavior profiles |
| GET | `/api/v1/dashboard/anomalies/alerts` | Anomaly alerts |
| GET | `/api/v1/dashboard/system/health` | System health |

### Query Parameters

**Timeline**: `?period=24h|7d|30d`

**Audit**: `?limit=50&offset=0&risk_level=HIGH&action_type=read&agent_id=agent-1&result_status=success`

**Compliance**: `?type=soc2|gdpr|governance`

**Regulatory**: `?framework=eu_ai_act|nist_ai_rmf|soc2|iso_42001`

## Disabling the Dashboard

```python
app = create_app(
    policy_path="policy.yaml",
    enable_dashboard=False,  # API-only mode
)
```

Or via CLI:

```bash
aegis serve policy.yaml --no-dashboard
```

## Demo

Try the dashboard with sample data:

```bash
python examples/dashboard_demo.py
# Generates 250 realistic audit entries and launches at http://localhost:8000
```
