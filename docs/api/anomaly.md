# Anomaly Detection

## AnomalyDetector

Stateful behavioral anomaly detector that builds per-agent profiles over time. Flags rate spikes, bursts, unknown action types, unusual targets, and high block rates without requiring explicit YAML rules.

Thread-safe: all profile mutations use per-agent locks.

```python
from aegis.core.anomaly import AnomalyDetector

detector = AnomalyDetector(
    rate_threshold=5.0,       # multiplier over avg rate before flagging
    burst_window=60.0,        # seconds for burst detection window
    burst_limit=10,           # max actions in burst_window
    new_action_alert=True,    # flag first-ever action type per agent
    block_rate_threshold=0.5, # fraction of blocked actions before flagging
)
```

### `record(action, agent_id="default", *, blocked=False) -> None`

Record an action to build/update the behavior profile.

| Param | Type | Description |
|-------|------|-------------|
| `action` | `Action` | The action being performed |
| `agent_id` | `str` | Agent identifier |
| `blocked` | `bool` | Whether the action was blocked by policy |

```python
from aegis.core.action import Action

action = Action(type="read_file", target="docs", description="Read docs")
detector.record(action, agent_id="agent-1")
detector.record(action, agent_id="agent-1", blocked=True)
```

### `check(action, agent_id="default") -> AnomalyResult`

Check whether an action is anomalous for the given agent. Returns `AnomalyResult` with `is_anomalous=True` when a problem is detected.

Returns OK (no anomaly) when no profile exists yet -- anomalies require history.

Anomaly types detected:

| Type | Description |
|------|-------------|
| `new_action` | Action type never seen before for this agent |
| `unusual_target` | Target never seen before for this agent |
| `rate_spike` | Rate exceeds `avg * rate_threshold` |
| `burst` | More than `burst_limit` actions within `burst_window` |
| `high_block_rate` | Blocked fraction exceeds `block_rate_threshold` |

```python
result = detector.check(action, agent_id="agent-1")
if result.is_anomalous:
    print(f"[{result.anomaly_type}] severity={result.severity:.2f}: {result.message}")
```

### `get_profile(agent_id) -> BehaviorProfile | None`

Return the profile for the given agent, or `None` if no data has been recorded.

### `generate_policy(agent_id) -> dict`

Generate a YAML-ready policy dict from observed behavior. Read-like actions get `auto` approval, write-like actions get `approve`, and common destructive patterns never observed get `block`.

Returns an empty dict when no profile exists.

```python
policy_dict = detector.generate_policy("agent-1")
# {'version': '1', 'defaults': {...}, 'rules': [...]}
```

### `reset(agent_id=None) -> None`

Clear profile data. When `agent_id` is given, only that agent's profile is removed. Otherwise all profiles are cleared.

## BehaviorProfile

Per-agent behavioral statistics accumulated over time.

```python
from aegis.core.anomaly import BehaviorProfile
```

| Field | Type | Description |
|-------|------|-------------|
| `agent_id` | `str` | Agent identifier |
| `action_counts` | `dict[str, int]` | Action type to total count |
| `action_rate` | `dict[str, list[float]]` | Action type to recent timestamps |
| `avg_rate_per_minute` | `dict[str, float]` | Smoothed rate per action type |
| `target_counts` | `dict[str, int]` | Target to total count |
| `blocked_count` | `int` | Number of blocked actions |
| `total_actions` | `int` | Total actions recorded |
| `first_seen` | `datetime` | First recorded action timestamp |
| `last_seen` | `datetime` | Most recent action timestamp |

## AnomalyResult

Frozen dataclass returned by `AnomalyDetector.check()`.

| Field | Type | Description |
|-------|------|-------------|
| `is_anomalous` | `bool` | `True` when an anomaly was detected |
| `anomaly_type` | `str \| None` | Classification (e.g. `"rate_spike"`, `"burst"`) |
| `severity` | `float` | 0.0 (benign) to 1.0 (critical) |
| `message` | `str` | Human-readable explanation |
| `recommendation` | `str` | Suggested policy action |
