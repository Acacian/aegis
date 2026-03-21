# Troubleshooting

## Installation Issues

### `ImportError: No module named 'aegis'`

The PyPI package is `agent-aegis`, but you import as `aegis`:

```bash
pip install agent-aegis
```

```python
from aegis import Runtime, Policy  # Correct
```

### `ImportError: langchain-core is required`

Install the optional dependency for your adapter:

```bash
pip install 'agent-aegis[langchain]'
# or
pip install 'agent-aegis[playwright]'
# or
pip install 'agent-aegis[all]'
```

### `Python version error`

Aegis requires Python 3.11+. Check your version:

```bash
python --version  # Must be 3.11 or higher
```

## Policy Issues

### `Policy validation failed: ...`

Run `aegis validate` for details:

```bash
aegis validate policy.yaml
```

Common causes:
- Invalid `risk_level` (must be: low, medium, high, critical)
- Invalid `approval` (must be: auto, approve, block)
- Missing `version` field
- YAML syntax errors

### Rules not matching as expected

Rules are evaluated **top to bottom, first match wins**. Check order:

```python
from aegis import Action, Policy

policy = Policy.from_yaml("policy.yaml")
decision = policy.evaluate(Action("your_action", "your_target"))
print(f"Matched rule: {decision.matched_rule}")
print(f"Risk: {decision.risk_level}, Approval: {decision.approval}")
```

### Conditions not working

- Time conditions use **UTC**, not local time
- `weekdays` uses ISO weekday numbers: 1=Monday, 7=Sunday
- `param_*` conditions check `action.params` — make sure your action has the expected params

## Runtime Issues

### `RuntimeError: This event loop is already running`

This happens when calling `asyncio.run()` inside an existing event loop (e.g., Jupyter). Use:

```python
import nest_asyncio
nest_asyncio.apply()
```

Or use `await` directly in async contexts:

```python
results = await runtime.execute(plan)
```

### Actions are blocked unexpectedly

Check which rule matched:

```python
plan = runtime.plan([your_action])
print(plan.summary())
```

### Audit log is empty

Make sure you're checking the right database file:

```bash
aegis audit --db path/to/your/aegis_audit.db
```

The default is `aegis_audit.db` in the current directory.

## Adapter Issues

### Playwright: `BrowserType.launch: Executable doesn't exist`

Install browser binaries:

```bash
playwright install chromium
```

### httpx: Connection errors

Check that your base URL is correct and the service is reachable:

```python
executor = HttpxExecutor(base_url="https://api.example.com")
# Make sure the URL doesn't have a trailing path
```

## Server Issues

### `aegis serve` fails to start

Make sure you have the server extra installed:

```bash
pip install 'agent-aegis[server]'
aegis serve policy.yaml --port 8000
```

### CORS errors from browser

The Aegis REST API server includes CORS headers by default. If you're still getting errors, check that you're hitting the right port and the server is running.

### Request body too large

The server limits request bodies to 1MB by default. For bulk operations, consider splitting into smaller batches.

## Performance Issues

### Policy evaluation is slow

If you have many rules (100+), ensure you're using the latest version which includes compiled glob caching. Policy evaluation should be < 1ms for typical policies.

### Audit log database grows too large

Use JSONL export and rotate:

```bash
aegis audit --format jsonl -o audit-$(date +%Y%m%d).jsonl
```

The in-memory audit logger caps at 10,000 entries by default. The SQLite logger is append-only and should be rotated externally.

## Migration

### Upgrading from 0.1.x to 0.1.3+

No breaking changes. New features are additive. If you're using the REST API server, check the [server docs](guides/rest-api.md) for new endpoints.

### Upgrading from 0.1.3 to 0.1.4+

No breaking changes. Unknown conditions now fail-closed (return `False`) instead of fail-open. If you have custom conditions that relied on unknown operators passing, update your policies.

## Getting Help

- [GitHub Discussions](https://github.com/Acacian/aegis/discussions) — questions, ideas, show & tell
- [GitHub Issues](https://github.com/Acacian/aegis/issues) — bug reports and feature requests
- [Documentation](https://acacian.github.io/aegis/) — full guides and API reference
