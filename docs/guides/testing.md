# Testing Guide

How to run, write, and extend the Aegis test suite.

## Running Tests

```bash
# Full suite (verbose)
make test

# Or directly with pytest
pytest tests/ -v

# Single file
pytest tests/test_runtime.py -v

# Single test
pytest tests/test_runtime.py::test_plan_evaluates_actions -v

# With coverage report
make coverage
# Generates htmlcov/index.html + terminal summary
```

## Test Structure

```
tests/
├── conftest.py              # Shared fixtures (FakeExecutor, sample_policy, runtime)
├── test_runtime.py          # Core runtime engine tests
├── test_policy.py           # Policy loading and evaluation
├── test_action.py           # Action model
├── test_conditions.py       # Time/param-based policy conditions
├── test_approval.py         # Approval handlers
├── test_audit.py            # Audit logger (SQLite)
├── test_audit_export.py     # JSONL export
├── test_audit_logging.py    # Python logging backend
├── test_schema.py           # Policy JSON schema
├── test_cli.py              # CLI commands
├── test_adapters.py         # Adapter import guards
├── test_anthropic_adapter.py
├── test_httpx_adapter.py
├── test_playwright_adapter.py
├── test_langchain_adapter.py
├── test_crewai_adapter.py
├── test_openai_agents_adapter.py
└── ...
```

## Shared Fixtures (`conftest.py`)

`tests/conftest.py` provides reusable fixtures available to all test files:

```python
from tests.conftest import FakeExecutor  # records calls, configurable failures

# Fixtures available via pytest injection:
# sample_policy  — Policy with read(AUTO), write(APPROVE), delete(BLOCK) rules
# fake_executor  — FakeExecutor instance
# runtime        — Pre-configured Runtime with fake executor + auto-approval + tmp audit DB
```

**FakeExecutor** is the go-to mock for testing anything that needs a `BaseExecutor`:

```python
class FakeExecutor(BaseExecutor):
    def __init__(self, fail_on: set[str] | None = None) -> None:
        self.executed: list[Action] = []   # inspect what was executed
        self._fail_on = fail_on or set()   # action types that return FAILED

    async def execute(self, action: Action) -> Result:
        self.executed.append(action)
        if action.type in self._fail_on:
            return Result(action=action, status=ResultStatus.FAILED, ...)
        return Result(action=action, status=ResultStatus.SUCCESS, ...)
```

## Writing Async Tests

All async tests use **pytest-asyncio** with `asyncio_mode = "auto"` (configured in `pyproject.toml`). Simply mark tests with `@pytest.mark.asyncio`:

```python
import pytest
from aegis.core.action import Action

@pytest.mark.asyncio
async def test_run_one_convenience(tmp_path):
    executor = FakeExecutor()
    runtime = _make_runtime(tmp_path, executor=executor)
    result = await runtime.run_one(Action("read", "salesforce"))

    assert result.ok
    assert len(executor.executed) == 1
```

Use `tmp_path` (pytest built-in) for any test that needs a temporary database:

```python
from aegis.runtime.audit import AuditLogger

audit = AuditLogger(db_path=tmp_path / "test.db")
```

## Mocking Adapters

Adapters that depend on external libraries (httpx, playwright, etc.) are tested by mocking the underlying client. The pattern:

### 1. Mock the response object

```python
from unittest.mock import AsyncMock, MagicMock

mock_response = MagicMock()
mock_response.status_code = 200
mock_response.is_success = True
mock_response.json.return_value = {"id": 1, "name": "Alice"}
```

### 2. Inject the mock client

```python
from aegis.adapters.httpx_adapter import HttpxExecutor

executor = HttpxExecutor(base_url="https://api.example.com")
mock_client = AsyncMock()
mock_client.request = AsyncMock(return_value=mock_response)
executor._client = mock_client  # bypass setup()
```

### 3. Assert on results

```python
action = Action("get", "/users/1")
result = await executor.execute(action)

assert result.status == ResultStatus.SUCCESS
assert result.data["body"] == {"id": 1, "name": "Alice"}
mock_client.request.assert_called_once()
```

### Testing import guards

Every adapter has a guard that raises `ImportError` when its optional dependency is missing:

```python
def test_import_guard():
    import sys
    saved = sys.modules.pop("httpx", None)
    sys.modules["httpx"] = None
    try:
        from aegis.adapters.httpx_adapter import _require_httpx
        with pytest.raises(ImportError, match="httpx"):
            _require_httpx()
    finally:
        if saved:
            sys.modules["httpx"] = saved
        else:
            sys.modules.pop("httpx", None)
```

## Coverage Goals

Target: **98%+ line coverage**.

```bash
make coverage
# pytest tests/ --cov=aegis --cov-report=term-missing --cov-report=html
```

The coverage configuration in `pyproject.toml` excludes lines that cannot be meaningfully tested:

```toml
[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "if TYPE_CHECKING:",
    "if __name__ ==",
    "raise NotImplementedError",
    "\\.\\.\\.",
]
```

## Adding Tests for a New Adapter

When you add a new adapter (e.g., `src/aegis/adapters/my_adapter.py`):

1. **Create the test file**: `tests/test_my_adapter.py`

2. **Test the import guard** -- every adapter with an optional dependency needs one:

    ```python
    def test_my_adapter_import_guard():
        try:
            from aegis.adapters.my_adapter import MyExecutor
            MyExecutor()
        except ImportError as e:
            assert "my-library" in str(e)
    ```

3. **Test execute() with mocked dependencies** -- follow the mock injection pattern above.

4. **Test error paths** -- network errors, unsupported action types, bad responses:

    ```python
    @pytest.mark.asyncio
    async def test_execute_error_handling():
        executor, mock_client = setup_mocked_executor()
        mock_client.request = AsyncMock(side_effect=Exception("Network error"))

        result = await executor.execute(Action("get", "/test"))
        assert result.status == ResultStatus.FAILED
        assert "Network error" in result.error
    ```

5. **Test with the runtime** -- verify end-to-end governance works:

    ```python
    @pytest.mark.asyncio
    async def test_my_adapter_with_runtime(tmp_path):
        from aegis.runtime.engine import Runtime
        from aegis.runtime.approval import AutoApprovalHandler
        from aegis.runtime.audit import AuditLogger

        runtime = Runtime(
            executor=MyExecutor(...),
            policy=Policy(rules=[
                PolicyRule(match_type="*", approval=Approval.AUTO, risk_level=RiskLevel.LOW),
            ]),
            approval_handler=AutoApprovalHandler(),
            audit_logger=AuditLogger(db_path=tmp_path / "test.db"),
        )
        result = await runtime.run_one(Action("read", "target"))
        assert result.ok
    ```

6. **Run the full check pipeline** before submitting:

    ```bash
    ruff check src/ tests/
    ruff format --check src/ tests/
    mypy src/aegis/
    pytest tests/ -v --cov=aegis
    ```
