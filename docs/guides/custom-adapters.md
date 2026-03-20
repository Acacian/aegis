# Custom Adapters

Build your own executor to connect Aegis to any system.

## The BaseExecutor Interface

```python
from aegis.adapters.base import BaseExecutor
from aegis.core.action import Action
from aegis.core.result import Result, ResultStatus

class MyExecutor(BaseExecutor):
    async def execute(self, action: Action) -> Result:
        """Required: execute a single action."""
        ...

    async def verify(self, action: Action, result: Result) -> bool:
        """Optional: verify the action completed correctly."""
        return result.ok

    async def setup(self) -> None:
        """Optional: initialize resources (called once before execution)."""

    async def teardown(self) -> None:
        """Optional: clean up resources (called once after execution)."""
```

Only `execute()` is required. The others have sensible defaults.

## Built-in: HttpxExecutor

For REST APIs, use the built-in `HttpxExecutor` instead of building your own:

```python
from aegis.adapters.httpx_adapter import HttpxExecutor

executor = HttpxExecutor(
    base_url="https://api.example.com",
    default_headers={"Authorization": "Bearer ..."},
    timeout=30.0,
)
runtime = Runtime(executor=executor, policy=Policy.from_yaml("policy.yaml"))

# Action types map to HTTP methods: get, post, put, patch, delete
plan = runtime.plan([
    Action("get", "/users"),
    Action("post", "/users", params={"json": {"name": "Alice"}}),
])
```

Install with: `pip install 'agent-aegis[httpx]'`

## Example: Custom REST API Executor

If you need custom behavior beyond what `HttpxExecutor` provides:

```python
import httpx
from aegis.adapters.base import BaseExecutor
from aegis.core.action import Action
from aegis.core.result import Result, ResultStatus

class MyAPIExecutor(BaseExecutor):
    def __init__(self, base_url: str, headers: dict | None = None):
        self._base_url = base_url
        self._headers = headers or {}
        self._client: httpx.AsyncClient | None = None

    async def setup(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers=self._headers,
        )

    async def teardown(self) -> None:
        if self._client:
            await self._client.aclose()

    async def execute(self, action: Action) -> Result:
        method_map = {
            "read": "GET",
            "write": "POST",
            "update": "PUT",
            "delete": "DELETE",
        }
        method = method_map.get(action.type, "POST")
        path = action.params.get("path", "/")

        try:
            response = await self._client.request(method, path, json=action.params)
            response.raise_for_status()
            return Result(
                action=action,
                status=ResultStatus.SUCCESS,
                data=response.json(),
            )
        except Exception as e:
            return Result(
                action=action,
                status=ResultStatus.FAILED,
                error=str(e),
            )
```

## Using Your Adapter

```python
runtime = Runtime(
    executor=MyAPIExecutor(
        base_url="https://api.example.com",
        headers={"Authorization": "Bearer ..."},
    ),
    policy=Policy.from_yaml("policy.yaml"),
)
```

## Custom Verification

Override `verify()` to add post-execution checks:

```python
class StrictExecutor(BaseExecutor):
    async def execute(self, action: Action) -> Result:
        ...

    async def verify(self, action: Action, result: Result) -> bool:
        if action.type == "write" and result.ok:
            # Re-read the record to confirm the write took effect
            check = await self._read_back(action)
            return check is not None
        return result.ok
```

If verification fails, the result is marked as `FAILED` even if the execution itself succeeded.
