"""Anthropic Claude tool_use integration: govern Claude tool calls with Aegis.

Provides a middleware layer that intercepts Claude's tool_use blocks,
runs them through Aegis policy checks, and returns governed results.

Requires: ``pip install agent-aegis[anthropic]``

Example::

    from anthropic import Anthropic
    from aegis import Policy, Runtime
    from aegis.adapters.anthropic import govern_tool_call

    runtime = Runtime(executor=my_executor, policy=my_policy)
    client = Anthropic()

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        tools=[...],
        messages=[...],
    )

    for block in response.content:
        if block.type == "tool_use":
            result = await govern_tool_call(
                runtime=runtime,
                tool_name=block.name,
                tool_input=block.input,
                target="my_system",
            )
"""

from __future__ import annotations

from typing import Any

from aegis.core.action import Action
from aegis.core.result import Result


async def govern_tool_call(
    *,
    runtime: Any,
    tool_name: str,
    tool_input: dict[str, Any],
    target: str = "default",
    description: str = "",
) -> Result:
    """Run a Claude tool_use call through Aegis governance.

    Creates an Action from the tool call, evaluates it against the policy,
    and executes it through the runtime pipeline.

    Args:
        runtime: An Aegis Runtime instance.
        tool_name: The name of the tool being called (maps to Action.type).
        tool_input: The input parameters from Claude's tool_use block.
        target: The system being acted upon.
        description: Optional human-readable description.

    Returns:
        The Aegis Result from the governed execution.
    """
    action = Action(
        type=tool_name,
        target=target,
        params=tool_input,
        description=description or f"Claude tool call: {tool_name}",
    )

    plan = runtime.plan([action])
    results: list[Result] = await runtime.execute(plan)
    return results[0]


def tool_results_to_api_format(results: list[Result]) -> list[dict[str, Any]]:
    """Convert Aegis Results to Anthropic API tool_result format.

    Useful for feeding governed results back into a Claude conversation.

    Args:
        results: List of Aegis Result objects.

    Returns:
        List of dicts suitable for the Anthropic messages API.
    """
    api_results = []
    for r in results:
        content = str(r.data) if r.ok else f"[{r.status.value.upper()}] {r.error}"
        api_results.append(
            {
                "type": "tool_result",
                "content": content,
                "is_error": not r.ok,
            }
        )
    return api_results
