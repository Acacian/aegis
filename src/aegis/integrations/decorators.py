"""Decorator-based governance for arbitrary functions.

Provides ``@guard`` — a zero-code way to wrap any sync or async function
with Aegis policy evaluation.  The decorator creates an
:class:`~aegis.core.action.Action`, evaluates it against a lazily-loaded
:class:`~aegis.core.policy.Policy`, and either proceeds or blocks based
on the policy decision.
"""

from __future__ import annotations

import functools
import inspect
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar, overload

from aegis.core.action import Action
from aegis.core.policy import Approval, Policy
from aegis.integrations.errors import AegisBlockedError

logger = logging.getLogger("aegis.integrations")

F = TypeVar("F", bound=Callable[..., Any])

# ------------------------------------------------------------------ #
# Lazy policy singleton
# ------------------------------------------------------------------ #

_default_policy: Policy | None = None
_DEFAULT_POLICY_PATHS = ("aegis.yaml", "aegis-policy.yaml", "policy.yaml")


def _get_default_policy() -> Policy:
    """Return (and cache) a default policy loaded from well-known file paths.

    Searches for ``aegis.yaml``, ``aegis-policy.yaml``, and ``policy.yaml``
    in the current working directory.  If none is found, returns a permissive
    default policy that allows everything.
    """
    global _default_policy  # noqa: PLW0603
    if _default_policy is not None:
        return _default_policy

    for name in _DEFAULT_POLICY_PATHS:
        path = Path(name)
        if path.exists():
            _default_policy = Policy.from_yaml(path)
            logger.debug("Loaded default policy from %s", path)
            return _default_policy

    # No policy file found — permissive default
    _default_policy = Policy()
    logger.debug("No policy file found; using permissive defaults")
    return _default_policy


def _load_policy(policy_path: str | None) -> Policy:
    """Load a policy from an explicit path or fall back to the default."""
    if policy_path is not None:
        return Policy.from_yaml(policy_path)
    return _get_default_policy()


# ------------------------------------------------------------------ #
# Action inference
# ------------------------------------------------------------------ #

_ACTION_TYPE_PREFIXES: dict[str, str] = {
    "get": "read",
    "fetch": "read",
    "load": "read",
    "list": "read",
    "read": "read",
    "query": "read",
    "find": "read",
    "search": "read",
    "create": "write",
    "add": "write",
    "insert": "write",
    "post": "write",
    "put": "write",
    "set": "write",
    "save": "write",
    "store": "write",
    "write": "write",
    "update": "update",
    "patch": "update",
    "modify": "update",
    "edit": "update",
    "delete": "delete",
    "remove": "delete",
    "drop": "delete",
    "destroy": "delete",
    "purge": "delete",
    "send": "execute",
    "run": "execute",
    "execute": "execute",
    "call": "execute",
    "invoke": "execute",
    "trigger": "execute",
}


def _infer_action_type(fn: Callable[..., Any]) -> str:
    """Infer an action type from the function name.

    Splits the function name by ``_`` and checks the first token against
    a map of common verb prefixes.  Falls back to ``"execute"`` when no
    prefix matches.
    """
    name = getattr(fn, "__name__", "unknown")
    first_token = name.split("_")[0].lower()
    return _ACTION_TYPE_PREFIXES.get(first_token, "execute")


def _infer_action_target(fn: Callable[..., Any]) -> str:
    """Infer an action target from the function's qualified name.

    Uses the module name as the target, or falls back to ``"unknown"``.
    """
    module: str | None = getattr(fn, "__module__", None)
    if module:
        result: str = module.rsplit(".", 1)[-1]
        return result
    return "unknown"


# ------------------------------------------------------------------ #
# Block handling
# ------------------------------------------------------------------ #


def _handle_block(
    on_block: str,
    reason: str,
    decision: Any,
) -> Any:
    """Handle a blocked action according to the *on_block* strategy.

    Args:
        on_block: One of ``"raise"``, ``"return_none"``, or ``"log"``.
        reason: Human-readable reason for the block.
        decision: The :class:`~aegis.core.policy.PolicyDecision`.

    Returns:
        ``None`` when *on_block* is ``"return_none"`` or ``"log"``.

    Raises:
        AegisBlockedError: When *on_block* is ``"raise"`` (the default).
    """
    if on_block == "raise":
        raise AegisBlockedError(reason, decision=decision)
    if on_block == "log":
        logger.warning("Aegis blocked: %s (decision=%s)", reason, decision)
    # "return_none" and "log" both return None
    return None


# ------------------------------------------------------------------ #
# @guard decorator
# ------------------------------------------------------------------ #


@overload
def guard(fn: F) -> F: ...


@overload
def guard(
    fn: None = None,
    *,
    action_type: str | None = None,
    action_target: str | None = None,
    policy_path: str | None = None,
    on_block: str = "raise",
) -> Callable[[F], F]: ...


def guard(
    fn: F | None = None,
    *,
    action_type: str | None = None,
    action_target: str | None = None,
    policy_path: str | None = None,
    on_block: str = "raise",
) -> F | Callable[[F], F]:
    """Decorator that adds Aegis governance to any function.

    Can be used with or without parentheses::

        @guard
        def call_api(endpoint, data):
            ...

        @guard(action_type="write", action_target="database")
        def update_record(record_id, data):
            ...

    Args:
        fn: The function to wrap (passed implicitly when used without
            parentheses).
        action_type: Override the action type.  When ``None``, it is
            inferred from the function name.
        action_target: Override the action target.  When ``None``, it is
            inferred from the function's module.
        policy_path: Path to a YAML policy file.  When ``None``, the
            default policy is loaded from well-known file names.
        on_block: Strategy when the action is blocked —
            ``"raise"`` (default), ``"return_none"``, or ``"log"``.

    Returns:
        The wrapped function (or a decorator if called with keyword
        arguments).
    """

    def decorator(func: F) -> F:
        resolved_type = action_type or _infer_action_type(func)
        resolved_target = action_target or _infer_action_target(func)

        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                action = Action(
                    type=resolved_type,
                    target=resolved_target,
                    params={"args": list(args), "kwargs": kwargs},
                    description=func.__doc__ or "",
                )
                policy = _load_policy(policy_path)
                decision = policy.evaluate(action)

                if decision.approval == Approval.BLOCK:
                    reason = f"Blocked by policy rule: {decision.matched_rule}"
                    return _handle_block(on_block, reason, decision)

                return await func(*args, **kwargs)

            return async_wrapper  # type: ignore[return-value]

        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                action = Action(
                    type=resolved_type,
                    target=resolved_target,
                    params={"args": list(args), "kwargs": kwargs},
                    description=func.__doc__ or "",
                )
                policy = _load_policy(policy_path)
                decision = policy.evaluate(action)

                if decision.approval == Approval.BLOCK:
                    reason = f"Blocked by policy rule: {decision.matched_rule}"
                    return _handle_block(on_block, reason, decision)

                return func(*args, **kwargs)

            return sync_wrapper  # type: ignore[return-value]

    # Support bare @guard (no parentheses)
    if fn is not None:
        return decorator(fn)
    return decorator
