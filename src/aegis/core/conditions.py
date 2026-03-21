"""Policy condition evaluators.

Extends glob-based matching with conditional logic:
- Time-based conditions (time windows, weekdays)
- Param-based conditions (comparisons on action params)

Example YAML::

    rules:
      - name: after_hours_block
        match: { type: "write*" }
        conditions:
          time_after: "18:00"
          time_before: "08:00"
        risk_level: critical
        approval: block

      - name: bulk_ops
        match: { type: "update*" }
        conditions:
          param_gt: { count: 100 }
        risk_level: high
        approval: approve

      - name: weekday_only
        match: { type: "deploy*" }
        conditions:
          weekdays: [1, 2, 3, 4, 5]
        risk_level: medium
        approval: approve
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from datetime import UTC, datetime, time
from typing import Any

logger = logging.getLogger(__name__)

_KNOWN_KEYS = frozenset(
    {
        "time_after",
        "time_before",
        "weekdays",
        "param_eq",
        "param_gt",
        "param_lt",
        "param_gte",
        "param_lte",
        "param_contains",
        "param_matches",
    }
)


def evaluate_conditions(
    conditions: dict[str, Any], params: dict[str, Any], now: datetime | None = None
) -> bool:
    """Evaluate all conditions. Returns True if ALL conditions pass.

    Args:
        conditions: Dictionary of condition keys to values.
        params: Action params to check against.
        now: Current time (defaults to UTC now). Inject for testing.
    """
    if not conditions:
        return True

    now = now or datetime.now(UTC)
    return all(_evaluate_one(key, value, params, now) for key, value in conditions.items())


def _evaluate_one(key: str, value: Any, params: dict[str, Any], now: datetime) -> bool:
    """Evaluate a single condition."""
    match key:
        case "time_after":
            return _check_time_after(value, now)
        case "time_before":
            return _check_time_before(value, now)
        case "weekdays":
            return now.isoweekday() in value
        case "param_eq":
            return _check_param_compare(value, params, _op_eq)
        case "param_gt":
            return _check_param_compare(value, params, _op_gt)
        case "param_lt":
            return _check_param_compare(value, params, _op_lt)
        case "param_gte":
            return _check_param_compare(value, params, _op_gte)
        case "param_lte":
            return _check_param_compare(value, params, _op_lte)
        case "param_contains":
            return _check_param_compare(value, params, _op_contains)
        case "param_matches":
            return _check_param_compare(value, params, _op_matches)
        case _:
            logger.warning(
                "Unknown policy condition '%s' denied (fail-closed). Known conditions: %s",
                key,
                ", ".join(sorted(_KNOWN_KEYS)),
            )
            return False  # Unknown conditions deny — fail-closed for safety


def _parse_time(s: str) -> time:
    """Parse HH:MM string to time object."""
    parts = s.strip().split(":")
    return time(int(parts[0]), int(parts[1]))


def _check_time_after(value: str, now: datetime) -> bool:
    """True if current time is after the given HH:MM."""
    threshold = _parse_time(value)
    return now.time() >= threshold


def _check_time_before(value: str, now: datetime) -> bool:
    """True if current time is before the given HH:MM."""
    threshold = _parse_time(value)
    return now.time() < threshold


# -- Param comparison operators ---


def _op_eq(actual: Any, expected: Any) -> bool:
    return bool(actual == expected)


def _op_gt(actual: Any, expected: Any) -> bool:
    return bool(actual > expected)


def _op_lt(actual: Any, expected: Any) -> bool:
    return bool(actual < expected)


def _op_gte(actual: Any, expected: Any) -> bool:
    return bool(actual >= expected)


def _op_lte(actual: Any, expected: Any) -> bool:
    return bool(actual <= expected)


def _op_contains(actual: Any, expected: Any) -> bool:
    return bool(expected in actual)


_MAX_REGEX_LEN = 1000


def _op_matches(actual: Any, expected: Any) -> bool:
    pattern = str(expected)
    if len(pattern) > _MAX_REGEX_LEN:
        logger.warning(
            "Regex pattern too long (%d chars, max %d), denied",
            len(pattern),
            _MAX_REGEX_LEN,
        )
        return False
    try:
        return bool(re.search(pattern, str(actual)))
    except re.error:
        return False


def _check_param_compare(
    spec: dict[str, Any],
    params: dict[str, Any],
    op: Callable[[Any, Any], bool],
) -> bool:
    """Check param conditions. spec is {param_name: expected_value}."""
    for param_name, expected in spec.items():
        actual = params.get(param_name)
        if actual is None:
            return False
        if not op(actual, expected):
            return False
    return True
