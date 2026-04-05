"""Tests for aegis.core.contracts — resource contracts."""

from __future__ import annotations

import asyncio

import pytest

from aegis.core.contracts import (
    ContractMonitor,
    ContractStatus,
    ContractViolation,
    ResourceContract,
    resource_contract,
)

# ---------------------------------------------------------------------------
# ResourceContract
# ---------------------------------------------------------------------------


class TestResourceContract:
    def test_defaults(self) -> None:
        c = ResourceContract()
        assert c.name == "default"
        assert c.max_calls is None
        assert c.on_violation == "raise"

    def test_custom(self) -> None:
        c = ResourceContract(name="test", max_calls=10, max_cost_usd=1.0)
        assert c.max_calls == 10
        assert c.max_cost_usd == 1.0

    def test_frozen(self) -> None:
        c = ResourceContract()
        with pytest.raises(AttributeError):
            c.name = "modified"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ContractMonitor
# ---------------------------------------------------------------------------


class TestContractMonitor:
    def test_record_call(self) -> None:
        monitor = ContractMonitor(ResourceContract(max_calls=5))
        monitor.record_call(tokens=100, cost_usd=0.01)
        assert monitor.remaining_calls == 4
        assert monitor.remaining_tokens is None  # unconstrained

    def test_call_limit_violation(self) -> None:
        monitor = ContractMonitor(ResourceContract(name="test", max_calls=2))
        monitor.record_call()
        monitor.record_call()
        with pytest.raises(ContractViolation) as exc_info:
            monitor.record_call()
        assert exc_info.value.dimension == "max_calls"
        assert exc_info.value.contract_name == "test"

    def test_token_limit_violation(self) -> None:
        monitor = ContractMonitor(ResourceContract(max_tokens=100))
        monitor.record_call(tokens=60)
        with pytest.raises(ContractViolation):
            monitor.record_call(tokens=50)  # 110 > 100

    def test_cost_limit_violation(self) -> None:
        monitor = ContractMonitor(ResourceContract(max_cost_usd=0.10))
        monitor.record_call(cost_usd=0.06)
        with pytest.raises(ContractViolation):
            monitor.record_call(cost_usd=0.06)  # 0.12 > 0.10

    def test_tool_invocation_limit(self) -> None:
        monitor = ContractMonitor(ResourceContract(max_tool_invocations=3))
        monitor.record_tool_invocation()
        monitor.record_tool_invocation()
        monitor.record_tool_invocation()
        with pytest.raises(ContractViolation):
            monitor.record_tool_invocation()

    def test_retry_limit(self) -> None:
        monitor = ContractMonitor(ResourceContract(max_retries=2))
        monitor.record_retry()
        monitor.record_retry()
        with pytest.raises(ContractViolation):
            monitor.record_retry()

    def test_warn_mode_no_raise(self) -> None:
        monitor = ContractMonitor(ResourceContract(max_calls=1, on_violation="warn"))
        monitor.record_call()
        monitor.record_call()  # No exception
        status = monitor.status()
        assert len(status.violations) > 0

    def test_status(self) -> None:
        monitor = ContractMonitor(ResourceContract(name="test", max_calls=10))
        monitor.record_call(tokens=50, cost_usd=0.01)
        status = monitor.status()
        assert isinstance(status, ContractStatus)
        assert status.contract_name == "test"
        assert status.calls_used == 1
        assert status.tokens_used == 50
        assert status.cost_used_usd == 0.01
        assert status.elapsed_s >= 0
        assert not status.exhausted

    def test_status_exhausted(self) -> None:
        monitor = ContractMonitor(ResourceContract(max_calls=1, on_violation="warn"))
        monitor.record_call()
        status = monitor.status()
        assert status.exhausted

    def test_remaining_properties(self) -> None:
        monitor = ContractMonitor(
            ResourceContract(max_calls=10, max_tokens=1000, max_cost_usd=5.0, max_duration_s=60)
        )
        assert monitor.remaining_calls == 10
        assert monitor.remaining_tokens == 1000
        assert monitor.remaining_cost_usd == 5.0
        assert monitor.remaining_duration_s is not None
        assert monitor.remaining_duration_s > 0

    def test_unconstrained_returns_none(self) -> None:
        monitor = ContractMonitor(ResourceContract())
        assert monitor.remaining_calls is None
        assert monitor.remaining_tokens is None
        assert monitor.remaining_cost_usd is None
        assert monitor.remaining_duration_s is None

    def test_child_monotone_constraint(self) -> None:
        parent = ContractMonitor(ResourceContract(max_calls=10, max_cost_usd=1.0))
        parent.record_call(cost_usd=0.3)
        child = parent.child("child-task", max_calls=20)
        # Child max_calls capped at parent remaining (9)
        assert child.remaining_calls == 9
        # Child cost capped at parent remaining (0.7)
        assert child.remaining_cost_usd is not None
        assert child.remaining_cost_usd <= 0.71  # float tolerance


# ---------------------------------------------------------------------------
# @resource_contract decorator
# ---------------------------------------------------------------------------


class TestResourceContractDecorator:
    def test_sync_function(self) -> None:
        @resource_contract(max_calls=5)
        def my_func(x: int, _contract_monitor: ContractMonitor | None = None) -> int:
            assert _contract_monitor is not None
            _contract_monitor.record_call()
            return x * 2

        result = my_func(21)
        assert result == 42

    def test_sync_violation(self) -> None:
        @resource_contract(max_calls=1)
        def greedy(x: int, _contract_monitor: ContractMonitor | None = None) -> int:
            monitor = _contract_monitor
            assert monitor is not None
            monitor.record_call()
            monitor.record_call()  # 2nd call exceeds limit
            return x

        with pytest.raises(ContractViolation):
            greedy(1)

    def test_async_function(self) -> None:
        @resource_contract(max_calls=5)
        async def my_async(x: int, _contract_monitor: ContractMonitor | None = None) -> int:
            assert _contract_monitor is not None
            _contract_monitor.record_call()
            return x * 3

        result = asyncio.get_event_loop().run_until_complete(my_async(10))
        assert result == 30

    def test_async_timeout(self) -> None:
        @resource_contract(max_duration_s=0.1)
        async def slow_task(
            _contract_monitor: ContractMonitor | None = None,
        ) -> str:
            await asyncio.sleep(1.0)
            return "done"

        with pytest.raises(ContractViolation) as exc_info:
            asyncio.get_event_loop().run_until_complete(slow_task())
        assert exc_info.value.dimension == "max_duration_s"

    def test_preserves_function_name(self) -> None:
        @resource_contract(max_calls=10)
        def my_named_func(_contract_monitor: ContractMonitor | None = None) -> None:
            pass

        assert my_named_func.__name__ == "my_named_func"
