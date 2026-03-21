"""Tests for PolicyWatcher — file-based policy hot-reload."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest
import yaml

from aegis.core.action import Action
from aegis.core.policy import Approval, Policy
from aegis.runtime.approval import AutoApprovalHandler
from aegis.runtime.audit import AuditLogger
from aegis.runtime.engine import Runtime
from aegis.runtime.watcher import PolicyWatcher
from tests.conftest import FakeExecutor

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_POLICY = {
    "version": "1",
    "defaults": {"risk_level": "medium", "approval": "approve"},
    "rules": [
        {
            "name": "read_auto",
            "match": {"type": "read"},
            "risk_level": "low",
            "approval": "auto",
        }
    ],
}

UPDATED_POLICY = {
    "version": "1",
    "defaults": {"risk_level": "high", "approval": "block"},
    "rules": [
        {
            "name": "all_blocked",
            "match": {"type": "*"},
            "risk_level": "critical",
            "approval": "block",
        }
    ],
}


def _write_policy(path: Path, data: dict[str, object]) -> None:
    """Write a policy dict as YAML and ensure mtime advances."""
    path.write_text(yaml.dump(data))


def _make_runtime(tmp_path: Path, policy_path: Path) -> Runtime:
    return Runtime(
        executor=FakeExecutor(),
        policy=Policy.from_yaml(policy_path),
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "audit.db"),
    )


async def _wait_for(predicate: object, *, timeout: float = 5.0, step: float = 0.05) -> None:
    """Spin until *predicate* is truthy or *timeout* expires."""
    elapsed = 0.0
    while elapsed < timeout:
        if callable(predicate) and predicate():
            return
        await asyncio.sleep(step)
        elapsed += step
    msg = f"Predicate not satisfied within {timeout}s"
    raise TimeoutError(msg)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reload_on_file_change(tmp_path: Path) -> None:
    """Modifying the YAML should trigger an automatic policy reload."""
    policy_file = tmp_path / "policy.yaml"
    _write_policy(policy_file, VALID_POLICY)

    runtime = _make_runtime(tmp_path, policy_file)
    # Sanity: read action should be auto-approved.
    decision = runtime.policy.evaluate(Action("read", "anything"))
    assert decision.approval == Approval.AUTO

    watcher = PolicyWatcher(runtime, policy_file, interval=0.1)
    await watcher.start()
    try:
        # Ensure mtime changes (some filesystems have 1-second granularity).
        await asyncio.sleep(0.05)
        _write_policy(policy_file, UPDATED_POLICY)
        # Bump mtime explicitly in case the write was too fast.
        new_time = os.path.getmtime(policy_file) + 2
        os.utime(policy_file, (new_time, new_time))

        await _wait_for(lambda: runtime.policy.default_approval == Approval.BLOCK)

        decision = runtime.policy.evaluate(Action("read", "anything"))
        assert decision.approval == Approval.BLOCK
    finally:
        await watcher.stop()


@pytest.mark.asyncio
async def test_invalid_yaml_keeps_old_policy(tmp_path: Path) -> None:
    """If the file has invalid YAML, the old policy should remain active."""
    policy_file = tmp_path / "policy.yaml"
    _write_policy(policy_file, VALID_POLICY)

    runtime = _make_runtime(tmp_path, policy_file)
    original_policy = runtime.policy

    watcher = PolicyWatcher(runtime, policy_file, interval=0.1)
    await watcher.start()
    try:
        await asyncio.sleep(0.05)
        # Write something that yaml.safe_load will parse but Policy.from_dict will reject,
        # or genuinely broken YAML.
        policy_file.write_text(": : : not valid yaml {{{{")
        new_time = os.path.getmtime(policy_file) + 2
        os.utime(policy_file, (new_time, new_time))

        # Give the watcher a few cycles to notice the change.
        await asyncio.sleep(0.5)

        # Policy should be unchanged.
        assert runtime.policy is original_policy
    finally:
        await watcher.stop()


@pytest.mark.asyncio
async def test_deleted_file_keeps_old_policy(tmp_path: Path) -> None:
    """If the watched file is deleted, the old policy stays active."""
    policy_file = tmp_path / "policy.yaml"
    _write_policy(policy_file, VALID_POLICY)

    runtime = _make_runtime(tmp_path, policy_file)
    original_policy = runtime.policy

    watcher = PolicyWatcher(runtime, policy_file, interval=0.1)
    await watcher.start()
    try:
        await asyncio.sleep(0.05)
        policy_file.unlink()

        await asyncio.sleep(0.5)
        assert runtime.policy is original_policy
    finally:
        await watcher.stop()


@pytest.mark.asyncio
async def test_start_stop_lifecycle(tmp_path: Path) -> None:
    """Start and stop should be idempotent and well-behaved."""
    policy_file = tmp_path / "policy.yaml"
    _write_policy(policy_file, VALID_POLICY)

    runtime = _make_runtime(tmp_path, policy_file)
    watcher = PolicyWatcher(runtime, policy_file, interval=0.1)

    # Stop before start is a no-op.
    await watcher.stop()

    await watcher.start()
    assert watcher._task is not None and not watcher._task.done()

    # Double-start is a no-op (same task).
    task = watcher._task
    await watcher.start()
    assert watcher._task is task

    await watcher.stop()
    assert watcher._task is None

    # Double-stop is a no-op.
    await watcher.stop()


@pytest.mark.asyncio
async def test_context_manager(tmp_path: Path) -> None:
    """PolicyWatcher should work as an async context manager."""
    policy_file = tmp_path / "policy.yaml"
    _write_policy(policy_file, VALID_POLICY)

    runtime = _make_runtime(tmp_path, policy_file)

    async with PolicyWatcher(runtime, policy_file, interval=0.1) as watcher:
        assert watcher._task is not None and not watcher._task.done()

    # After exiting the context, the task should be stopped.
    assert watcher._task is None


@pytest.mark.asyncio
async def test_on_reload_callback(tmp_path: Path) -> None:
    """The on_reload callback should fire after a successful reload."""
    policy_file = tmp_path / "policy.yaml"
    _write_policy(policy_file, VALID_POLICY)

    runtime = _make_runtime(tmp_path, policy_file)
    reloaded_policies: list[Policy] = []

    async def capture(policy: Policy) -> None:
        reloaded_policies.append(policy)

    watcher = PolicyWatcher(runtime, policy_file, interval=0.1, on_reload=capture)
    await watcher.start()
    try:
        await asyncio.sleep(0.05)
        _write_policy(policy_file, UPDATED_POLICY)
        new_time = os.path.getmtime(policy_file) + 2
        os.utime(policy_file, (new_time, new_time))

        await _wait_for(lambda: len(reloaded_policies) > 0)

        assert len(reloaded_policies) == 1
        assert reloaded_policies[0].default_approval == Approval.BLOCK
    finally:
        await watcher.stop()


@pytest.mark.asyncio
async def test_on_reload_callback_not_called_on_invalid_yaml(tmp_path: Path) -> None:
    """The on_reload callback should NOT fire when YAML is invalid."""
    policy_file = tmp_path / "policy.yaml"
    _write_policy(policy_file, VALID_POLICY)

    runtime = _make_runtime(tmp_path, policy_file)
    reloaded_policies: list[Policy] = []

    async def capture(policy: Policy) -> None:
        reloaded_policies.append(policy)

    watcher = PolicyWatcher(runtime, policy_file, interval=0.1, on_reload=capture)
    await watcher.start()
    try:
        await asyncio.sleep(0.05)
        policy_file.write_text(": : : broken {{{{")
        new_time = os.path.getmtime(policy_file) + 2
        os.utime(policy_file, (new_time, new_time))

        await asyncio.sleep(0.5)
        assert len(reloaded_policies) == 0
    finally:
        await watcher.stop()
