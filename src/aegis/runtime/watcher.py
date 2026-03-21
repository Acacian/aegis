"""File watcher for automatic policy hot-reload.

Polls a YAML policy file for changes and updates the runtime
automatically when modifications are detected.

Example::

    watcher = PolicyWatcher(runtime, "policy.yaml")
    await watcher.start()
    # ... policy.yaml changes are auto-reloaded ...
    await watcher.stop()

Or as an async context manager::

    async with PolicyWatcher(runtime, "policy.yaml"):
        # policy.yaml changes are auto-reloaded
        ...
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING

from aegis.core.policy import Policy

if TYPE_CHECKING:
    from aegis.runtime.engine import Runtime

logger = logging.getLogger(__name__)


class PolicyWatcher:
    """Watch a policy YAML file and hot-reload on changes.

    Uses polling (``pathlib.Path.stat().st_mtime``) to detect changes,
    requiring no external dependencies.

    Args:
        runtime: The :class:`Runtime` whose policy will be updated.
        policy_path: Path to the YAML policy file to watch.
        interval: Seconds between polls. Defaults to ``1.0``.
        on_reload: Optional async callback invoked after a successful reload.
            Receives the new :class:`Policy` as its argument.
    """

    def __init__(
        self,
        runtime: Runtime,
        policy_path: str | Path,
        interval: float = 1.0,
        on_reload: Callable[[Policy], Awaitable[None]] | None = None,
    ) -> None:
        self._runtime = runtime
        self._policy_path = Path(policy_path)
        self._interval = interval
        self._on_reload = on_reload
        self._task: asyncio.Task[None] | None = None
        self._last_mtime: float = 0.0

    async def start(self) -> None:
        """Start watching the policy file in a background asyncio task.

        Calling ``start()`` when already started is a no-op.
        """
        if self._task is not None and not self._task.done():
            return
        # Seed the mtime so we don't reload immediately on start.
        self._last_mtime = self._get_mtime()
        self._task = asyncio.create_task(self._watch_loop())

    async def stop(self) -> None:
        """Stop the background watcher task.

        Calling ``stop()`` when already stopped is a no-op.
        """
        if self._task is None or self._task.done():
            self._task = None
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None

    # -- Async context manager -----------------------------------------------

    async def __aenter__(self) -> PolicyWatcher:
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.stop()

    # -- Internal ------------------------------------------------------------

    def _get_mtime(self) -> float:
        """Return the file's mtime, or ``0.0`` if it doesn't exist."""
        try:
            return self._policy_path.stat().st_mtime
        except OSError:
            return 0.0

    async def _watch_loop(self) -> None:
        """Poll the file for mtime changes and reload when detected."""
        while True:
            await asyncio.sleep(self._interval)
            try:
                current_mtime = self._get_mtime()
                if current_mtime == 0.0:
                    # File missing — warn but keep the old policy.
                    logger.warning(
                        "Policy file not found: %s — keeping current policy",
                        self._policy_path,
                    )
                    continue
                if current_mtime != self._last_mtime:
                    self._last_mtime = current_mtime
                    await self._reload()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.warning(
                    "Unexpected error in policy watcher loop",
                    exc_info=True,
                )

    async def _reload(self) -> None:
        """Load the policy from disk and push it into the runtime."""
        try:
            new_policy = Policy.from_yaml(self._policy_path)
        except Exception:
            logger.warning(
                "Failed to parse policy file %s — keeping current policy",
                self._policy_path,
                exc_info=True,
            )
            return

        self._runtime.update_policy(new_policy)
        logger.info("Policy reloaded from %s", self._policy_path)

        if self._on_reload is not None:
            try:
                await self._on_reload(new_policy)
            except Exception:
                logger.warning(
                    "on_reload callback raised an exception",
                    exc_info=True,
                )
