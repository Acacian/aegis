"""Base executor interface for adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod

from aegis.core.action import Action
from aegis.core.result import Result


class BaseExecutor(ABC):
    """Abstract base class for action executors.

    Subclasses implement how actions are actually carried out
    (e.g. via Playwright, HTTP API calls, etc.).
    """

    @abstractmethod
    async def execute(self, action: Action) -> Result:
        """Execute a single action and return the result."""
        ...

    async def verify(self, action: Action, result: Result) -> bool:
        """Verify that an action completed as expected.

        Default implementation considers the action verified if the result is OK.
        Override for custom post-execution verification logic.
        """
        return result.ok

    async def setup(self) -> None:  # noqa: B027
        """Called once before the first action in a session.

        Use this to initialize resources (e.g. browser instances).
        Override in subclasses; default is a no-op.
        """

    async def teardown(self) -> None:  # noqa: B027
        """Called once after the last action in a session.

        Use this to clean up resources.
        Override in subclasses; default is a no-op.
        """
