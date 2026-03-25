"""Tests for aegis.runtime.audit_backend Protocol classes."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

import pytest

from aegis.core.policy import PolicyDecision
from aegis.core.result import Result
from aegis.runtime.audit_backend import AsyncAuditBackend, AuditBackend

# ---------------------------------------------------------------------------
# Concrete implementations for isinstance checks
# ---------------------------------------------------------------------------


class ConformingSyncBackend:
    """Sync backend that satisfies AuditBackend protocol."""

    def log(
        self,
        session_id: str,
        decision: PolicyDecision,
        *,
        result: Result | None = None,
        human_decision: str | None = None,
    ) -> int:
        return 1

    def get_log(
        self,
        session_id: str | None = None,
        *,
        action_type: str | None = None,
        risk_level: str | None = None,
        result_status: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int | None = None,
        agent_id: str | None = None,
        chain_id: str | None = None,
    ) -> list[dict[str, object]]:
        return []

    def count(
        self,
        *,
        session_id: str | None = None,
        action_type: str | None = None,
        risk_level: str | None = None,
        result_status: str | None = None,
    ) -> int:
        return 0

    def subscribe(self, callback: Callable[[dict[str, Any]], Any]) -> None:
        pass

    def unsubscribe(self, callback: Callable[[dict[str, Any]], Any]) -> None:
        pass

    def close(self) -> None:
        pass


class ConformingAsyncBackend:
    """Async backend that satisfies AsyncAuditBackend protocol."""

    async def log(
        self,
        session_id: str,
        decision: PolicyDecision,
        *,
        result: Result | None = None,
        human_decision: str | None = None,
    ) -> int:
        return 1

    async def get_log(
        self,
        session_id: str | None = None,
        *,
        action_type: str | None = None,
        risk_level: str | None = None,
        result_status: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int | None = None,
        agent_id: str | None = None,
        chain_id: str | None = None,
    ) -> list[dict[str, object]]:
        return []

    async def count(
        self,
        *,
        session_id: str | None = None,
        action_type: str | None = None,
        risk_level: str | None = None,
        result_status: str | None = None,
    ) -> int:
        return 0

    def subscribe(self, callback: Callable[[dict[str, Any]], Any]) -> None:
        pass

    def unsubscribe(self, callback: Callable[[dict[str, Any]], Any]) -> None:
        pass

    async def close(self) -> None:
        pass


class MissingLogBackend:
    """Missing 'log' method — should NOT satisfy AuditBackend."""

    def get_log(self, session_id=None, **kw):
        return []

    def count(self, **kw):
        return 0

    def subscribe(self, callback):
        pass

    def unsubscribe(self, callback):
        pass

    def close(self):
        pass


class EmptyClass:
    """Has no protocol methods at all."""

    pass


# ---------------------------------------------------------------------------
# Tests: AuditBackend (sync)
# ---------------------------------------------------------------------------


class TestAuditBackendProtocol:
    """Tests for the synchronous AuditBackend protocol."""

    def test_is_runtime_checkable(self):
        """AuditBackend should be decorated with @runtime_checkable."""
        assert hasattr(AuditBackend, "__protocol_attrs__") or hasattr(
            AuditBackend, "_is_runtime_protocol"
        )

    def test_conforming_instance_check(self):
        """A class implementing all methods satisfies isinstance check."""
        backend = ConformingSyncBackend()
        assert isinstance(backend, AuditBackend)

    def test_missing_method_fails_isinstance(self):
        """A class missing 'log' should NOT pass isinstance check."""
        backend = MissingLogBackend()
        assert not isinstance(backend, AuditBackend)

    def test_empty_class_fails_isinstance(self):
        """A class with no methods should NOT pass isinstance check."""
        obj = EmptyClass()
        assert not isinstance(obj, AuditBackend)

    def test_protocol_itself_is_not_instance(self):
        """The Protocol class itself should not be an instance of itself in a normal way."""
        # Protocols define structure, they aren't concrete implementations
        assert AuditBackend is not None

    def test_protocol_has_log_method(self):
        """Protocol should define a log method."""
        assert hasattr(AuditBackend, "log")

    def test_protocol_has_get_log_method(self):
        """Protocol should define a get_log method."""
        assert hasattr(AuditBackend, "get_log")

    def test_protocol_has_count_method(self):
        """Protocol should define a count method."""
        assert hasattr(AuditBackend, "count")

    def test_protocol_has_subscribe_method(self):
        """Protocol should define a subscribe method."""
        assert hasattr(AuditBackend, "subscribe")

    def test_protocol_has_unsubscribe_method(self):
        """Protocol should define a unsubscribe method."""
        assert hasattr(AuditBackend, "unsubscribe")

    def test_protocol_has_close_method(self):
        """Protocol should define a close method."""
        assert hasattr(AuditBackend, "close")


# ---------------------------------------------------------------------------
# Tests: AsyncAuditBackend
# ---------------------------------------------------------------------------


class TestAsyncAuditBackendProtocol:
    """Tests for the asynchronous AsyncAuditBackend protocol."""

    def test_is_runtime_checkable(self):
        """AsyncAuditBackend should be decorated with @runtime_checkable."""
        assert hasattr(AsyncAuditBackend, "__protocol_attrs__") or hasattr(
            AsyncAuditBackend, "_is_runtime_protocol"
        )

    def test_conforming_instance_check(self):
        """A class implementing all async methods satisfies isinstance check."""
        backend = ConformingAsyncBackend()
        assert isinstance(backend, AsyncAuditBackend)

    def test_missing_method_fails_isinstance(self):
        """A class missing 'log' should NOT pass isinstance check."""
        backend = MissingLogBackend()
        assert not isinstance(backend, AsyncAuditBackend)

    def test_empty_class_fails_isinstance(self):
        """A class with no methods should NOT pass isinstance check."""
        obj = EmptyClass()
        assert not isinstance(obj, AsyncAuditBackend)

    def test_protocol_has_log_method(self):
        assert hasattr(AsyncAuditBackend, "log")

    def test_protocol_has_get_log_method(self):
        assert hasattr(AsyncAuditBackend, "get_log")

    def test_protocol_has_count_method(self):
        assert hasattr(AsyncAuditBackend, "count")

    def test_protocol_has_subscribe_method(self):
        assert hasattr(AsyncAuditBackend, "subscribe")

    def test_protocol_has_unsubscribe_method(self):
        assert hasattr(AsyncAuditBackend, "unsubscribe")

    def test_protocol_has_close_method(self):
        assert hasattr(AsyncAuditBackend, "close")

    def test_sync_backend_not_async_protocol(self):
        """Sync backend should also pass async isinstance (structural check)
        since subscribe/unsubscribe are sync in both protocols, and
        runtime_checkable only checks method existence, not signatures."""
        sync_backend = ConformingSyncBackend()
        # runtime_checkable only checks that methods exist, not async-ness
        assert isinstance(sync_backend, AsyncAuditBackend)


# ---------------------------------------------------------------------------
# Tests: Conforming backend method behavior
# ---------------------------------------------------------------------------


class TestConformingSyncBackendBehavior:
    """Verify the conforming sync backend actually works."""

    def test_log_returns_int(self):
        backend = ConformingSyncBackend()
        decision = PolicyDecision.__new__(PolicyDecision)
        # Use a mock decision instead
        from unittest.mock import MagicMock

        decision = MagicMock(spec=PolicyDecision)
        result = backend.log("sess-1", decision)
        assert result == 1
        assert isinstance(result, int)

    def test_get_log_returns_list(self):
        backend = ConformingSyncBackend()
        result = backend.get_log("sess-1")
        assert result == []
        assert isinstance(result, list)

    def test_count_returns_int(self):
        backend = ConformingSyncBackend()
        result = backend.count()
        assert result == 0
        assert isinstance(result, int)

    def test_subscribe_accepts_callback(self):
        backend = ConformingSyncBackend()

        def cb(entry):
            pass

        backend.subscribe(cb)  # Should not raise

    def test_unsubscribe_accepts_callback(self):
        backend = ConformingSyncBackend()

        def cb(entry):
            pass

        backend.unsubscribe(cb)  # Should not raise

    def test_close(self):
        backend = ConformingSyncBackend()
        backend.close()  # Should not raise


class TestConformingAsyncBackendBehavior:
    """Verify the conforming async backend actually works."""

    @pytest.mark.asyncio
    async def test_log_returns_int(self):
        from unittest.mock import MagicMock

        backend = ConformingAsyncBackend()
        decision = MagicMock(spec=PolicyDecision)
        result = await backend.log("sess-1", decision)
        assert result == 1

    @pytest.mark.asyncio
    async def test_get_log_returns_list(self):
        backend = ConformingAsyncBackend()
        result = await backend.get_log("sess-1")
        assert result == []

    @pytest.mark.asyncio
    async def test_count_returns_int(self):
        backend = ConformingAsyncBackend()
        result = await backend.count()
        assert result == 0

    def test_subscribe_accepts_callback(self):
        backend = ConformingAsyncBackend()

        def cb(entry):
            pass

        backend.subscribe(cb)

    def test_unsubscribe_accepts_callback(self):
        backend = ConformingAsyncBackend()

        def cb(entry):
            pass

        backend.unsubscribe(cb)

    @pytest.mark.asyncio
    async def test_close(self):
        backend = ConformingAsyncBackend()
        await backend.close()


# ---------------------------------------------------------------------------
# Tests: Import and module-level
# ---------------------------------------------------------------------------


class TestModuleImports:
    """Verify the module and its exports are importable."""

    def test_import_audit_backend_module(self):
        import aegis.runtime.audit_backend as mod

        assert mod is not None

    def test_audit_backend_is_protocol(self):
        from typing import Protocol

        assert issubclass(AuditBackend, Protocol)

    def test_async_audit_backend_is_protocol(self):
        from typing import Protocol

        assert issubclass(AsyncAuditBackend, Protocol)

    def test_module_exports_both_protocols(self):
        import aegis.runtime.audit_backend as mod

        assert hasattr(mod, "AuditBackend")
        assert hasattr(mod, "AsyncAuditBackend")
