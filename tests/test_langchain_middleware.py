"""Tests for LangChain AgentMiddleware integration (AegisMiddleware).

All langchain/langgraph dependencies are mocked so these tests run
without any optional packages installed.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aegis.core.policy import Approval, Policy, PolicyDecision, PolicyRule
from aegis.core.risk import RiskLevel

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_tool_call_request(
    tool_name: str = "search",
    tool_args: dict | None = None,
    tool_call_id: str = "call_123",
) -> SimpleNamespace:
    """Build a mock ToolCallRequest matching LangChain's interface."""
    return SimpleNamespace(
        tool_call={
            "name": tool_name,
            "args": tool_args or {},
            "id": tool_call_id,
        },
        tool=SimpleNamespace(name=tool_name),
    )


@pytest.fixture
def mock_middleware_deps():
    """Mock langchain + langgraph so AegisMiddleware can be imported."""
    # Mock langchain_core.messages.ToolMessage
    mock_tool_message_cls = MagicMock()

    def _tool_message_ctor(**kwargs):
        return SimpleNamespace(**kwargs)

    mock_tool_message_cls.side_effect = _tool_message_ctor

    mock_lc_messages = MagicMock()
    mock_lc_messages.ToolMessage = mock_tool_message_cls

    mock_lc_core = MagicMock()
    mock_lc_core.messages = mock_lc_messages

    # Mock langchain.agents.middleware.types.AgentMiddleware
    mock_agent_middleware = type("AgentMiddleware", (), {})
    mock_middleware_types = MagicMock()
    mock_middleware_types.AgentMiddleware = mock_agent_middleware

    mock_middleware_pkg = MagicMock()
    mock_middleware_pkg.types = mock_middleware_types

    mock_agents = MagicMock()
    mock_agents.middleware = mock_middleware_pkg
    mock_agents.middleware.types = mock_middleware_types

    mock_langchain = MagicMock()
    mock_langchain.agents = mock_agents
    mock_langchain.agents.middleware = mock_middleware_pkg
    mock_langchain.agents.middleware.types = mock_middleware_types

    # Mock langgraph.prebuilt.tool_node.ToolCallRequest
    mock_tool_call_request = type("ToolCallRequest", (), {})
    mock_tool_node = MagicMock()
    mock_tool_node.ToolCallRequest = mock_tool_call_request

    mock_prebuilt = MagicMock()
    mock_prebuilt.tool_node = mock_tool_node

    mock_langgraph = MagicMock()
    mock_langgraph.prebuilt = mock_prebuilt
    mock_langgraph.prebuilt.tool_node = mock_tool_node

    modules = {
        "langchain_core": mock_lc_core,
        "langchain_core.messages": mock_lc_messages,
        "langchain": mock_langchain,
        "langchain.agents": mock_agents,
        "langchain.agents.middleware": mock_middleware_pkg,
        "langchain.agents.middleware.types": mock_middleware_types,
        "langgraph": mock_langgraph,
        "langgraph.prebuilt": mock_prebuilt,
        "langgraph.prebuilt.tool_node": mock_tool_node,
    }

    with patch.dict("sys.modules", modules):
        # Force re-import so the module sees the mocked deps
        sys.modules.pop("aegis.adapters.langchain", None)
        import aegis.adapters.langchain as lc_mod

        # Flip the flag so _require_middleware() passes
        lc_mod._HAS_MIDDLEWARE = True
        yield lc_mod


@pytest.fixture
def block_delete_policy() -> Policy:
    """Policy: auto-allow reads, require approval for writes, block deletes."""
    return Policy(
        rules=[
            PolicyRule(
                match_type="search",
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
                name="search_auto",
            ),
            PolicyRule(
                match_type="write_*",
                risk_level=RiskLevel.MEDIUM,
                approval=Approval.APPROVE,
                name="write_approve",
            ),
            PolicyRule(
                match_type="delete_*",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
                name="delete_block",
            ),
        ],
        default_risk_level=RiskLevel.MEDIUM,
        default_approval=Approval.AUTO,
    )


# ---------------------------------------------------------------------------
# AegisMiddleware construction tests
# ---------------------------------------------------------------------------


class TestAegisMiddlewareInit:
    """Construction and property tests."""

    def test_init_basic(self, mock_middleware_deps, block_delete_policy):
        """Should construct with required params."""
        mw = mock_middleware_deps.AegisMiddleware(policy=block_delete_policy)

        assert mw.name == "AegisMiddleware"
        assert mw.policy is block_delete_policy
        assert len(mw.session_id) == 12  # auto-generated hex

    def test_init_custom_session(self, mock_middleware_deps, block_delete_policy):
        """Should accept a custom session_id."""
        mw = mock_middleware_deps.AegisMiddleware(
            policy=block_delete_policy,
            session_id="custom-sess",
        )
        assert mw.session_id == "custom-sess"

    def test_policy_hot_swap(self, mock_middleware_deps, block_delete_policy):
        """Should allow replacing the policy at runtime."""
        mw = mock_middleware_deps.AegisMiddleware(policy=block_delete_policy)
        new_policy = Policy()
        mw.policy = new_policy
        assert mw.policy is new_policy

    def test_require_middleware_raises(self):
        """_require_middleware should raise when deps are missing."""
        sys.modules.pop("aegis.adapters.langchain", None)
        import aegis.adapters.langchain as lc_mod

        # Ensure the flag is False (default when import fails)
        original = lc_mod._HAS_MIDDLEWARE
        lc_mod._HAS_MIDDLEWARE = False
        try:
            with pytest.raises(ImportError, match="langchain_v1"):
                lc_mod._require_middleware()
        finally:
            lc_mod._HAS_MIDDLEWARE = original


# ---------------------------------------------------------------------------
# wrap_tool_call (sync) tests
# ---------------------------------------------------------------------------


class TestWrapToolCallSync:
    """Synchronous wrap_tool_call tests."""

    def test_allowed_call_passes_through(self, mock_middleware_deps, block_delete_policy):
        """Allowed tool calls should delegate to the handler."""
        mw = mock_middleware_deps.AegisMiddleware(policy=block_delete_policy)

        request = _make_tool_call_request(tool_name="search", tool_args={"query": "test"})
        handler = MagicMock(return_value=SimpleNamespace(content="search result"))

        result = mw.wrap_tool_call(request, handler)

        handler.assert_called_once_with(request)
        assert result.content == "search result"

    def test_blocked_call_returns_error_message(self, mock_middleware_deps, block_delete_policy):
        """Blocked tool calls should return a ToolMessage with error."""
        mw = mock_middleware_deps.AegisMiddleware(policy=block_delete_policy)

        request = _make_tool_call_request(tool_name="delete_user", tool_args={"id": "42"})
        handler = MagicMock()

        result = mw.wrap_tool_call(request, handler)

        handler.assert_not_called()
        assert "AEGIS BLOCKED" in result.content
        assert "delete_block" in result.content
        assert result.tool_call_id == "call_123"
        assert result.status == "error"

    def test_approval_required_still_passes(self, mock_middleware_deps, block_delete_policy):
        """Approval-required calls should pass through (approval gate is Runtime's job)."""
        mw = mock_middleware_deps.AegisMiddleware(policy=block_delete_policy)

        request = _make_tool_call_request(tool_name="write_file", tool_args={"path": "/tmp"})
        handler = MagicMock(return_value=SimpleNamespace(content="written"))

        result = mw.wrap_tool_call(request, handler)

        handler.assert_called_once_with(request)
        assert result.content == "written"

    def test_default_policy_allows_unmatched(self, mock_middleware_deps, block_delete_policy):
        """Unmatched tools should use the default policy (AUTO)."""
        mw = mock_middleware_deps.AegisMiddleware(policy=block_delete_policy)

        request = _make_tool_call_request(tool_name="calculator", tool_args={"expr": "2+2"})
        handler = MagicMock(return_value=SimpleNamespace(content="4"))

        result = mw.wrap_tool_call(request, handler)

        handler.assert_called_once_with(request)
        assert result.content == "4"

    def test_tool_target_map(self, mock_middleware_deps, block_delete_policy):
        """tool_target_map should override the default target."""
        mw = mock_middleware_deps.AegisMiddleware(
            policy=block_delete_policy,
            target="default",
            tool_target_map={"search": "web-search"},
        )

        request = _make_tool_call_request(tool_name="search", tool_args={"q": "test"})
        handler = MagicMock(return_value=SimpleNamespace(content="ok"))

        mw.wrap_tool_call(request, handler)

        # Verify the action was built with the mapped target
        # (We check indirectly via the policy evaluation working correctly)
        handler.assert_called_once()

    def test_agent_id_attached(self, mock_middleware_deps, block_delete_policy):
        """agent_id should be attached to actions."""
        mw = mock_middleware_deps.AegisMiddleware(
            policy=block_delete_policy,
            agent_id="agent-007",
        )

        # Build action directly to verify
        action = mw._build_action("search", {"q": "test"})
        assert action.agent_id == "agent-007"


# ---------------------------------------------------------------------------
# awrap_tool_call (async) tests
# ---------------------------------------------------------------------------


class TestWrapToolCallAsync:
    """Async awrap_tool_call tests."""

    @pytest.mark.asyncio
    async def test_allowed_call_passes_through(self, mock_middleware_deps, block_delete_policy):
        """Allowed async tool calls should delegate to the handler."""
        mw = mock_middleware_deps.AegisMiddleware(policy=block_delete_policy)

        request = _make_tool_call_request(tool_name="search", tool_args={"query": "test"})
        handler = AsyncMock(return_value=SimpleNamespace(content="async result"))

        result = await mw.awrap_tool_call(request, handler)

        handler.assert_awaited_once_with(request)
        assert result.content == "async result"

    @pytest.mark.asyncio
    async def test_blocked_call_returns_error_message(
        self, mock_middleware_deps, block_delete_policy
    ):
        """Blocked async tool calls should return a ToolMessage with error."""
        mw = mock_middleware_deps.AegisMiddleware(policy=block_delete_policy)

        request = _make_tool_call_request(
            tool_name="delete_user",
            tool_args={"id": "42"},
            tool_call_id="call_456",
        )
        handler = AsyncMock()

        result = await mw.awrap_tool_call(request, handler)

        handler.assert_not_awaited()
        assert "AEGIS BLOCKED" in result.content
        assert "delete_block" in result.content
        assert result.tool_call_id == "call_456"

    @pytest.mark.asyncio
    async def test_on_blocked_callback_invoked(self, mock_middleware_deps, block_delete_policy):
        """on_blocked callback should be awaited when a call is blocked."""
        on_blocked = AsyncMock()
        mw = mock_middleware_deps.AegisMiddleware(
            policy=block_delete_policy,
            on_blocked=on_blocked,
        )

        request = _make_tool_call_request(tool_name="delete_user", tool_args={"id": "1"})
        handler = AsyncMock()

        await mw.awrap_tool_call(request, handler)

        on_blocked.assert_awaited_once()
        decision = on_blocked.call_args[0][0]
        assert isinstance(decision, PolicyDecision)
        assert decision.approval == Approval.BLOCK

    @pytest.mark.asyncio
    async def test_on_blocked_not_called_for_allowed(
        self, mock_middleware_deps, block_delete_policy
    ):
        """on_blocked callback should NOT be invoked for allowed calls."""
        on_blocked = AsyncMock()
        mw = mock_middleware_deps.AegisMiddleware(
            policy=block_delete_policy,
            on_blocked=on_blocked,
        )

        request = _make_tool_call_request(tool_name="search", tool_args={"q": "safe"})
        handler = AsyncMock(return_value=SimpleNamespace(content="ok"))

        await mw.awrap_tool_call(request, handler)

        on_blocked.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_approval_required_passes_async(self, mock_middleware_deps, block_delete_policy):
        """Approval-required calls pass through in async context too."""
        mw = mock_middleware_deps.AegisMiddleware(policy=block_delete_policy)

        request = _make_tool_call_request(tool_name="write_doc", tool_args={"text": "hello"})
        handler = AsyncMock(return_value=SimpleNamespace(content="written"))

        result = await mw.awrap_tool_call(request, handler)

        handler.assert_awaited_once_with(request)
        assert result.content == "written"


# ---------------------------------------------------------------------------
# Audit logging tests
# ---------------------------------------------------------------------------


class TestAegisMiddlewareAudit:
    """Tests for audit trail integration."""

    def test_audit_logged_on_allow(self, mock_middleware_deps, block_delete_policy, tmp_path):
        """Allowed calls should be logged to the audit logger."""
        from aegis.runtime.audit import AuditLogger

        audit = AuditLogger(db_path=tmp_path / "test_audit.db")
        mw = mock_middleware_deps.AegisMiddleware(
            policy=block_delete_policy,
            audit_logger=audit,
            session_id="sess-allow",
        )

        request = _make_tool_call_request(tool_name="search", tool_args={"q": "test"})
        handler = MagicMock(return_value=SimpleNamespace(content="ok"))

        mw.wrap_tool_call(request, handler)

        entries = audit.get_log(session_id="sess-allow")
        assert len(entries) == 1
        assert entries[0]["action_type"] == "search"
        assert entries[0]["approval"] == "auto"
        assert entries[0]["result_status"] is None  # allowed, no result recorded

    def test_audit_logged_on_block(self, mock_middleware_deps, block_delete_policy, tmp_path):
        """Blocked calls should be logged with BLOCKED result."""
        from aegis.runtime.audit import AuditLogger

        audit = AuditLogger(db_path=tmp_path / "test_audit.db")
        mw = mock_middleware_deps.AegisMiddleware(
            policy=block_delete_policy,
            audit_logger=audit,
            session_id="sess-block",
        )

        request = _make_tool_call_request(tool_name="delete_user", tool_args={"id": "1"})
        handler = MagicMock()

        mw.wrap_tool_call(request, handler)

        entries = audit.get_log(session_id="sess-block")
        assert len(entries) == 1
        assert entries[0]["action_type"] == "delete_user"
        assert entries[0]["approval"] == "block"
        assert entries[0]["result_status"] == "blocked"

    def test_no_audit_when_logger_absent(self, mock_middleware_deps, block_delete_policy):
        """Should not fail when audit_logger is None."""
        mw = mock_middleware_deps.AegisMiddleware(
            policy=block_delete_policy,
            audit_logger=None,
        )

        request = _make_tool_call_request(tool_name="search", tool_args={"q": "test"})
        handler = MagicMock(return_value=SimpleNamespace(content="ok"))

        # Should not raise
        result = mw.wrap_tool_call(request, handler)
        assert result.content == "ok"


# ---------------------------------------------------------------------------
# create_aegis_middleware factory tests
# ---------------------------------------------------------------------------


class TestCreateAegisMiddleware:
    """Tests for the convenience factory function."""

    def test_creates_middleware_instance(self, mock_middleware_deps, block_delete_policy):
        """Factory should return an AegisMiddleware instance."""
        mw = mock_middleware_deps.create_aegis_middleware(
            policy=block_delete_policy,
            target="my-agent",
            session_id="factory-sess",
        )

        assert isinstance(mw, mock_middleware_deps.AegisMiddleware)
        assert mw.session_id == "factory-sess"
        assert mw.policy is block_delete_policy

    def test_forwards_all_params(self, mock_middleware_deps, block_delete_policy):
        """Factory should forward all optional parameters."""
        on_blocked = AsyncMock()
        tool_map = {"search": "web"}
        audit = MagicMock()

        mw = mock_middleware_deps.create_aegis_middleware(
            policy=block_delete_policy,
            target="custom-target",
            session_id="sess",
            audit_logger=audit,
            agent_id="agent-x",
            tool_target_map=tool_map,
            on_blocked=on_blocked,
        )

        assert mw._target == "custom-target"
        assert mw._agent_id == "agent-x"
        assert mw._tool_target_map == tool_map
        assert mw._on_blocked is on_blocked
        assert mw._audit is audit


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases and robustness tests."""

    def test_empty_tool_call_args(self, mock_middleware_deps, block_delete_policy):
        """Should handle tool calls with no arguments."""
        mw = mock_middleware_deps.AegisMiddleware(policy=block_delete_policy)

        request = _make_tool_call_request(tool_name="search", tool_args={})
        handler = MagicMock(return_value=SimpleNamespace(content="ok"))

        mw.wrap_tool_call(request, handler)
        handler.assert_called_once()

    def test_missing_tool_call_fields(self, mock_middleware_deps, block_delete_policy):
        """Should handle incomplete tool_call dicts gracefully."""
        mw = mock_middleware_deps.AegisMiddleware(policy=block_delete_policy)

        # Minimal tool_call with only name
        request = SimpleNamespace(
            tool_call={"name": "search"},
            tool=SimpleNamespace(name="search"),
        )
        handler = MagicMock(return_value=SimpleNamespace(content="ok"))

        mw.wrap_tool_call(request, handler)
        handler.assert_called_once()

    def test_policy_with_target_matching(self, mock_middleware_deps):
        """Policy rules with target matching should work via tool_target_map."""
        policy = Policy(
            rules=[
                PolicyRule(
                    match_type="*",
                    match_target="production",
                    risk_level=RiskLevel.CRITICAL,
                    approval=Approval.BLOCK,
                    name="block_prod",
                ),
            ],
            default_risk_level=RiskLevel.LOW,
            default_approval=Approval.AUTO,
        )
        mw = mock_middleware_deps.AegisMiddleware(
            policy=policy,
            tool_target_map={"deploy": "production"},
        )

        # "deploy" maps to target "production" which is blocked
        request = _make_tool_call_request(tool_name="deploy", tool_args={"env": "prod"})
        handler = MagicMock()

        result = mw.wrap_tool_call(request, handler)

        handler.assert_not_called()
        assert "AEGIS BLOCKED" in result.content

    def test_unmapped_tool_uses_default_target(self, mock_middleware_deps):
        """Tools not in tool_target_map should use the default target."""
        policy = Policy(
            rules=[
                PolicyRule(
                    match_type="*",
                    match_target="production",
                    risk_level=RiskLevel.CRITICAL,
                    approval=Approval.BLOCK,
                    name="block_prod",
                ),
            ],
            default_risk_level=RiskLevel.LOW,
            default_approval=Approval.AUTO,
        )
        mw = mock_middleware_deps.AegisMiddleware(
            policy=policy,
            target="staging",  # default target is NOT production
            tool_target_map={"deploy": "production"},
        )

        # "search" is not in tool_target_map, uses "staging" target
        request = _make_tool_call_request(tool_name="search", tool_args={"q": "test"})
        handler = MagicMock(return_value=SimpleNamespace(content="ok"))

        result = mw.wrap_tool_call(request, handler)

        handler.assert_called_once()
        assert result.content == "ok"

    @pytest.mark.asyncio
    async def test_multiple_sequential_calls(self, mock_middleware_deps, block_delete_policy):
        """Middleware should handle multiple sequential calls correctly."""
        mw = mock_middleware_deps.AegisMiddleware(policy=block_delete_policy)

        # Call 1: allowed
        req1 = _make_tool_call_request(tool_name="search", tool_args={"q": "a"})
        handler1 = AsyncMock(return_value=SimpleNamespace(content="result_a"))
        result1 = await mw.awrap_tool_call(req1, handler1)
        assert result1.content == "result_a"

        # Call 2: blocked
        req2 = _make_tool_call_request(tool_name="delete_user", tool_args={"id": "1"})
        handler2 = AsyncMock()
        result2 = await mw.awrap_tool_call(req2, handler2)
        assert "AEGIS BLOCKED" in result2.content

        # Call 3: allowed again
        req3 = _make_tool_call_request(tool_name="search", tool_args={"q": "b"})
        handler3 = AsyncMock(return_value=SimpleNamespace(content="result_b"))
        result3 = await mw.awrap_tool_call(req3, handler3)
        assert result3.content == "result_b"

        # Verify handlers called/not-called correctly
        handler1.assert_awaited_once()
        handler2.assert_not_awaited()
        handler3.assert_awaited_once()
