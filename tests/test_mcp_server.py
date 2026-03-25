"""Tests for aegis.mcp_server — MCP governance API server."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from aegis.core.action import Action
from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.risk import RiskLevel


# ---------------------------------------------------------------------------
# _load_policy
# ---------------------------------------------------------------------------


class TestLoadPolicy:
    """Tests for _load_policy helper."""

    def test_load_from_path(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            yaml.dump(
                {
                    "rules": [
                        {
                            "name": "block-delete",
                            "match_type": "delete",
                            "match_target": "*",
                            "risk_level": "critical",
                            "approval": "block",
                        }
                    ]
                }
            )
        )
        from aegis.mcp_server import _load_policy

        p = _load_policy(str(policy_file))
        assert len(p.rules) == 1
        assert p.rules[0].name == "block-delete"

    def test_load_from_env_var(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        policy_file = tmp_path / "env_policy.yaml"
        policy_file.write_text(yaml.dump({"rules": [{"name": "r1", "match_type": "read"}]}))
        monkeypatch.setenv("AEGIS_POLICY_PATH", str(policy_file))
        from aegis.mcp_server import _load_policy

        p = _load_policy()
        assert len(p.rules) == 1

    def test_fallback_to_empty_policy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AEGIS_POLICY_PATH", raising=False)
        from aegis.mcp_server import _load_policy

        p = _load_policy(None)
        assert len(p.rules) == 0

    def test_nonexistent_path_falls_back(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AEGIS_POLICY_PATH", raising=False)
        from aegis.mcp_server import _load_policy

        p = _load_policy("/nonexistent/policy.yaml")
        assert len(p.rules) == 0

    def test_path_takes_precedence_over_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env_file = tmp_path / "env.yaml"
        env_file.write_text(yaml.dump({"rules": [{"name": "env-rule"}]}))
        path_file = tmp_path / "path.yaml"
        path_file.write_text(yaml.dump({"rules": [{"name": "path-rule"}]}))
        monkeypatch.setenv("AEGIS_POLICY_PATH", str(env_file))
        from aegis.mcp_server import _load_policy

        p = _load_policy(str(path_file))
        assert p.rules[0].name == "path-rule"


# ---------------------------------------------------------------------------
# _create_server — tool functions extracted for testing
# ---------------------------------------------------------------------------


class TestCreateServer:
    """Test _create_server and its registered MCP tool functions."""

    @pytest.fixture(autouse=True)
    def _setup_policy(self) -> None:
        """Set up module-level _policy for tool functions."""
        import aegis.mcp_server as mod

        self._mod = mod
        self._original_policy = mod._policy
        mod._policy = Policy(
            rules=[
                PolicyRule(
                    name="block-delete",
                    match_type="delete",
                    match_target="*",
                    risk_level=RiskLevel.CRITICAL,
                    approval=Approval.BLOCK,
                ),
                PolicyRule(
                    name="allow-read",
                    match_type="read",
                    match_target="*",
                    risk_level=RiskLevel.LOW,
                    approval=Approval.AUTO,
                ),
            ]
        )
        yield
        mod._policy = self._original_policy

    @pytest.fixture()
    def server_and_tools(self) -> dict:
        """Create the MCP server and extract registered tools."""
        # Mock FastMCP to capture registered tool functions
        registered_tools: dict = {}

        class FakeMCP:
            def __init__(self, *args, **kwargs):
                pass

            def tool(self):
                def decorator(fn):
                    registered_tools[fn.__name__] = fn
                    return fn

                return decorator

            def run(self, **kwargs):
                pass

        with patch.dict("sys.modules", {"mcp": MagicMock(), "mcp.server": MagicMock(), "mcp.server.fastmcp": MagicMock()}):
            # Replace FastMCP with our fake
            sys.modules["mcp.server.fastmcp"] = type(sys)("mcp.server.fastmcp")
            sys.modules["mcp.server.fastmcp"].FastMCP = FakeMCP

            server = self._mod._create_server()
            return registered_tools

    def test_server_creates_successfully(self, server_and_tools: dict) -> None:
        assert len(server_and_tools) >= 4

    def test_evaluate_action_allowed(self, server_and_tools: dict) -> None:
        fn = server_and_tools["evaluate_action"]
        result = fn(action_type="read", target="filesystem")
        assert result["risk_level"] == RiskLevel.LOW.value
        assert result["approval"] == "auto"
        assert result["is_allowed"] is True
        assert result["action_type"] == "read"
        assert result["target"] == "filesystem"
        assert result["matched_rule"] == "allow-read"

    def test_evaluate_action_blocked(self, server_and_tools: dict) -> None:
        fn = server_and_tools["evaluate_action"]
        result = fn(action_type="delete", target="database")
        assert result["risk_level"] == RiskLevel.CRITICAL.value
        assert result["approval"] == "block"
        assert result["is_allowed"] is False
        assert result["matched_rule"] == "block-delete"

    def test_evaluate_action_with_optional_params(self, server_and_tools: dict) -> None:
        fn = server_and_tools["evaluate_action"]
        result = fn(
            action_type="read",
            target="filesystem",
            params={"path": "/etc/passwd"},
            description="Read password file",
            agent_id="agent-1",
        )
        assert result["is_allowed"] is True

    def test_evaluate_action_default_policy(self, server_and_tools: dict) -> None:
        """Action that doesn't match any rule gets default policy."""
        fn = server_and_tools["evaluate_action"]
        result = fn(action_type="custom_action", target="custom_target")
        assert result["matched_rule"] == "<default>"
        assert result["is_allowed"] is True

    def test_evaluate_batch(self, server_and_tools: dict) -> None:
        fn = server_and_tools["evaluate_batch"]
        results = fn(
            actions=[
                {"action_type": "read", "target": "filesystem"},
                {"action_type": "delete", "target": "database"},
            ]
        )
        assert len(results) == 2
        assert results[0]["is_allowed"] is True
        assert results[1]["is_allowed"] is False

    def test_evaluate_batch_empty(self, server_and_tools: dict) -> None:
        fn = server_and_tools["evaluate_batch"]
        results = fn(actions=[])
        assert results == []

    def test_evaluate_batch_minimal_action(self, server_and_tools: dict) -> None:
        """Batch items with missing optional fields use defaults."""
        fn = server_and_tools["evaluate_batch"]
        results = fn(actions=[{}])
        assert len(results) == 1
        # Empty action_type/target → uses default rule
        assert "risk_level" in results[0]

    def test_get_policy(self, server_and_tools: dict) -> None:
        fn = server_and_tools["get_policy"]
        result = fn()
        assert result["rule_count"] == 2
        assert len(result["rules"]) == 2
        assert result["rules"][0]["name"] == "block-delete"
        assert result["rules"][1]["name"] == "allow-read"
        assert "default_risk" in result
        assert "default_approval" in result

    def test_get_policy_rule_fields(self, server_and_tools: dict) -> None:
        fn = server_and_tools["get_policy"]
        result = fn()
        rule = result["rules"][0]
        assert "match_type" in rule
        assert "match_target" in rule
        assert "risk_level" in rule
        assert "approval" in rule
        assert "conditions" in rule

    def test_update_policy_success(self, server_and_tools: dict) -> None:
        fn = server_and_tools["update_policy"]
        new_yaml = yaml.dump(
            {
                "rules": [
                    {
                        "name": "new-rule",
                        "match_type": "write",
                        "match_target": "*",
                        "risk_level": "high",
                        "approval": "approve",
                    }
                ]
            }
        )
        result = fn(yaml_content=new_yaml)
        assert result["success"] is True
        assert result["rule_count"] == 1
        assert "1 rules loaded" in result["message"]

    def test_update_policy_invalid_yaml(self, server_and_tools: dict) -> None:
        fn = server_and_tools["update_policy"]
        result = fn(yaml_content="{{invalid yaml: [")
        # Even invalid YAML may parse as a string in yaml.safe_load; test with truly broken policy
        # The function catches exceptions from Policy.from_dict
        assert "success" in result

    def test_update_policy_bad_structure(self, server_and_tools: dict) -> None:
        fn = server_and_tools["update_policy"]
        # Pass valid YAML but invalid policy structure (rules should be list)
        result = fn(yaml_content="rules: not_a_list")
        assert result["success"] is False
        assert "error" in result

    def test_check_risk(self, server_and_tools: dict) -> None:
        fn = server_and_tools["check_risk"]
        result = fn(action_type="delete", target="anything")
        assert result["risk_level"] == RiskLevel.CRITICAL.value
        assert result["approval"] == "block"

    def test_check_risk_low(self, server_and_tools: dict) -> None:
        fn = server_and_tools["check_risk"]
        result = fn(action_type="read", target="anything")
        assert result["risk_level"] == RiskLevel.LOW.value
        assert result["approval"] == "auto"


# ---------------------------------------------------------------------------
# _create_server — import error handling
# ---------------------------------------------------------------------------


class TestCreateServerImportError:
    """Test _create_server when mcp package is not installed."""

    def test_exits_on_missing_mcp(self) -> None:
        import aegis.mcp_server as mod

        with patch.dict("sys.modules", {"mcp": None, "mcp.server": None, "mcp.server.fastmcp": None}):
            # Clear cached imports so the ImportError path triggers
            with pytest.raises(SystemExit) as exc_info:
                mod._create_server()
            assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


class TestMain:
    """Tests for the main() entry point."""

    @pytest.fixture(autouse=True)
    def _restore_policy(self) -> None:
        import aegis.mcp_server as mod

        original = mod._policy
        yield
        mod._policy = original

    def test_main_stdio(self) -> None:
        """main() with stdio transport calls server.run(transport='stdio')."""
        import aegis.mcp_server as mod

        mock_server = MagicMock()

        with patch.object(mod, "_create_server", return_value=mock_server):
            with patch.object(mod, "_load_policy", return_value=Policy(rules=[])):
                mod.main(["--transport", "stdio"])

        mock_server.run.assert_called_once_with(transport="stdio")

    def test_main_sse_transport(self) -> None:
        import aegis.mcp_server as mod

        mock_server = MagicMock()

        with patch.object(mod, "_create_server", return_value=mock_server) as create_mock:
            with patch.object(mod, "_load_policy", return_value=Policy(rules=[])):
                mod.main(["--transport", "sse", "--port", "9090", "--host", "127.0.0.1"])

        create_mock.assert_called_once_with(host="127.0.0.1", port=9090)
        mock_server.run.assert_called_once_with(transport="sse")

    def test_main_streamable_http(self) -> None:
        import aegis.mcp_server as mod

        mock_server = MagicMock()

        with patch.object(mod, "_create_server", return_value=mock_server):
            with patch.object(mod, "_load_policy", return_value=Policy(rules=[])):
                mod.main(["--transport", "streamable-http", "--port", "7070"])

        mock_server.run.assert_called_once_with(transport="streamable-http")

    def test_main_with_policy_path(self, tmp_path: Path) -> None:
        import aegis.mcp_server as mod

        policy_file = tmp_path / "test.yaml"
        policy_file.write_text(yaml.dump({"rules": [{"name": "test-rule", "match_type": "*"}]}))

        mock_server = MagicMock()
        with patch.object(mod, "_create_server", return_value=mock_server):
            mod.main(["--policy", str(policy_file)])

        assert len(mod._policy.rules) == 1

    def test_main_default_args(self) -> None:
        """main() with no args uses defaults: stdio, 8080, 0.0.0.0."""
        import aegis.mcp_server as mod

        mock_server = MagicMock()

        with patch.object(mod, "_create_server", return_value=mock_server) as create_mock:
            with patch.object(mod, "_load_policy", return_value=Policy(rules=[])):
                mod.main([])

        create_mock.assert_called_once_with(host="0.0.0.0", port=8080)
        mock_server.run.assert_called_once_with(transport="stdio")

    def test_main_loads_policy_into_module(self, tmp_path: Path) -> None:
        """main() should set the module-level _policy."""
        import aegis.mcp_server as mod

        policy_file = tmp_path / "rules.yaml"
        policy_file.write_text(
            yaml.dump(
                {
                    "rules": [
                        {"name": "r1", "match_type": "x"},
                        {"name": "r2", "match_type": "y"},
                    ]
                }
            )
        )

        mock_server = MagicMock()
        with patch.object(mod, "_create_server", return_value=mock_server):
            mod.main(["--policy", str(policy_file)])

        assert len(mod._policy.rules) == 2

    def test_main_stderr_output_stdio(self, capsys: pytest.CaptureFixture) -> None:
        """Stdio transport prints starting message but not host:port."""
        import aegis.mcp_server as mod

        mock_server = MagicMock()
        with patch.object(mod, "_create_server", return_value=mock_server):
            with patch.object(mod, "_load_policy", return_value=Policy(rules=[])):
                mod.main([])

        captured = capsys.readouterr()
        assert "Aegis MCP server starting" in captured.err
        assert "Listening on" not in captured.err

    def test_main_stderr_output_sse(self, capsys: pytest.CaptureFixture) -> None:
        """SSE transport prints both starting message and host:port."""
        import aegis.mcp_server as mod

        mock_server = MagicMock()
        with patch.object(mod, "_create_server", return_value=mock_server):
            with patch.object(mod, "_load_policy", return_value=Policy(rules=[])):
                mod.main(["--transport", "sse", "--host", "localhost", "--port", "3000"])

        captured = capsys.readouterr()
        assert "Aegis MCP server starting" in captured.err
        assert "Listening on localhost:3000" in captured.err
        assert "sse" in captured.err
