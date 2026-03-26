"""Tests for aegis.core.mcp_transport — MCP transport security validator."""

from __future__ import annotations

from aegis.core.mcp_security import Severity
from aegis.core.mcp_transport import (
    MCPTransportValidator,
    NetworkConfig,
    StdioConfig,
    TransportFinding,
    TransportProfile,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _has_category(profile: TransportProfile, category: str) -> bool:
    return any(f.category == category for f in profile.findings)


def _has_severity(profile: TransportProfile, severity: str) -> bool:
    return any(f.severity == severity for f in profile.findings)


def _finding_count(profile: TransportProfile) -> int:
    return len(profile.findings)


# ---------------------------------------------------------------------------
# StdioConfig dataclass
# ---------------------------------------------------------------------------


class TestStdioConfig:
    def test_minimal(self):
        cfg = StdioConfig(command="node")
        assert cfg.command == "node"
        assert cfg.args == []
        assert cfg.env is None

    def test_full(self):
        cfg = StdioConfig(command="npx", args=["-y", "pkg"], env={"FOO": "bar"})
        assert cfg.command == "npx"
        assert cfg.args == ["-y", "pkg"]
        assert cfg.env == {"FOO": "bar"}

    def test_frozen(self):
        cfg = StdioConfig(command="node")
        try:
            cfg.command = "python"  # type: ignore[misc]
            assert False, "Should raise"
        except AttributeError:
            pass


# ---------------------------------------------------------------------------
# NetworkConfig dataclass
# ---------------------------------------------------------------------------


class TestNetworkConfig:
    def test_defaults(self):
        cfg = NetworkConfig(url="https://example.com")
        assert cfg.timeout_seconds == 30.0
        assert cfg.verify_ssl is True
        assert cfg.headers is None

    def test_full(self):
        cfg = NetworkConfig(
            url="https://api.example.com/mcp",
            headers={"Authorization": "Bearer token"},
            timeout_seconds=60.0,
            verify_ssl=False,
        )
        assert cfg.headers == {"Authorization": "Bearer token"}
        assert cfg.timeout_seconds == 60.0
        assert cfg.verify_ssl is False


# ---------------------------------------------------------------------------
# Stdio: Command Injection
# ---------------------------------------------------------------------------


class TestStdioCommandInjection:
    def setup_method(self):
        self.v = MCPTransportValidator()

    def test_clean_command(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="node", args=["server.js"]),
            server_name="test",
        )
        assert not _has_category(profile, "command_injection")

    def test_semicolon_in_command(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="node; rm -rf /", args=[]),
            server_name="test",
        )
        assert _has_category(profile, "command_injection")
        assert _has_severity(profile, Severity.CRITICAL)

    def test_pipe_in_args(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="node", args=["server.js", "| cat /etc/passwd"]),
            server_name="test",
        )
        assert _has_category(profile, "command_injection")

    def test_command_substitution_dollar_paren(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="node", args=["$(whoami)"]),
            server_name="test",
        )
        assert _has_category(profile, "command_injection")

    def test_backtick_substitution(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="node", args=["`id`"]),
            server_name="test",
        )
        assert _has_category(profile, "command_injection")

    def test_double_ampersand(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="node", args=["server.js && echo pwned"]),
            server_name="test",
        )
        assert _has_category(profile, "command_injection")

    def test_dollar_brace(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="node", args=["${PATH}"]),
            server_name="test",
        )
        assert _has_category(profile, "command_injection")


# ---------------------------------------------------------------------------
# Stdio: Dangerous Commands
# ---------------------------------------------------------------------------


class TestStdioDangerousCommands:
    def setup_method(self):
        self.v = MCPTransportValidator()

    def test_sh_c(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="sh", args=["-c", "node server.js"]),
            server_name="test",
        )
        assert _has_severity(profile, Severity.HIGH)

    def test_bash_c(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="bash", args=["-c", "echo hello"]),
            server_name="test",
        )
        assert _has_severity(profile, Severity.HIGH)

    def test_eval(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="eval", args=["node server.js"]),
            server_name="test",
        )
        assert _has_severity(profile, Severity.HIGH)

    def test_bash_without_c_is_not_flagged(self):
        """bash without -c shouldn't trigger the dangerous command check."""
        profile = self.v.validate_stdio(
            StdioConfig(command="bash", args=["script.sh"]),
            server_name="test",
        )
        # Should not have a HIGH finding from dangerous commands
        dangerous = [
            f for f in profile.findings
            if f.severity == Severity.HIGH and "Dangerous command" in f.detail
        ]
        assert len(dangerous) == 0

    def test_full_path_command(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="/bin/bash", args=["-c", "echo hello"]),
            server_name="test",
        )
        assert _has_severity(profile, Severity.HIGH)


# ---------------------------------------------------------------------------
# Stdio: Path Traversal in Args
# ---------------------------------------------------------------------------


class TestStdioPathTraversal:
    def setup_method(self):
        self.v = MCPTransportValidator()

    def test_dotdot_in_args(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="node", args=["../../etc/passwd"]),
            server_name="test",
        )
        assert _has_category(profile, "command_injection")
        assert _has_severity(profile, Severity.HIGH)

    def test_clean_absolute_path(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="node", args=["/home/user/server.js"]),
            server_name="test",
        )
        traversal = [f for f in profile.findings if "Path traversal" in f.detail]
        assert len(traversal) == 0


# ---------------------------------------------------------------------------
# Stdio: Sensitive Env Vars
# ---------------------------------------------------------------------------


class TestStdioSensitiveEnv:
    def setup_method(self):
        self.v = MCPTransportValidator()

    def test_api_key_in_env(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="node", args=[], env={"OPENAI_API_KEY": "sk-..."}),
            server_name="test",
        )
        assert _has_severity(profile, Severity.MEDIUM)

    def test_secret_in_env(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="node", args=[], env={"MY_SECRET": "value"}),
            server_name="test",
        )
        assert _has_severity(profile, Severity.MEDIUM)

    def test_password_in_env(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="node", args=[], env={"DB_PASSWORD": "hunter2"}),
            server_name="test",
        )
        assert _has_severity(profile, Severity.MEDIUM)

    def test_token_in_env(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="node", args=[], env={"AUTH_TOKEN": "abc123"}),
            server_name="test",
        )
        assert _has_severity(profile, Severity.MEDIUM)

    def test_clean_env(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="node", args=[], env={"NODE_ENV": "production", "PORT": "3000"}),
            server_name="test",
        )
        sensitive = [f for f in profile.findings if f.category == "missing_auth"]
        assert len(sensitive) == 0

    def test_no_env(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="node", args=[]),
            server_name="test",
        )
        sensitive = [f for f in profile.findings if f.category == "missing_auth"]
        assert len(sensitive) == 0


# ---------------------------------------------------------------------------
# Stdio: Unpinned Packages
# ---------------------------------------------------------------------------


class TestStdioUnpinnedPackages:
    def setup_method(self):
        self.v = MCPTransportValidator()

    def test_unpinned_npx_package(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="npx", args=["-y", "@modelcontextprotocol/server-filesystem"]),
            server_name="test",
        )
        unpinned = [f for f in profile.findings if "Unpinned" in f.detail]
        assert len(unpinned) >= 1

    def test_pinned_npx_package(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="npx", args=["-y", "@modelcontextprotocol/server-filesystem@1.2.3"]),
            server_name="test",
        )
        unpinned = [f for f in profile.findings if "Unpinned" in f.detail]
        assert len(unpinned) == 0

    def test_not_npx_is_ignored(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="node", args=["-y", "some-package"]),
            server_name="test",
        )
        unpinned = [f for f in profile.findings if "Unpinned" in f.detail]
        assert len(unpinned) == 0

    def test_npx_without_y_flag(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="npx", args=["@scope/pkg"]),
            server_name="test",
        )
        unpinned = [f for f in profile.findings if "Unpinned" in f.detail]
        assert len(unpinned) == 0


# ---------------------------------------------------------------------------
# Stdio: World-writable Command
# ---------------------------------------------------------------------------


class TestStdioWorldWritable:
    def setup_method(self):
        self.v = MCPTransportValidator()

    def test_tmp_command(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="/tmp/malicious-server"),
            server_name="test",
        )
        assert _has_severity(profile, Severity.LOW)

    def test_var_tmp_command(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="/var/tmp/server"),
            server_name="test",
        )
        assert _has_severity(profile, Severity.LOW)

    def test_normal_path(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="/usr/local/bin/node"),
            server_name="test",
        )
        world_writable = [f for f in profile.findings if "world-writable" in f.detail]
        assert len(world_writable) == 0


# ---------------------------------------------------------------------------
# Network: HTTP without TLS
# ---------------------------------------------------------------------------


class TestNetworkHttpWithoutTLS:
    def setup_method(self):
        self.v = MCPTransportValidator()

    def test_http_is_critical(self):
        profile = self.v.validate_network(
            NetworkConfig(url="http://api.example.com/mcp"),
            server_name="test",
        )
        assert _has_category(profile, "insecure_transport")
        assert _has_severity(profile, Severity.CRITICAL)
        assert not profile.is_secure

    def test_https_is_ok(self):
        profile = self.v.validate_network(
            NetworkConfig(
                url="https://api.example.com/mcp",
                headers={"Authorization": "Bearer token"},
            ),
            server_name="test",
        )
        insecure = [
            f for f in profile.findings
            if f.category == "insecure_transport" and f.severity == Severity.CRITICAL
        ]
        assert len(insecure) == 0


# ---------------------------------------------------------------------------
# Network: Missing Auth
# ---------------------------------------------------------------------------


class TestNetworkMissingAuth:
    def setup_method(self):
        self.v = MCPTransportValidator()

    def test_no_headers_at_all(self):
        profile = self.v.validate_network(
            NetworkConfig(url="https://api.example.com/mcp"),
            server_name="test",
        )
        assert _has_category(profile, "missing_auth")
        assert _has_severity(profile, Severity.HIGH)

    def test_authorization_header(self):
        profile = self.v.validate_network(
            NetworkConfig(
                url="https://api.example.com/mcp",
                headers={"Authorization": "Bearer token"},
            ),
            server_name="test",
        )
        auth_findings = [f for f in profile.findings if f.category == "missing_auth"]
        assert len(auth_findings) == 0

    def test_x_api_key_header(self):
        profile = self.v.validate_network(
            NetworkConfig(
                url="https://api.example.com/mcp",
                headers={"X-API-Key": "key123"},
            ),
            server_name="test",
        )
        auth_findings = [f for f in profile.findings if f.category == "missing_auth"]
        assert len(auth_findings) == 0

    def test_wrong_header_is_still_missing(self):
        profile = self.v.validate_network(
            NetworkConfig(
                url="https://api.example.com/mcp",
                headers={"Content-Type": "application/json"},
            ),
            server_name="test",
        )
        assert _has_category(profile, "missing_auth")


# ---------------------------------------------------------------------------
# Network: Localhost Binding
# ---------------------------------------------------------------------------


class TestNetworkLocalhost:
    def setup_method(self):
        self.v = MCPTransportValidator()

    def test_localhost(self):
        profile = self.v.validate_network(
            NetworkConfig(url="https://localhost:3000/mcp"),
            server_name="test",
        )
        assert _has_category(profile, "insecure_transport")

    def test_127_0_0_1(self):
        profile = self.v.validate_network(
            NetworkConfig(url="https://127.0.0.1:3000/mcp"),
            server_name="test",
        )
        localhost = [f for f in profile.findings if "Localhost" in f.detail]
        assert len(localhost) >= 1

    def test_remote_host_no_localhost_finding(self):
        profile = self.v.validate_network(
            NetworkConfig(
                url="https://api.example.com/mcp",
                headers={"Authorization": "Bearer token"},
            ),
            server_name="test",
        )
        localhost = [f for f in profile.findings if "Localhost" in f.detail]
        assert len(localhost) == 0


# ---------------------------------------------------------------------------
# Network: Timeout
# ---------------------------------------------------------------------------


class TestNetworkTimeout:
    def setup_method(self):
        self.v = MCPTransportValidator()

    def test_short_timeout(self):
        profile = self.v.validate_network(
            NetworkConfig(url="https://api.example.com/mcp", timeout_seconds=2.0),
            server_name="test",
        )
        assert _has_category(profile, "timeout")
        assert _has_severity(profile, Severity.MEDIUM)

    def test_long_timeout(self):
        profile = self.v.validate_network(
            NetworkConfig(url="https://api.example.com/mcp", timeout_seconds=300.0),
            server_name="test",
        )
        assert _has_category(profile, "timeout")
        assert _has_severity(profile, Severity.LOW)

    def test_normal_timeout(self):
        profile = self.v.validate_network(
            NetworkConfig(url="https://api.example.com/mcp", timeout_seconds=30.0),
            server_name="test",
        )
        timeout_findings = [f for f in profile.findings if f.category == "timeout"]
        assert len(timeout_findings) == 0

    def test_boundary_5s(self):
        """Exactly 5s should not trigger short timeout."""
        profile = self.v.validate_network(
            NetworkConfig(url="https://api.example.com/mcp", timeout_seconds=5.0),
            server_name="test",
        )
        short = [f for f in profile.findings if f.category == "timeout" and f.severity == Severity.MEDIUM]
        assert len(short) == 0

    def test_boundary_120s(self):
        """Exactly 120s should not trigger long timeout."""
        profile = self.v.validate_network(
            NetworkConfig(url="https://api.example.com/mcp", timeout_seconds=120.0),
            server_name="test",
        )
        long = [f for f in profile.findings if f.category == "timeout" and f.severity == Severity.LOW]
        assert len(long) == 0


# ---------------------------------------------------------------------------
# Network: CORS
# ---------------------------------------------------------------------------


class TestNetworkCORS:
    def setup_method(self):
        self.v = MCPTransportValidator()

    def test_missing_origin(self):
        profile = self.v.validate_network(
            NetworkConfig(url="https://api.example.com/mcp"),
            server_name="test",
        )
        assert _has_category(profile, "cors")

    def test_origin_present(self):
        profile = self.v.validate_network(
            NetworkConfig(
                url="https://api.example.com/mcp",
                headers={"Origin": "https://myapp.com", "Authorization": "Bearer x"},
            ),
            server_name="test",
        )
        cors = [f for f in profile.findings if f.category == "cors"]
        assert len(cors) == 0


# ---------------------------------------------------------------------------
# Network: IP Address URL
# ---------------------------------------------------------------------------


class TestNetworkIPAddress:
    def setup_method(self):
        self.v = MCPTransportValidator()

    def test_raw_ip(self):
        profile = self.v.validate_network(
            NetworkConfig(url="https://192.168.1.100:8080/mcp"),
            server_name="test",
        )
        assert _has_category(profile, "tls")
        assert _has_severity(profile, Severity.MEDIUM)

    def test_localhost_ip_not_double_flagged(self):
        """127.0.0.1 should be flagged as localhost, not as raw IP."""
        profile = self.v.validate_network(
            NetworkConfig(url="https://127.0.0.1:3000/mcp"),
            server_name="test",
        )
        ip_findings = [f for f in profile.findings if f.category == "tls" and "Raw IP" in f.detail]
        assert len(ip_findings) == 0

    def test_hostname_is_fine(self):
        profile = self.v.validate_network(
            NetworkConfig(
                url="https://api.example.com/mcp",
                headers={"Authorization": "Bearer x"},
            ),
            server_name="test",
        )
        ip_findings = [f for f in profile.findings if f.category == "tls" and "Raw IP" in f.detail]
        assert len(ip_findings) == 0


# ---------------------------------------------------------------------------
# Network: Default Port
# ---------------------------------------------------------------------------


class TestNetworkDefaultPort:
    def setup_method(self):
        self.v = MCPTransportValidator()

    def test_port_8080(self):
        profile = self.v.validate_network(
            NetworkConfig(url="https://api.example.com:8080/mcp"),
            server_name="test",
        )
        port_findings = [f for f in profile.findings if "port" in f.detail.lower()]
        assert len(port_findings) >= 1

    def test_non_standard_port(self):
        profile = self.v.validate_network(
            NetworkConfig(url="https://api.example.com:9999/mcp"),
            server_name="test",
        )
        port_findings = [
            f for f in profile.findings
            if f.category == "insecure_transport" and "port" in f.detail.lower()
        ]
        assert len(port_findings) == 0


# ---------------------------------------------------------------------------
# Network: Credential in URL
# ---------------------------------------------------------------------------


class TestNetworkCredentialInURL:
    def setup_method(self):
        self.v = MCPTransportValidator()

    def test_cred_in_url(self):
        profile = self.v.validate_network(
            NetworkConfig(url="https://admin:password@api.example.com/mcp"),
            server_name="test",
        )
        assert _has_severity(profile, Severity.CRITICAL)
        cred = [f for f in profile.findings if "Credentials embedded" in f.detail]
        assert len(cred) >= 1

    def test_no_cred_in_url(self):
        profile = self.v.validate_network(
            NetworkConfig(url="https://api.example.com/mcp"),
            server_name="test",
        )
        cred = [f for f in profile.findings if "Credentials embedded" in f.detail]
        assert len(cred) == 0


# ---------------------------------------------------------------------------
# Network: verify_ssl disabled
# ---------------------------------------------------------------------------


class TestNetworkVerifySSL:
    def setup_method(self):
        self.v = MCPTransportValidator()

    def test_ssl_disabled(self):
        profile = self.v.validate_network(
            NetworkConfig(url="https://api.example.com/mcp", verify_ssl=False),
            server_name="test",
        )
        assert _has_category(profile, "tls")
        assert _has_severity(profile, Severity.CRITICAL)
        assert not profile.is_secure

    def test_ssl_enabled(self):
        profile = self.v.validate_network(
            NetworkConfig(
                url="https://api.example.com/mcp",
                verify_ssl=True,
                headers={"Authorization": "Bearer x"},
            ),
            server_name="test",
        )
        tls = [f for f in profile.findings if f.category == "tls"]
        assert len(tls) == 0


# ---------------------------------------------------------------------------
# Claude Desktop Config Validation
# ---------------------------------------------------------------------------


class TestClaudeDesktopConfig:
    def setup_method(self):
        self.v = MCPTransportValidator()

    def test_standard_config(self):
        config = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home"],
                },
                "remote": {
                    "url": "https://api.example.com/mcp",
                    "headers": {"Authorization": "Bearer xxx"},
                },
            }
        }
        profiles = self.v.validate_claude_desktop_config(config)
        assert len(profiles) == 2
        names = {p.server_name for p in profiles}
        assert "filesystem" in names
        assert "remote" in names

    def test_stdio_type(self):
        config = {
            "mcpServers": {
                "fs": {
                    "command": "node",
                    "args": ["server.js"],
                },
            }
        }
        profiles = self.v.validate_claude_desktop_config(config)
        assert len(profiles) == 1
        assert profiles[0].transport_type == "stdio"

    def test_network_type(self):
        config = {
            "mcpServers": {
                "api": {
                    "url": "https://api.example.com/mcp",
                    "headers": {"Authorization": "Bearer token"},
                },
            }
        }
        profiles = self.v.validate_claude_desktop_config(config)
        assert len(profiles) == 1
        assert profiles[0].transport_type == "sse"

    def test_without_mcpservers_wrapper(self):
        """Should accept the servers dict directly."""
        config = {
            "local": {
                "command": "node",
                "args": ["server.js"],
            },
        }
        profiles = self.v.validate_claude_desktop_config(config)
        assert len(profiles) == 1
        assert profiles[0].server_name == "local"

    def test_env_passthrough(self):
        config = {
            "mcpServers": {
                "myserver": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {"API_KEY": "secret"},
                },
            }
        }
        profiles = self.v.validate_claude_desktop_config(config)
        assert len(profiles) == 1
        assert _has_severity(profiles[0], Severity.MEDIUM)

    def test_empty_config(self):
        profiles = self.v.validate_claude_desktop_config({"mcpServers": {}})
        assert profiles == []

    def test_non_dict_server_entry_skipped(self):
        config = {"mcpServers": {"bad": "not_a_dict"}}
        profiles = self.v.validate_claude_desktop_config(config)
        assert profiles == []

    def test_insecure_network_in_desktop_config(self):
        config = {
            "mcpServers": {
                "bad_server": {
                    "url": "http://api.example.com/mcp",
                },
            }
        }
        profiles = self.v.validate_claude_desktop_config(config)
        assert len(profiles) == 1
        assert not profiles[0].is_secure
        assert _has_severity(profiles[0], Severity.CRITICAL)


# ---------------------------------------------------------------------------
# Mixed Configs: validate_all
# ---------------------------------------------------------------------------


class TestValidateAll:
    def setup_method(self):
        self.v = MCPTransportValidator()

    def test_mixed_servers(self):
        servers = [
            StdioConfig(command="node", args=["server.js"]),
            NetworkConfig(
                url="https://api.example.com/mcp",
                headers={"Authorization": "Bearer token"},
            ),
        ]
        profiles = self.v.validate_all(servers, names=["local", "remote"])
        assert len(profiles) == 2
        assert profiles[0].transport_type == "stdio"
        assert profiles[0].server_name == "local"
        assert profiles[1].transport_type == "sse"
        assert profiles[1].server_name == "remote"

    def test_no_names(self):
        servers = [StdioConfig(command="node")]
        profiles = self.v.validate_all(servers)
        assert len(profiles) == 1
        assert profiles[0].server_name == ""

    def test_empty_list(self):
        profiles = self.v.validate_all([])
        assert profiles == []

    def test_partial_names(self):
        servers = [
            StdioConfig(command="node"),
            StdioConfig(command="python"),
        ]
        profiles = self.v.validate_all(servers, names=["first"])
        assert profiles[0].server_name == "first"
        assert profiles[1].server_name == ""


# ---------------------------------------------------------------------------
# Risk Score Calculation
# ---------------------------------------------------------------------------


class TestRiskScore:
    def setup_method(self):
        self.v = MCPTransportValidator()

    def test_clean_stdio_low_risk(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="node", args=["server.js"]),
            server_name="test",
        )
        assert profile.risk_score == 0

    def test_critical_finding_high_risk(self):
        profile = self.v.validate_network(
            NetworkConfig(url="http://api.example.com/mcp", verify_ssl=False),
            server_name="test",
        )
        # HTTP without TLS (CRITICAL=30) + verify_ssl (CRITICAL=30) + missing auth (HIGH=20) + cors (MEDIUM=10) = capped at 100
        assert profile.risk_score > 0
        assert _has_severity(profile, Severity.CRITICAL)

    def test_risk_score_capped_at_100(self):
        """Even many findings should not exceed 100."""
        profile = self.v.validate_network(
            NetworkConfig(url="http://admin:pass@10.0.0.1:8080/mcp", verify_ssl=False),
            server_name="test",
        )
        assert profile.risk_score <= 100

    def test_moderate_risk(self):
        """A config with only MEDIUM findings should have moderate risk."""
        profile = self.v.validate_network(
            NetworkConfig(
                url="https://api.example.com/mcp",
                headers={"Authorization": "Bearer token"},
                timeout_seconds=2.0,
            ),
            server_name="test",
        )
        assert 0 < profile.risk_score < 50


# ---------------------------------------------------------------------------
# is_secure determination
# ---------------------------------------------------------------------------


class TestIsSecure:
    def setup_method(self):
        self.v = MCPTransportValidator()

    def test_clean_stdio_is_secure(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="node", args=["server.js"]),
            server_name="test",
        )
        assert profile.is_secure is True

    def test_critical_finding_not_secure(self):
        profile = self.v.validate_network(
            NetworkConfig(url="http://api.example.com/mcp"),
            server_name="test",
        )
        assert profile.is_secure is False

    def test_high_finding_not_secure(self):
        profile = self.v.validate_network(
            NetworkConfig(url="https://api.example.com/mcp"),  # missing auth = HIGH
            server_name="test",
        )
        assert profile.is_secure is False

    def test_medium_only_is_secure(self):
        """Only MEDIUM findings should still count as secure."""
        profile = self.v.validate_network(
            NetworkConfig(
                url="https://api.example.com/mcp",
                headers={"Authorization": "Bearer token"},
                timeout_seconds=2.0,
            ),
            server_name="test",
        )
        # Missing CORS (MEDIUM) + short timeout (MEDIUM) => still secure
        has_high_or_crit = any(
            f.severity in (Severity.CRITICAL, Severity.HIGH) for f in profile.findings
        )
        assert not has_high_or_crit
        assert profile.is_secure is True


# ---------------------------------------------------------------------------
# TransportProfile / TransportFinding frozen
# ---------------------------------------------------------------------------


class TestDataclassFrozen:
    def test_transport_finding_frozen(self):
        f = TransportFinding(
            category="test",
            severity=Severity.LOW,
            detail="detail",
            recommendation="rec",
        )
        try:
            f.category = "changed"  # type: ignore[misc]
            assert False, "Should raise"
        except AttributeError:
            pass

    def test_transport_profile_frozen(self):
        p = TransportProfile(
            transport_type="stdio",
            server_name="test",
            findings=[],
            is_secure=True,
            risk_score=0,
        )
        try:
            p.is_secure = False  # type: ignore[misc]
            assert False, "Should raise"
        except AttributeError:
            pass


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def setup_method(self):
        self.v = MCPTransportValidator()

    def test_empty_command(self):
        profile = self.v.validate_stdio(
            StdioConfig(command=""),
            server_name="empty",
        )
        # Should not crash
        assert profile.transport_type == "stdio"

    def test_empty_url(self):
        profile = self.v.validate_network(
            NetworkConfig(url=""),
            server_name="empty",
        )
        # Should not crash
        assert profile.transport_type == "sse"

    def test_unusual_scheme(self):
        profile = self.v.validate_network(
            NetworkConfig(url="ftp://files.example.com/mcp"),
            server_name="test",
        )
        # No HTTP without TLS finding since scheme is not 'http'
        http_findings = [f for f in profile.findings if "HTTP without TLS" in f.detail]
        assert len(http_findings) == 0

    def test_server_name_propagation(self):
        profile = self.v.validate_stdio(
            StdioConfig(command="node"),
            server_name="my-server",
        )
        assert profile.server_name == "my-server"

    def test_transport_type_http(self):
        profile = self.v.validate_network(
            NetworkConfig(url="https://api.example.com/mcp"),
            server_name="test",
            transport_type="http",
        )
        assert profile.transport_type == "http"

    def test_multiple_sensitive_env_vars(self):
        """Each sensitive env var should produce its own finding."""
        profile = self.v.validate_stdio(
            StdioConfig(
                command="node",
                args=[],
                env={"API_KEY": "k1", "DB_PASSWORD": "p1", "MY_SECRET": "s1"},
            ),
            server_name="test",
        )
        sensitive = [f for f in profile.findings if f.category == "missing_auth"]
        assert len(sensitive) == 3

    def test_desktop_config_with_verify_ssl_and_timeout(self):
        config = {
            "mcpServers": {
                "custom": {
                    "url": "https://api.example.com/mcp",
                    "headers": {"Authorization": "Bearer token"},
                    "timeout_seconds": 2.0,
                    "verify_ssl": False,
                },
            }
        }
        profiles = self.v.validate_claude_desktop_config(config)
        assert len(profiles) == 1
        assert _has_category(profiles[0], "tls")
        assert _has_category(profiles[0], "timeout")
