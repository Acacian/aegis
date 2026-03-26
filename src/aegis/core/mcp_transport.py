"""MCP transport security validator.

Static analysis of MCP server transport configurations to detect
insecure setups before any connections are made. Validates stdio,
SSE, and Streamable HTTP transports.

Components:
    - MCPTransportValidator: Main validator class
    - TransportFinding: Individual security finding
    - TransportProfile: Complete security profile for a transport
    - StdioConfig: Stdio transport configuration
    - NetworkConfig: SSE/HTTP transport configuration

Example::

    validator = MCPTransportValidator()
    profile = validator.validate_stdio(
        StdioConfig(
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem", "/home"],
        ),
        server_name="filesystem",
    )
    assert profile.is_secure
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from aegis.core.mcp_security import Severity

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TransportFinding:
    """A finding from transport security validation."""

    # "command_injection", "insecure_transport", "missing_auth",
    # "timeout", "cors", "tls"
    category: str
    severity: str  # Severity.CRITICAL / HIGH / MEDIUM / LOW
    detail: str
    recommendation: str


@dataclass(frozen=True)
class TransportProfile:
    """Security profile for a transport configuration."""

    transport_type: str  # "stdio", "sse", "http"
    server_name: str
    findings: list[TransportFinding]
    is_secure: bool  # True if no HIGH or CRITICAL findings
    risk_score: int  # 0-100 (0 = secure, 100 = very risky)


@dataclass(frozen=True)
class StdioConfig:
    """Configuration for a stdio MCP server."""

    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] | None = None


@dataclass(frozen=True)
class NetworkConfig:
    """Configuration for SSE/HTTP MCP server."""

    url: str
    headers: dict[str, str] | None = None
    timeout_seconds: float = 30.0
    verify_ssl: bool = True


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# Shell metacharacters that indicate command injection risk
_SHELL_META = re.compile(r"[;|`]|\$\(|\$\{|&&|\|\|")

# Dangerous shell wrapper commands
_DANGEROUS_COMMANDS = {"sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "eval", "exec"}

# Path traversal in arguments
_PATH_TRAVERSAL = re.compile(r"\.\./|\.\.\\")

# Sensitive environment variable name patterns
_SENSITIVE_ENV = re.compile(
    r"(?:API_KEY|SECRET|PASSWORD|TOKEN|CREDENTIAL|PRIVATE_KEY|AUTH)",
    re.IGNORECASE,
)

# npx without version pinning: "npx -y @scope/pkg" but NOT "npx -y @scope/pkg@version"
# Matches package names that do NOT end with @<version>
_NPX_UNPINNED = re.compile(r"^(?:@[\w./-]+/)?[\w./-]+$")

# World-writable directories
_WORLD_WRITABLE_DIRS = ("/tmp", "/var/tmp", "/dev/shm")

# Credentials embedded in URL
_URL_CREDENTIALS = re.compile(r"://[^/@]+:[^/@]+@")

# Well-known ports that might conflict
_DEFAULT_PORTS = {80, 443, 8080, 8443, 3000, 5000}

# ---------------------------------------------------------------------------
# Risk score calculation
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHTS: dict[str, int] = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
}


def _compute_risk_score(findings: list[TransportFinding]) -> int:
    """Compute a 0-100 risk score from findings. 0 = secure, 100 = very risky."""
    score = 0
    for f in findings:
        score += _SEVERITY_WEIGHTS.get(f.severity, 0)
    return min(100, score)


def _is_secure(findings: list[TransportFinding]) -> bool:
    """True if no HIGH or CRITICAL findings."""
    return not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)


# ---------------------------------------------------------------------------
# MCPTransportValidator
# ---------------------------------------------------------------------------


class MCPTransportValidator:
    """Validates transport-level security for MCP server connections.

    Pure static analysis of configuration data. No network calls,
    no file system probing. Sub-millisecond per config.
    """

    def validate_stdio(
        self,
        config: StdioConfig,
        *,
        server_name: str = "",
    ) -> TransportProfile:
        """Validate a stdio transport configuration.

        Checks for command injection, dangerous commands, path traversal
        in args, sensitive env vars, unpinned npx packages, and
        world-writable command paths.
        """
        findings: list[TransportFinding] = []

        self._check_command_injection(config, findings)
        self._check_dangerous_commands(config, findings)
        self._check_path_traversal_in_args(config, findings)
        self._check_sensitive_env(config, findings)
        self._check_unpinned_packages(config, findings)
        self._check_world_writable_command(config, findings)

        return TransportProfile(
            transport_type="stdio",
            server_name=server_name,
            findings=findings,
            is_secure=_is_secure(findings),
            risk_score=_compute_risk_score(findings),
        )

    def validate_network(
        self,
        config: NetworkConfig,
        *,
        server_name: str = "",
        transport_type: str = "sse",
    ) -> TransportProfile:
        """Validate an SSE or HTTP transport configuration.

        Checks for insecure transport (no TLS), missing auth,
        localhost binding, timeout issues, CORS, IP-based URLs,
        default ports, credentials in URL, and disabled SSL verification.
        """
        findings: list[TransportFinding] = []

        self._check_http_without_tls(config, findings)
        self._check_missing_auth(config, findings)
        self._check_localhost(config, findings)
        self._check_timeout(config, findings)
        self._check_cors(config, findings)
        self._check_ip_address_url(config, findings)
        self._check_default_port(config, findings)
        self._check_credential_in_url(config, findings)
        self._check_verify_ssl(config, findings)

        return TransportProfile(
            transport_type=transport_type,
            server_name=server_name,
            findings=findings,
            is_secure=_is_secure(findings),
            risk_score=_compute_risk_score(findings),
        )

    def validate_claude_desktop_config(
        self,
        config: dict[str, Any],
    ) -> list[TransportProfile]:
        """Validate a Claude Desktop mcpServers configuration block.

        Parses the JSON config format and validates each server.
        Supports both stdio (command/args) and network (url) configs.

        Args:
            config: A dict with an ``mcpServers`` key, or the servers
                    dict directly.
        """
        servers = config.get("mcpServers", config)
        profiles: list[TransportProfile] = []

        for name, server_config in servers.items():
            if not isinstance(server_config, dict):
                continue

            if "command" in server_config:
                # Stdio transport
                stdio = StdioConfig(
                    command=server_config["command"],
                    args=server_config.get("args", []),
                    env=server_config.get("env"),
                )
                profiles.append(self.validate_stdio(stdio, server_name=name))
            elif "url" in server_config:
                # Network transport (SSE or HTTP)
                net = NetworkConfig(
                    url=server_config["url"],
                    headers=server_config.get("headers"),
                    timeout_seconds=server_config.get("timeout_seconds", 30.0),
                    verify_ssl=server_config.get("verify_ssl", True),
                )
                profiles.append(self.validate_network(net, server_name=name, transport_type="sse"))

        return profiles

    def validate_all(
        self,
        servers: list[StdioConfig | NetworkConfig],
        *,
        names: list[str] | None = None,
    ) -> list[TransportProfile]:
        """Validate multiple server configurations.

        Args:
            servers: List of StdioConfig or NetworkConfig objects.
            names: Optional list of server names (same length as servers).
        """
        profiles: list[TransportProfile] = []
        for i, server in enumerate(servers):
            name = names[i] if names and i < len(names) else ""
            if isinstance(server, StdioConfig):
                profiles.append(self.validate_stdio(server, server_name=name))
            elif isinstance(server, NetworkConfig):
                profiles.append(self.validate_network(server, server_name=name))
        return profiles

    # ------------------------------------------------------------------
    # Stdio checks
    # ------------------------------------------------------------------

    def _check_command_injection(
        self,
        config: StdioConfig,
        findings: list[TransportFinding],
    ) -> None:
        """Check for shell metacharacters in command or args."""
        targets = [config.command] + list(config.args)
        for target in targets:
            if _SHELL_META.search(target):
                findings.append(
                    TransportFinding(
                        category="command_injection",
                        severity=Severity.CRITICAL,
                        detail=f"Shell metacharacter detected in: {target!r}",
                        recommendation=(
                            "Remove shell metacharacters."
                            " Use separate args instead of shell expansion."
                        ),
                    )
                )
                return  # One finding is enough

    def _check_dangerous_commands(
        self,
        config: StdioConfig,
        findings: list[TransportFinding],
    ) -> None:
        """Check if the command uses a dangerous shell wrapper."""
        cmd_base = config.command.rsplit("/", 1)[-1]
        if cmd_base in _DANGEROUS_COMMANDS:
            # Check if it's being used with -c (shell string execution)
            has_c_flag = "-c" in config.args
            if has_c_flag or cmd_base in ("eval", "exec"):
                findings.append(
                    TransportFinding(
                        category="command_injection",
                        severity=Severity.HIGH,
                        detail=f"Dangerous command '{config.command}' with shell execution",
                        recommendation=(
                            "Run the target program directly instead of through a shell wrapper."
                        ),
                    )
                )

    def _check_path_traversal_in_args(
        self,
        config: StdioConfig,
        findings: list[TransportFinding],
    ) -> None:
        """Check for path traversal patterns in arguments."""
        for arg in config.args:
            if _PATH_TRAVERSAL.search(arg):
                findings.append(
                    TransportFinding(
                        category="command_injection",
                        severity=Severity.HIGH,
                        detail=f"Path traversal pattern in argument: {arg!r}",
                        recommendation="Use absolute paths instead of relative path traversal.",
                    )
                )
                return  # One finding is enough

    def _check_sensitive_env(
        self,
        config: StdioConfig,
        findings: list[TransportFinding],
    ) -> None:
        """Check for sensitive values exposed in environment variables."""
        if not config.env:
            return
        for key in config.env:
            if _SENSITIVE_ENV.search(key):
                findings.append(
                    TransportFinding(
                        category="missing_auth",
                        severity=Severity.MEDIUM,
                        detail=f"Sensitive environment variable exposed: {key!r}",
                        recommendation=(
                            "Use a secrets manager or .env file instead of inline credentials."
                        ),
                    )
                )

    def _check_unpinned_packages(
        self,
        config: StdioConfig,
        findings: list[TransportFinding],
    ) -> None:
        """Check for npx -y without version pinning."""
        cmd_base = config.command.rsplit("/", 1)[-1]
        if cmd_base != "npx":
            return

        has_y_flag = "-y" in config.args or "--yes" in config.args
        if not has_y_flag:
            return

        # Find package arguments (not flags)
        for arg in config.args:
            if arg.startswith("-"):
                continue
            # Check if it looks like a package name without a version pin
            if _NPX_UNPINNED.match(arg) and "@" not in arg.rpartition("/")[-1]:
                # It's a package name without @version
                findings.append(
                    TransportFinding(
                        category="command_injection",
                        severity=Severity.MEDIUM,
                        detail=f"Unpinned npx package: {arg!r}",
                        recommendation="Pin the package version: e.g., @scope/pkg@1.2.3",
                    )
                )

    def _check_world_writable_command(
        self,
        config: StdioConfig,
        findings: list[TransportFinding],
    ) -> None:
        """Check if the command path is in a world-writable directory."""
        for dir_path in _WORLD_WRITABLE_DIRS:
            if config.command.startswith(dir_path + "/"):
                findings.append(
                    TransportFinding(
                        category="command_injection",
                        severity=Severity.LOW,
                        detail=f"Command in world-writable directory: {config.command!r}",
                        recommendation="Move the command to a non-world-writable location.",
                    )
                )
                return

    # ------------------------------------------------------------------
    # Network checks
    # ------------------------------------------------------------------

    def _check_http_without_tls(
        self,
        config: NetworkConfig,
        findings: list[TransportFinding],
    ) -> None:
        """Check for HTTP without TLS."""
        parsed = urlparse(config.url)
        if parsed.scheme == "http":
            findings.append(
                TransportFinding(
                    category="insecure_transport",
                    severity=Severity.CRITICAL,
                    detail=f"HTTP without TLS: {config.url}",
                    recommendation="Use https:// for production MCP servers.",
                )
            )

    def _check_missing_auth(
        self,
        config: NetworkConfig,
        findings: list[TransportFinding],
    ) -> None:
        """Check for missing Authorization header."""
        headers = config.headers or {}
        has_auth = any(k.lower() in ("authorization", "x-api-key") for k in headers)
        if not has_auth:
            findings.append(
                TransportFinding(
                    category="missing_auth",
                    severity=Severity.HIGH,
                    detail="No Authorization or X-API-Key header configured",
                    recommendation="Add an Authorization header with a bearer token or API key.",
                )
            )

    def _check_localhost(
        self,
        config: NetworkConfig,
        findings: list[TransportFinding],
    ) -> None:
        """Check for localhost binding."""
        parsed = urlparse(config.url)
        hostname = parsed.hostname or ""
        if hostname in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
            findings.append(
                TransportFinding(
                    category="insecure_transport",
                    severity=Severity.LOW,
                    detail=f"Localhost binding: {hostname}",
                    recommendation=(
                        "Acceptable for development. Use a proper hostname for production."
                    ),
                )
            )

    def _check_timeout(
        self,
        config: NetworkConfig,
        findings: list[TransportFinding],
    ) -> None:
        """Check for timeout issues."""
        if config.timeout_seconds < 5.0:
            findings.append(
                TransportFinding(
                    category="timeout",
                    severity=Severity.MEDIUM,
                    detail=f"Short timeout: {config.timeout_seconds}s (< 5s)",
                    recommendation="Use at least 5 seconds to avoid premature disconnections.",
                )
            )
        elif config.timeout_seconds > 120.0:
            findings.append(
                TransportFinding(
                    category="timeout",
                    severity=Severity.LOW,
                    detail=f"Long timeout: {config.timeout_seconds}s (> 120s)",
                    recommendation=(
                        "Consider reducing timeout to avoid holding resources too long."
                    ),
                )
            )

    def _check_cors(
        self,
        config: NetworkConfig,
        findings: list[TransportFinding],
    ) -> None:
        """Check for missing CORS origin header."""
        headers = config.headers or {}
        has_origin = any(k.lower() == "origin" for k in headers)
        if not has_origin:
            findings.append(
                TransportFinding(
                    category="cors",
                    severity=Severity.MEDIUM,
                    detail="No Origin header configured for browser-based clients",
                    recommendation=(
                        "Set an Origin header if this server is accessed from a browser."
                    ),
                )
            )

    def _check_ip_address_url(
        self,
        config: NetworkConfig,
        findings: list[TransportFinding],
    ) -> None:
        """Check for raw IP address in URL instead of hostname."""
        parsed = urlparse(config.url)
        hostname = parsed.hostname or ""
        # Skip localhost IPs (already covered)
        if hostname in ("127.0.0.1", "::1", "0.0.0.0"):
            return
        # Check if hostname looks like an IP address
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
            findings.append(
                TransportFinding(
                    category="tls",
                    severity=Severity.MEDIUM,
                    detail=f"Raw IP address in URL: {hostname}",
                    recommendation=(
                        "Use a hostname instead of an IP for proper TLS certificate validation."
                    ),
                )
            )

    def _check_default_port(
        self,
        config: NetworkConfig,
        findings: list[TransportFinding],
    ) -> None:
        """Check for well-known ports that might conflict."""
        parsed = urlparse(config.url)
        port = parsed.port
        if port and port in _DEFAULT_PORTS:
            findings.append(
                TransportFinding(
                    category="insecure_transport",
                    severity=Severity.LOW,
                    detail=f"Well-known port {port} may conflict with other services",
                    recommendation="Use a non-standard port to avoid conflicts.",
                )
            )

    def _check_credential_in_url(
        self,
        config: NetworkConfig,
        findings: list[TransportFinding],
    ) -> None:
        """Check for credentials embedded in URL."""
        if _URL_CREDENTIALS.search(config.url):
            findings.append(
                TransportFinding(
                    category="insecure_transport",
                    severity=Severity.CRITICAL,
                    detail="Credentials embedded in URL (user:pass@host)",
                    recommendation="Move credentials to the Authorization header.",
                )
            )

    def _check_verify_ssl(
        self,
        config: NetworkConfig,
        findings: list[TransportFinding],
    ) -> None:
        """Check if TLS verification is disabled."""
        if not config.verify_ssl:
            findings.append(
                TransportFinding(
                    category="tls",
                    severity=Severity.CRITICAL,
                    detail="TLS certificate verification is disabled (verify_ssl=False)",
                    recommendation="Enable TLS verification to prevent man-in-the-middle attacks.",
                )
            )
