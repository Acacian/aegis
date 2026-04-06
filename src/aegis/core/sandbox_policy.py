"""Policy-based command and action interception for safe execution.

Addresses risks identified in "Fault-Tolerant Sandboxing for AI Coding
Agents" -- AI agents that execute shell commands or file-system
operations need a policy layer that blocks destructive commands, gates
risky ones behind human approval, and transparently logs the rest.

Rules are matched by regular expression against command strings or file
paths.  Each rule produces a :class:`SandboxDecision` indicating
whether the action is allowed, denied, or requires user confirmation.
A workspace boundary restricts file-system access to a designated
directory tree.

Built-in rules cover ~30 dangerous shell patterns (fork bombs,
pipe-to-shell, disk wipers, privilege escalation) and file-system
categories (network access, package installs, writes outside workspace).

Pure Python, no external dependencies.  Thread-safe, sub-millisecond.

Reference:
    Fault-Tolerant Sandboxing for AI Coding Agents.
    arXiv:2512.12806 (2025).

Example::

    policy = SandboxPolicy()
    decision = policy.check_command("rm -rf /")
    assert not decision.allowed
    assert decision.action == SandboxAction.DENY
"""

from __future__ import annotations

import os
import re
import threading
import time
from dataclasses import dataclass
from enum import StrEnum

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class SandboxAction(StrEnum):
    """Action to take when a sandbox rule matches."""

    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"
    LOG_ONLY = "log_only"


class RiskLevel(StrEnum):
    """Risk level of a sandbox decision."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Frozen data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SandboxRule:
    """Immutable rule for command/action interception.

    Attributes:
        rule_id: Unique identifier for this rule.
        pattern: Regex pattern to match against the command or path.
        action: What to do when the pattern matches.
        category: Human-readable category (e.g. ``"destructive"``).
        description: Explanation of why this rule exists.
        risk_level: Risk level associated with this pattern.
    """

    rule_id: str
    pattern: str
    action: SandboxAction
    category: str
    description: str
    risk_level: RiskLevel = RiskLevel.HIGH


@dataclass(frozen=True)
class SandboxDecision:
    """Immutable result of a sandbox check.

    Attributes:
        allowed: Whether the action is permitted.
        rule_matched: The rule that triggered (or ``None``).
        action: The sandbox action applied.
        risk_level: Risk level of the command.
        description: Human-readable explanation.
    """

    allowed: bool
    rule_matched: str | None
    action: SandboxAction
    risk_level: RiskLevel
    description: str


@dataclass(frozen=True)
class SandboxViolation:
    """Immutable record of a sandbox violation.

    Attributes:
        command: The command or path that was checked.
        rule: The rule that was violated.
        timestamp: When the violation occurred (monotonic clock).
        agent_id: Agent that triggered the violation.
    """

    command: str
    rule: str
    timestamp: float
    agent_id: str


@dataclass(frozen=True)
class SandboxReport:
    """Immutable summary of sandbox activity.

    Attributes:
        total_checks: Total number of checks performed.
        allowed: Number of allowed checks.
        denied: Number of denied checks.
        asked: Number of checks that required user confirmation.
        violations: List of recorded violations.
    """

    total_checks: int
    allowed: int
    denied: int
    asked: int
    violations: tuple[SandboxViolation, ...] = ()


# ---------------------------------------------------------------------------
# Compiled rule (internal)
# ---------------------------------------------------------------------------


class _CompiledRule:
    """Internal representation with a pre-compiled regex."""

    __slots__ = ("rule", "regex")

    def __init__(self, rule: SandboxRule) -> None:
        self.rule = rule
        self.regex: re.Pattern[str] = re.compile(rule.pattern, re.IGNORECASE)


# ---------------------------------------------------------------------------
# Built-in rules
# ---------------------------------------------------------------------------

_DENY_RULES: list[SandboxRule] = [
    # Destructive commands
    SandboxRule(
        "deny-rm-rf-root",
        r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/\s*$",
        SandboxAction.DENY,
        "destructive",
        "rm -rf / destroys filesystem",
        RiskLevel.CRITICAL,
    ),
    SandboxRule(
        "deny-rm-rf-root2",
        r"\brm\s+-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*\s+/\s*$",
        SandboxAction.DENY,
        "destructive",
        "rm -fr / destroys filesystem",
        RiskLevel.CRITICAL,
    ),
    SandboxRule(
        "deny-format",
        r"\bformat\s+[A-Za-z]:",
        SandboxAction.DENY,
        "destructive",
        "Format disk command",
        RiskLevel.CRITICAL,
    ),
    SandboxRule(
        "deny-dd-if",
        r"\bdd\s+if=",
        SandboxAction.DENY,
        "destructive",
        "dd can overwrite disks",
        RiskLevel.CRITICAL,
    ),
    SandboxRule(
        "deny-mkfs",
        r"\bmkfs\b",
        SandboxAction.DENY,
        "destructive",
        "mkfs creates filesystem, destroys data",
        RiskLevel.CRITICAL,
    ),
    SandboxRule(
        "deny-shutdown",
        r"\bshutdown\b",
        SandboxAction.DENY,
        "system",
        "System shutdown",
        RiskLevel.CRITICAL,
    ),
    SandboxRule(
        "deny-reboot",
        r"\breboot\b",
        SandboxAction.DENY,
        "system",
        "System reboot",
        RiskLevel.CRITICAL,
    ),
    SandboxRule(
        "deny-fork-bomb",
        r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;",
        SandboxAction.DENY,
        "destructive",
        "Fork bomb pattern",
        RiskLevel.CRITICAL,
    ),
    SandboxRule(
        "deny-fork-bomb2",
        r"\.\s*/dev/null\s*\|",
        SandboxAction.DENY,
        "destructive",
        "Fork-like redirect pattern",
        RiskLevel.CRITICAL,
    ),
    # Pipe to shell
    SandboxRule(
        "deny-curl-pipe-sh",
        r"\bcurl\b[^|]*\|\s*(?:ba)?sh\b",
        SandboxAction.DENY,
        "remote_exec",
        "curl piped to shell executes remote code",
        RiskLevel.CRITICAL,
    ),
    SandboxRule(
        "deny-wget-pipe-sh",
        r"\bwget\b[^|]*\|\s*(?:ba)?sh\b",
        SandboxAction.DENY,
        "remote_exec",
        "wget piped to shell executes remote code",
        RiskLevel.CRITICAL,
    ),
    SandboxRule(
        "deny-curl-pipe-bash",
        r"\bcurl\b[^|]*\|\s*bash\b",
        SandboxAction.DENY,
        "remote_exec",
        "curl piped to bash",
        RiskLevel.CRITICAL,
    ),
    SandboxRule(
        "deny-wget-pipe-bash",
        r"\bwget\b[^|]*\|\s*bash\b",
        SandboxAction.DENY,
        "remote_exec",
        "wget piped to bash",
        RiskLevel.CRITICAL,
    ),
    # Privilege escalation
    SandboxRule(
        "deny-chmod-777",
        r"\bchmod\s+777\b",
        SandboxAction.DENY,
        "privilege",
        "chmod 777 sets world-writable",
        RiskLevel.HIGH,
    ),
    SandboxRule(
        "deny-chown-root",
        r"\bchown\s+root\b",
        SandboxAction.DENY,
        "privilege",
        "chown root changes file owner to root",
        RiskLevel.HIGH,
    ),
    # Data destruction
    SandboxRule(
        "deny-dev-null-redirect",
        r">\s*/dev/sda",
        SandboxAction.DENY,
        "destructive",
        "Overwrite disk device directly",
        RiskLevel.CRITICAL,
    ),
    SandboxRule(
        "deny-truncate-log",
        r"\btruncate\s+.*--size\s+0\s+/var/log",
        SandboxAction.DENY,
        "destructive",
        "Truncate system logs",
        RiskLevel.HIGH,
    ),
]

_ASK_RULES: list[SandboxRule] = [
    # Network access
    SandboxRule(
        "ask-curl",
        r"\bcurl\b",
        SandboxAction.ASK,
        "network",
        "curl network access",
        RiskLevel.MEDIUM,
    ),
    SandboxRule(
        "ask-wget",
        r"\bwget\b",
        SandboxAction.ASK,
        "network",
        "wget network access",
        RiskLevel.MEDIUM,
    ),
    SandboxRule(
        "ask-ssh", r"\bssh\b", SandboxAction.ASK, "network", "SSH remote access", RiskLevel.MEDIUM
    ),
    SandboxRule(
        "ask-scp", r"\bscp\b", SandboxAction.ASK, "network", "SCP file transfer", RiskLevel.MEDIUM
    ),
    SandboxRule(
        "ask-nc",
        r"\b(?:nc|netcat|ncat)\b",
        SandboxAction.ASK,
        "network",
        "Netcat network tool",
        RiskLevel.MEDIUM,
    ),
    # Package install
    SandboxRule(
        "ask-pip-install",
        r"\bpip\s+install\b",
        SandboxAction.ASK,
        "package",
        "pip package install",
        RiskLevel.MEDIUM,
    ),
    SandboxRule(
        "ask-npm-install",
        r"\bnpm\s+install\b",
        SandboxAction.ASK,
        "package",
        "npm package install",
        RiskLevel.MEDIUM,
    ),
    SandboxRule(
        "ask-apt-install",
        r"\bapt(?:-get)?\s+install\b",
        SandboxAction.ASK,
        "package",
        "apt package install",
        RiskLevel.MEDIUM,
    ),
    SandboxRule(
        "ask-brew-install",
        r"\bbrew\s+install\b",
        SandboxAction.ASK,
        "package",
        "Homebrew package install",
        RiskLevel.MEDIUM,
    ),
    # Elevated
    SandboxRule(
        "ask-sudo",
        r"\bsudo\b",
        SandboxAction.ASK,
        "privilege",
        "Elevated privilege command",
        RiskLevel.HIGH,
    ),
    SandboxRule(
        "ask-docker-run",
        r"\bdocker\s+run\b",
        SandboxAction.ASK,
        "container",
        "Docker container execution",
        RiskLevel.MEDIUM,
    ),
]

_ALLOW_RULES: list[SandboxRule] = [
    SandboxRule(
        "allow-ls",
        r"^\s*ls\b",
        SandboxAction.ALLOW,
        "read",
        "List directory contents",
        RiskLevel.NONE,
    ),
    SandboxRule(
        "allow-cat",
        r"^\s*cat\b",
        SandboxAction.ALLOW,
        "read",
        "Display file contents",
        RiskLevel.NONE,
    ),
    SandboxRule(
        "allow-grep",
        r"^\s*grep\b",
        SandboxAction.ALLOW,
        "read",
        "Search file contents",
        RiskLevel.NONE,
    ),
    SandboxRule(
        "allow-head",
        r"^\s*head\b",
        SandboxAction.ALLOW,
        "read",
        "Display first lines",
        RiskLevel.NONE,
    ),
    SandboxRule(
        "allow-tail",
        r"^\s*tail\b",
        SandboxAction.ALLOW,
        "read",
        "Display last lines",
        RiskLevel.NONE,
    ),
    SandboxRule(
        "allow-echo", r"^\s*echo\b", SandboxAction.ALLOW, "read", "Print text", RiskLevel.NONE
    ),
    SandboxRule(
        "allow-pwd",
        r"^\s*pwd\b",
        SandboxAction.ALLOW,
        "read",
        "Print working directory",
        RiskLevel.NONE,
    ),
    SandboxRule(
        "allow-git-status",
        r"^\s*git\s+status\b",
        SandboxAction.ALLOW,
        "read",
        "Git status check",
        RiskLevel.NONE,
    ),
    SandboxRule(
        "allow-git-log",
        r"^\s*git\s+log\b",
        SandboxAction.ALLOW,
        "read",
        "Git log view",
        RiskLevel.NONE,
    ),
    SandboxRule(
        "allow-git-diff",
        r"^\s*git\s+diff\b",
        SandboxAction.ALLOW,
        "read",
        "Git diff view",
        RiskLevel.NONE,
    ),
]


# ---------------------------------------------------------------------------
# SandboxPolicy
# ---------------------------------------------------------------------------


class SandboxPolicy:
    """Policy-based command interception for safe agent execution.

    Rules are evaluated in priority order: DENY rules first, then ASK,
    then ALLOW.  The first matching rule wins.  Commands that match no
    rule receive a default ``LOG_ONLY`` decision.

    Thread-safe: all mutations are guarded by an internal lock.

    Args:
        workspace: Allowed working directory (optional).
        agent_id: Default agent identifier for violation tracking.
    """

    def __init__(
        self,
        *,
        workspace: str | None = None,
        agent_id: str = "default",
    ) -> None:
        self._workspace: str | None = os.path.abspath(workspace) if workspace else None
        self._agent_id = agent_id
        self._lock = threading.Lock()

        # Pre-compile built-in rules
        self._deny: list[_CompiledRule] = [_CompiledRule(r) for r in _DENY_RULES]
        self._ask: list[_CompiledRule] = [_CompiledRule(r) for r in _ASK_RULES]
        self._allow: list[_CompiledRule] = [_CompiledRule(r) for r in _ALLOW_RULES]

        # Stats
        self._total_checks = 0
        self._allowed_count = 0
        self._denied_count = 0
        self._asked_count = 0
        self._violations: list[SandboxViolation] = []

    # -- public API ----------------------------------------------------------

    def check_command(self, command: str) -> SandboxDecision:
        """Check if a shell command is allowed under the current policy.

        Args:
            command: The shell command string to check.

        Returns:
            A :class:`SandboxDecision` with the result.
        """
        if not command or not command.strip():
            return self._record(
                SandboxDecision(
                    allowed=True,
                    rule_matched=None,
                    action=SandboxAction.ALLOW,
                    risk_level=RiskLevel.NONE,
                    description="Empty command",
                )
            )

        stripped = command.strip()

        # Priority: DENY > ASK > ALLOW
        for cr in self._deny:
            if cr.regex.search(stripped):
                decision = SandboxDecision(
                    allowed=False,
                    rule_matched=cr.rule.rule_id,
                    action=SandboxAction.DENY,
                    risk_level=cr.rule.risk_level,
                    description=cr.rule.description,
                )
                self._record_violation(stripped, cr.rule.rule_id)
                return self._record(decision)

        for cr in self._ask:
            if cr.regex.search(stripped):
                decision = SandboxDecision(
                    allowed=False,
                    rule_matched=cr.rule.rule_id,
                    action=SandboxAction.ASK,
                    risk_level=cr.rule.risk_level,
                    description=cr.rule.description,
                )
                return self._record(decision)

        for cr in self._allow:
            if cr.regex.search(stripped):
                decision = SandboxDecision(
                    allowed=True,
                    rule_matched=cr.rule.rule_id,
                    action=SandboxAction.ALLOW,
                    risk_level=cr.rule.risk_level,
                    description=cr.rule.description,
                )
                return self._record(decision)

        # Default: log-only (allowed but logged)
        return self._record(
            SandboxDecision(
                allowed=True,
                rule_matched=None,
                action=SandboxAction.LOG_ONLY,
                risk_level=RiskLevel.LOW,
                description="No matching rule; logged",
            )
        )

    def check_file_access(
        self,
        path: str,
        mode: str = "read",
    ) -> SandboxDecision:
        """Check if file path access is allowed.

        Args:
            path: The file path to check.
            mode: Access mode: ``"read"``, ``"write"``, or ``"delete"``.

        Returns:
            A :class:`SandboxDecision`.
        """
        abs_path = os.path.abspath(path)

        # Read access is always allowed within workspace
        if mode == "read":
            return self._record(
                SandboxDecision(
                    allowed=True,
                    rule_matched=None,
                    action=SandboxAction.ALLOW,
                    risk_level=RiskLevel.NONE,
                    description=f"Read access to {abs_path}",
                )
            )

        # Write/delete outside workspace
        if self._workspace and not abs_path.startswith(self._workspace):
            rule_id = "workspace-boundary"
            desc = (
                f"{mode.title()} access outside workspace: {abs_path} not under {self._workspace}"
            )
            decision = SandboxDecision(
                allowed=False,
                rule_matched=rule_id,
                action=SandboxAction.DENY,
                risk_level=RiskLevel.HIGH,
                description=desc,
            )
            self._record_violation(abs_path, rule_id)
            return self._record(decision)

        # Sensitive system paths (check both POSIX and Windows-resolved paths)
        sensitive = ("/etc/", "/boot/", "/sys/", "/proc/", "/dev/")
        check_path = abs_path.replace("\\", "/")
        for sp in sensitive:
            seg = sp.strip("/")
            if (
                abs_path.startswith(sp)
                or f"/{seg}/" in check_path
                or check_path.endswith(f"/{seg}")
            ):
                rule_id = "sensitive-path"
                decision = SandboxDecision(
                    allowed=False,
                    rule_matched=rule_id,
                    action=SandboxAction.DENY,
                    risk_level=RiskLevel.CRITICAL,
                    description=f"{mode.title()} to sensitive system path: {abs_path}",
                )
                self._record_violation(abs_path, rule_id)
                return self._record(decision)

        # Allowed write/delete inside workspace
        return self._record(
            SandboxDecision(
                allowed=True,
                rule_matched=None,
                action=SandboxAction.ALLOW,
                risk_level=RiskLevel.LOW,
                description=f"{mode.title()} access to {abs_path}",
            )
        )

    def add_rule(self, rule: SandboxRule) -> None:
        """Add a custom sandbox rule.

        The rule is inserted into the appropriate priority list based
        on its action.

        Args:
            rule: The rule to add.
        """
        compiled = _CompiledRule(rule)
        with self._lock:
            if rule.action == SandboxAction.DENY:
                self._deny.append(compiled)
            elif rule.action == SandboxAction.ASK:
                self._ask.append(compiled)
            elif rule.action == SandboxAction.ALLOW:
                self._allow.append(compiled)
            # LOG_ONLY rules go to allow list
            else:
                self._allow.append(compiled)

    def set_workspace(self, workspace: str) -> None:
        """Define the allowed workspace directory.

        Args:
            workspace: Absolute path to the workspace root.
        """
        with self._lock:
            self._workspace = os.path.abspath(workspace)

    def report(self) -> SandboxReport:
        """Return a summary of sandbox activity.

        Returns:
            A frozen :class:`SandboxReport`.
        """
        with self._lock:
            return SandboxReport(
                total_checks=self._total_checks,
                allowed=self._allowed_count,
                denied=self._denied_count,
                asked=self._asked_count,
                violations=tuple(self._violations),
            )

    # -- internal helpers ----------------------------------------------------

    def _record(self, decision: SandboxDecision) -> SandboxDecision:
        """Update stats for a decision."""
        with self._lock:
            self._total_checks += 1
            if decision.action == SandboxAction.DENY:
                self._denied_count += 1
            elif decision.action == SandboxAction.ASK:
                self._asked_count += 1
            else:
                self._allowed_count += 1
        return decision

    def _record_violation(self, command: str, rule_id: str) -> None:
        """Record a violation."""
        violation = SandboxViolation(
            command=command,
            rule=rule_id,
            timestamp=time.monotonic(),
            agent_id=self._agent_id,
        )
        with self._lock:
            self._violations.append(violation)
