"""Aegis MCP Server — policy-based governance for AI agent tool calls.

Runs as a standalone MCP server (stdio transport) that exposes Aegis
governance capabilities as MCP tools. Any MCP client can connect to
evaluate actions against YAML policies, check audit logs, and manage
policy rules at runtime.

Install & run::

    pip install 'agent-aegis[mcp]'
    aegis-mcp-server                           # default (empty policy)
    aegis-mcp-server --policy policy.yaml      # with policy file
    AEGIS_POLICY_PATH=policy.yaml aegis-mcp-server  # via env var

Or with uvx::

    uvx --from 'agent-aegis[mcp]' aegis-mcp-server
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

from aegis.core.action import Action
from aegis.core.policy import Policy


def _load_policy(policy_path: str | None = None) -> Policy:
    """Load policy from path or env var, falling back to empty policy."""
    path = policy_path or os.environ.get("AEGIS_POLICY_PATH")
    if path and Path(path).exists():
        return Policy.from_yaml(path)
    return Policy(rules=[])


# Module-level state, initialized in main()
_policy: Policy = Policy(rules=[])


def _create_server() -> Any:
    """Create and configure the MCP server with Aegis tools."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print(
            "Error: mcp package required. Install with: pip install 'agent-aegis[mcp]'",
            file=sys.stderr,
        )
        sys.exit(1)

    mcp = FastMCP(
        "aegis",
        instructions=(
            "Aegis governance server. Use evaluate_action to check if an AI agent "
            "action is allowed by the current YAML policy. Use get_policy to inspect "
            "rules. Use update_policy to hot-reload policy YAML."
        ),
    )

    @mcp.tool()
    def evaluate_action(
        action_type: str,
        target: str,
        params: dict[str, Any] | None = None,
        description: str = "",
        agent_id: str = "",
    ) -> dict[str, Any]:
        """Evaluate an AI agent action against the current governance policy.

        Returns a decision: auto (allow), approve (needs human review), or block (deny).

        Args:
            action_type: The kind of operation (e.g. "read_file", "send_email", "delete").
            target: The system being acted upon (e.g. "filesystem", "stripe", "database").
            params: Arbitrary parameters for the operation.
            description: Optional human-readable description.
            agent_id: Optional identifier for the agent performing the action.
        """
        action = Action(
            type=action_type,
            target=target,
            params=params or {},
            description=description,
            agent_id=agent_id,
        )
        decision = _policy.evaluate(action)
        return {
            "action_type": decision.action.type,
            "target": decision.action.target,
            "risk_level": decision.risk_level.value,
            "approval": decision.approval.value,
            "matched_rule": decision.matched_rule,
            "is_allowed": decision.is_allowed,
        }

    @mcp.tool()
    def evaluate_batch(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Evaluate multiple actions at once against the governance policy.

        Each action dict should have: action_type, target,
        and optionally params, description, agent_id.

        Args:
            actions: List of action dicts to evaluate.
        """
        results = []
        for a in actions:
            action = Action(
                type=a.get("action_type", ""),
                target=a.get("target", ""),
                params=a.get("params", {}),
                description=a.get("description", ""),
                agent_id=a.get("agent_id", ""),
            )
            decision = _policy.evaluate(action)
            results.append({
                "action_type": decision.action.type,
                "target": decision.action.target,
                "risk_level": decision.risk_level.value,
                "approval": decision.approval.value,
                "matched_rule": decision.matched_rule,
                "is_allowed": decision.is_allowed,
            })
        return results

    @mcp.tool()
    def get_policy() -> dict[str, Any]:
        """Get the current governance policy rules.

        Returns all configured rules with their action patterns, targets,
        risk levels, and approval requirements.
        """
        rules = []
        for rule in _policy.rules:
            rules.append({
                "name": rule.name,
                "match_type": rule.match_type,
                "match_target": rule.match_target,
                "risk_level": rule.risk_level.value,
                "approval": rule.approval.value,
                "conditions": rule.conditions,
            })
        return {
            "rule_count": len(rules),
            "rules": rules,
            "default_risk": _policy.default_risk_level.value,
            "default_approval": _policy.default_approval.value,
        }

    @mcp.tool()
    def update_policy(yaml_content: str) -> dict[str, Any]:
        """Hot-reload the governance policy from a YAML string.

        The new policy takes effect immediately for all subsequent evaluations.

        Args:
            yaml_content: YAML string containing the policy rules.
        """
        global _policy
        try:
            import yaml

            data = yaml.safe_load(yaml_content)
            _policy = Policy.from_dict(data)
            return {
                "success": True,
                "rule_count": len(_policy.rules),
                "message": f"Policy updated: {len(_policy.rules)} rules loaded.",
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "Failed to parse policy YAML.",
            }

    @mcp.tool()
    def check_risk(action_type: str, target: str) -> dict[str, str | int]:
        """Quick risk check for an action type + target combination.

        Returns just the risk level and approval requirement — lighter than evaluate_action.

        Args:
            action_type: The kind of operation.
            target: The system being acted upon.
        """
        action = Action(type=action_type, target=target)
        decision = _policy.evaluate(action)
        return {
            "risk_level": decision.risk_level.value,
            "approval": decision.approval.value,
        }

    return mcp


def main(argv: list[str] | None = None) -> None:
    """Entry point for the Aegis MCP server."""
    global _policy

    parser = argparse.ArgumentParser(
        prog="aegis-mcp-server",
        description="Aegis MCP server — policy-based governance for AI agent tool calls.",
    )
    parser.add_argument(
        "--policy",
        type=str,
        default=None,
        help="Path to YAML policy file (or set AEGIS_POLICY_PATH env var).",
    )
    args = parser.parse_args(argv)

    _policy = _load_policy(args.policy)

    rule_count = len(_policy.rules)
    print(f"Aegis MCP server starting with {rule_count} policy rules.", file=sys.stderr)

    server = _create_server()
    server.run()


if __name__ == "__main__":
    main()
