"""Approval gate for human-in-the-loop decisions."""

from __future__ import annotations

from abc import ABC, abstractmethod

from aegis.core.policy import PolicyDecision


class ApprovalHandler(ABC):
    """Base class for approval handlers."""

    @abstractmethod
    async def request_approval(self, decision: PolicyDecision) -> bool:
        """Request human approval for an action.

        Returns:
            True if the action is approved, False if denied.
        """
        ...


class CLIApprovalHandler(ApprovalHandler):
    """Interactive CLI-based approval handler that prompts for y/n."""

    async def request_approval(self, decision: PolicyDecision) -> bool:
        action = decision.action
        print(f"\n{'=' * 60}")
        print("  APPROVAL REQUIRED")
        print(f"{'=' * 60}")
        print(f"  Action:  {action.type}")
        print(f"  Target:  {action.target}")
        print(f"  Risk:    {decision.risk_level.name}")
        print(f"  Rule:    {decision.matched_rule}")
        if action.params:
            print(f"  Params:  {action.params}")
        if action.description:
            print(f"  Desc:    {action.description}")
        print(f"{'=' * 60}")

        while True:
            try:
                response = input("  Approve? [y/n]: ").strip().lower()
            except EOFError:
                # No one is there to answer — running under CI, a service
                # manager, or a closed pipe.  Deny rather than propagate:
                # an unanswerable approval prompt is a denied approval.
                print("  No input available — denying (fail-closed).")
                return False
            if response in ("y", "yes"):
                return True
            if response in ("n", "no"):
                return False
            print("  Please enter 'y' or 'n'.")


class AutoApprovalHandler(ApprovalHandler):
    """Automatically approves every action. For testing only."""

    async def request_approval(self, decision: PolicyDecision) -> bool:
        return True
