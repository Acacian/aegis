"""AGP Level 1 (Basic) conformance tests.

Level 1 requires:
- action.declare / action.evaluate message exchange
- AGEF ``policy_decision`` events producible from decisions
- Fail-safe policy (BLOCK/DENY on destructive actions when no rules match)

Tests exercise the actual Aegis policy engine and data models.
"""

from __future__ import annotations

from aegis.core.action import Action
from aegis.core.policy import Approval, Policy, PolicyDecision, PolicyRule
from aegis.core.risk import RiskLevel

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _basic_policy() -> Policy:
    """Policy with explicit rules and safe defaults."""
    return Policy(
        rules=[
            PolicyRule(
                name="read_auto",
                match_type="read*",
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
            ),
            PolicyRule(
                name="write_approve",
                match_type="write*",
                risk_level=RiskLevel.MEDIUM,
                approval=Approval.APPROVE,
            ),
            PolicyRule(
                name="delete_block",
                match_type="delete*",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
            ),
        ],
        default_risk_level=RiskLevel.MEDIUM,
        default_approval=Approval.APPROVE,
    )


def _failsafe_policy() -> Policy:
    """Policy with no rules -- everything falls to defaults.

    Used to test the fail-safe: destructive actions with no matching
    rule must still produce a decision (not crash).
    """
    return Policy(
        rules=[],
        default_risk_level=RiskLevel.HIGH,
        default_approval=Approval.BLOCK,
    )


# ---------------------------------------------------------------------------
# action.declare / action.evaluate
# ---------------------------------------------------------------------------


class TestActionDeclareEvaluate:
    """The policy engine evaluates any declared action and returns a decision."""

    def test_evaluate_known_action(self) -> None:
        """A read action matches the read_auto rule."""
        policy = _basic_policy()
        action = Action("read", "salesforce")
        decision = policy.evaluate(action)

        assert isinstance(decision, PolicyDecision)
        assert decision.risk_level == RiskLevel.LOW
        assert decision.approval == Approval.AUTO
        assert decision.matched_rule == "read_auto"

    def test_evaluate_write_action(self) -> None:
        """A write action matches the write_approve rule."""
        policy = _basic_policy()
        action = Action("write", "database")
        decision = policy.evaluate(action)

        assert decision.risk_level == RiskLevel.MEDIUM
        assert decision.approval == Approval.APPROVE
        assert decision.matched_rule == "write_approve"

    def test_evaluate_delete_action(self) -> None:
        """A delete action matches the delete_block rule."""
        policy = _basic_policy()
        action = Action("delete", "database")
        decision = policy.evaluate(action)

        assert decision.risk_level == RiskLevel.CRITICAL
        assert decision.approval == Approval.BLOCK
        assert decision.matched_rule == "delete_block"

    def test_evaluate_unknown_action_no_crash(self) -> None:
        """An unknown action type does not crash; it falls to defaults."""
        policy = _basic_policy()
        action = Action("quantum_entangle", "photon_array")
        decision = policy.evaluate(action)

        assert isinstance(decision, PolicyDecision)
        assert decision.matched_rule == "<default>"

    def test_evaluate_empty_action_type(self) -> None:
        """Empty action type is handled gracefully."""
        policy = _basic_policy()
        action = Action("", "target")
        decision = policy.evaluate(action)

        assert isinstance(decision, PolicyDecision)

    def test_evaluate_empty_target(self) -> None:
        """Empty target is handled gracefully."""
        policy = _basic_policy()
        action = Action("read", "")
        decision = policy.evaluate(action)

        assert isinstance(decision, PolicyDecision)


# ---------------------------------------------------------------------------
# Decision required fields
# ---------------------------------------------------------------------------


class TestDecisionRequiredFields:
    """PolicyDecision must have outcome, risk_level, and rule."""

    def test_decision_has_approval_outcome(self) -> None:
        """Decision has an approval field (maps to AGP outcome)."""
        policy = _basic_policy()
        decision = policy.evaluate(Action("read", "crm"))
        assert decision.approval in (Approval.AUTO, Approval.APPROVE, Approval.BLOCK)

    def test_decision_has_risk_level(self) -> None:
        """Decision includes risk_level."""
        policy = _basic_policy()
        decision = policy.evaluate(Action("read", "crm"))
        assert isinstance(decision.risk_level, RiskLevel)
        assert decision.risk_level.name in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_decision_has_matched_rule(self) -> None:
        """Decision includes the rule that matched."""
        policy = _basic_policy()
        decision = policy.evaluate(Action("read", "crm"))
        assert isinstance(decision.matched_rule, str)
        assert len(decision.matched_rule) > 0

    def test_decision_carries_original_action(self) -> None:
        """Decision carries a reference to the original action."""
        policy = _basic_policy()
        action = Action("write", "stripe", params={"amount": 100})
        decision = policy.evaluate(action)
        assert decision.action is action
        assert decision.action.type == "write"
        assert decision.action.target == "stripe"

    def test_is_allowed_property(self) -> None:
        """is_allowed is True for AUTO/APPROVE, False for BLOCK."""
        policy = _basic_policy()

        auto_decision = policy.evaluate(Action("read", "crm"))
        assert auto_decision.is_allowed is True

        approve_decision = policy.evaluate(Action("write", "crm"))
        assert approve_decision.is_allowed is True

        block_decision = policy.evaluate(Action("delete", "db"))
        assert block_decision.is_allowed is False


# ---------------------------------------------------------------------------
# Fail-safe policy
# ---------------------------------------------------------------------------


class TestFailSafePolicy:
    """When no rules match, destructive actions must be blocked."""

    def test_no_rules_blocks_by_default(self) -> None:
        """Fail-safe policy blocks all actions when configured to do so."""
        policy = _failsafe_policy()
        action = Action("delete_everything", "production")
        decision = policy.evaluate(action)

        assert decision.approval == Approval.BLOCK
        assert decision.is_allowed is False

    def test_no_rules_reports_default_rule(self) -> None:
        """When no rule matches, matched_rule is '<default>'."""
        policy = _failsafe_policy()
        action = Action("unknown", "somewhere")
        decision = policy.evaluate(action)

        assert decision.matched_rule == "<default>"

    def test_no_rules_assigns_default_risk(self) -> None:
        """Default risk level is applied when no rule matches."""
        policy = _failsafe_policy()
        action = Action("anything", "anywhere")
        decision = policy.evaluate(action)

        assert decision.risk_level == RiskLevel.HIGH

    def test_failsafe_with_various_destructive_actions(self) -> None:
        """Multiple destructive actions are all blocked by fail-safe."""
        policy = _failsafe_policy()
        destructive_actions = [
            Action("drop_table", "production_db"),
            Action("rm_rf", "/"),
            Action("format_disk", "system"),
            Action("shutdown", "server-001"),
        ]

        for action in destructive_actions:
            decision = policy.evaluate(action)
            assert decision.approval == Approval.BLOCK, f"Fail-safe did not block: {action.type}"


# ---------------------------------------------------------------------------
# AGEF policy_decision events from decisions
# ---------------------------------------------------------------------------


class TestAGEFPolicyDecisionEvent:
    """Verify that PolicyDecision data can produce AGEF policy_decision events."""

    def _decision_to_agef(self, decision: PolicyDecision) -> dict:
        """Convert a PolicyDecision to an AGEF-shaped dict.

        This is a conformance-level check that the required AGEF fields
        are derivable from the Aegis decision model.
        """
        return {
            "event_type": "policy_decision",
            "action": {
                "type": decision.action.type,
                "target": decision.action.target,
                "params": decision.action.params,
                "description": decision.action.description,
            },
            "decision": {
                "outcome": self._approval_to_outcome(decision.approval),
                "risk_level": decision.risk_level.name,
                "rule": decision.matched_rule,
                "approval_required": decision.approval == Approval.APPROVE,
            },
        }

    @staticmethod
    def _approval_to_outcome(approval: Approval) -> str:
        """Map Aegis Approval enum to AGEF outcome string."""
        return {
            Approval.AUTO: "allowed",
            Approval.APPROVE: "escalated",
            Approval.BLOCK: "blocked",
        }[approval]

    def test_auto_decision_maps_to_allowed(self) -> None:
        policy = _basic_policy()
        decision = policy.evaluate(Action("read", "crm"))
        agef = self._decision_to_agef(decision)

        assert agef["event_type"] == "policy_decision"
        assert agef["decision"]["outcome"] == "allowed"
        assert agef["decision"]["risk_level"] == "LOW"
        assert agef["decision"]["approval_required"] is False

    def test_approve_decision_maps_to_escalated(self) -> None:
        policy = _basic_policy()
        decision = policy.evaluate(Action("write", "database"))
        agef = self._decision_to_agef(decision)

        assert agef["decision"]["outcome"] == "escalated"
        assert agef["decision"]["risk_level"] == "MEDIUM"
        assert agef["decision"]["approval_required"] is True

    def test_block_decision_maps_to_blocked(self) -> None:
        policy = _basic_policy()
        decision = policy.evaluate(Action("delete", "database"))
        agef = self._decision_to_agef(decision)

        assert agef["decision"]["outcome"] == "blocked"
        assert agef["decision"]["risk_level"] == "CRITICAL"
        assert agef["decision"]["approval_required"] is False

    def test_agef_action_section_complete(self) -> None:
        """AGEF action section has all required fields from the Action model."""
        policy = _basic_policy()
        action = Action(
            "api_call",
            "stripe",
            params={"amount": 100},
            description="Charge customer",
        )
        decision = policy.evaluate(action)
        agef = self._decision_to_agef(decision)

        assert agef["action"]["type"] == "api_call"
        assert agef["action"]["target"] == "stripe"
        assert agef["action"]["params"] == {"amount": 100}
        assert agef["action"]["description"] == "Charge customer"

    def test_default_decision_produces_valid_agef(self) -> None:
        """Even default (unmatched) decisions produce valid AGEF events."""
        policy = _basic_policy()
        decision = policy.evaluate(Action("custom_action", "custom_target"))
        agef = self._decision_to_agef(decision)

        assert agef["event_type"] == "policy_decision"
        assert agef["decision"]["outcome"] in (
            "allowed",
            "blocked",
            "escalated",
            "masked",
            "warned",
        )
        assert agef["decision"]["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert isinstance(agef["decision"]["rule"], str)
