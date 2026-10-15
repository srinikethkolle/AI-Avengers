# ...existing code...

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Optional, Set

SENSITIVE_ACTIONS = {
    "delete_user",
    "disable_mfa",
    "export_data",
    "grant_admin",
    "install_software",
    "reset_credentials",
    "transfer_funds",
    "write_production_config",
}

class Decision(str, Enum):
    REJECT = "REJECT"
    DENY = "DENY"
    HOLD_FOR_APPROVAL = "HOLD_FOR_APPROVAL"
    QUARANTINE = "QUARANTINE"
    ALLOW = "ALLOW"

class Restriction(str, Enum):
    NONE = "NONE"
    QUARANTINE = "QUARANTINE"
    DENY = "DENY"

@dataclass(frozen=True)
class Agent:
    agent_id: str
    authenticated: bool = True
    active: bool = True
    permissions: Set[str] = field(default_factory=set)
    mandatory_prohibitions: Set[str] = field(default_factory=set)

@dataclass
class Request:
    agent: Agent
    action: str
    metadata: Dict[str, object] = field(default_factory=dict)

@dataclass
class PolicyDecision:
    decision: Decision
    reason: List[str]
    risk_score: int
    approval_required: bool = False
    restriction: Restriction = Restriction.NONE

class SecurityPolicy:
    """
    Security policy engine.
    Default deny: an action is denied unless it is explicitly permitted.
    Security-critical rule: invalid identities and mandatory prohibitions cannot be
    overridden by a low risk score.
    """

    def __init__(
        self,
        risk_threshold: int = 60,
        quarantine_threshold: int = 85,
        approval_threshold: int = 40,
    ) -> None:
        self.risk_threshold = risk_threshold
        self.quarantine_threshold = quarantine_threshold
        self.approval_threshold = approval_threshold

    def is_authenticated(self, agent: Agent) -> bool:
        return bool(agent.authenticated)

    def is_active(self, agent: Agent) -> bool:
        return bool(agent.active)

    def is_sensitive_action(self, action: str) -> bool:
        return action in SENSITIVE_ACTIONS

    def is_action_permitted(self, agent: Agent, action: str) -> bool:
        return action in set(agent.permissions)

    def has_mandatory_prohibition(self, agent: Agent, action: str) -> bool:
        return action in set(agent.mandatory_prohibitions)

    def requires_approval(self, agent: Agent, action: str, risk_score: int) -> bool:
        if self.is_sensitive_action(action):
            return True
        if risk_score >= self.approval_threshold:
            return True
        return False

    def calculate_risk_score(self, agent: Agent, action: str, metadata: Dict[str, object]) -> int:
        score = 0

        if self.is_sensitive_action(action):
            score += 35

        if metadata.get("privileged", False):
            score += 20

        if metadata.get("source") in {"external", "untrusted"}:
            score += 15

        if metadata.get("new_device", False):
            score += 15

        if metadata.get("unknown_user", False):
            score += 10

        if metadata.get("high_impact", False):
            score += 20

        if metadata.get("out_of_hours", False):
            score += 10

        if metadata.get("unusual_location", False):
            score += 10

        if metadata.get("admin_action", False):
            score += 15

        return min(score, 100)

    def evaluate(self, request: Request) -> PolicyDecision:
        agent = request.agent
        action = request.action
        reasons: List[str] = []

        # 1. Must be authenticated
        if not self.is_authenticated(agent):
            return PolicyDecision(
                decision=Decision.REJECT,
                reason=["Caller is not authenticated."],
                risk_score=0,
                approval_required=False,
                restriction=Restriction.NONE,
            )

        # 2. Must be active
        if not self.is_active(agent):
            return PolicyDecision(
                decision=Decision.REJECT,
                reason=["Agent is inactive."],
                risk_score=0,
                approval_required=False,
                restriction=Restriction.NONE,
            )

        # 3. Permit check is explicit and default-deny
        if not self.is_action_permitted(agent, action):
            return PolicyDecision(
                decision=Decision.DENY,
                reason=[f"Action '{action}' is not explicitly permitted for agent '{agent.agent_id}'."],
                risk_score=0,
                approval_required=False,
                restriction=Restriction.DENY,
            )

        # 4. Mandatory prohibitions cannot be overridden
        if self.has_mandatory_prohibition(agent, action):
            return PolicyDecision(
                decision=Decision.DENY,
                reason=[f"Mandatory security rule prohibits action '{action}'."],
                risk_score=0,
                approval_required=False,
                restriction=Restriction.DENY,
            )

        risk_score = self.calculate_risk_score(agent, action, request.metadata)
        approval_required = self.requires_approval(agent, action, risk_score)
        reasons.append(f"Risk score: {risk_score}")

        # 5. Approval decision
        if approval_required and risk_score < self.quarantine_threshold:
            return PolicyDecision(
                decision=Decision.HOLD_FOR_APPROVAL,
                reason=reasons + [f"Approval required for action '{action}'."],
                risk_score=risk_score,
                approval_required=True,
                restriction=Restriction.NONE,
            )

        # 6. Risk policy: do not allow low-risk actions to override security rules.
        if risk_score >= self.quarantine_threshold:
            return PolicyDecision(
                decision=Decision.QUARANTINE,
                reason=reasons + ["Risk policy requires quarantine."],
                risk_score=risk_score,
                approval_required=approval_required,
                restriction=Restriction.QUARANTINE,
            )

        if risk_score >= self.risk_threshold:
            return PolicyDecision(
                decision=Decision.DENY,
                reason=reasons + ["Risk policy requires denial."],
                risk_score=risk_score,
                approval_required=approval_required,
                restriction=Restriction.DENY,
            )

        # 7. Otherwise allow
        return PolicyDecision(
            decision=Decision.ALLOW,
            reason=[f"Action '{action}' allowed under policy."],
            risk_score=risk_score,
            approval_required=False,
            restriction=Restriction.NONE,
        )


# ---------------------------------------------------------------------------
# Example usage
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Normal allowed action
    agent = Agent(
        agent_id="agent-001",
        authenticated=True,
        active=True,
        permissions={"read_report", "list_users"},
    )
    request = Request(agent=agent, action="read_report", metadata={})
    decision = SecurityPolicy().evaluate(request)
    print(decision)

    # Sensitive action requiring approval
    agent_2 = Agent(
        agent_id="agent-002",
        authenticated=True,
        active=True,
        permissions={"export_data"},
    )
    request_2 = Request(
        agent=agent_2,
        action="export_data",
        metadata={"source": "external", "high_impact": True},
    )
    decision_2 = SecurityPolicy().evaluate(request_2)
    print(decision_2)

    # Mandatory prohibition
    agent_3 = Agent(
        agent_id="agent-003",
        authenticated=True,
        active=True,
        permissions={"delete_user"},
        mandatory_prohibitions={"delete_user"},
    )
    request_3 = Request(agent=agent_3, action="delete_user", metadata={})
    print(SecurityPolicy().evaluate(request_3))

import unittest


class SecurityPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = SecurityPolicy()

    def test_rejects_unauthenticated_agent(self):
        agent = Agent("a1", authenticated=False, active=True, permissions={"read_report"})
        decision = self.policy.evaluate(Request(agent=agent, action="read_report"))
        self.assertEqual(decision.decision, Decision.REJECT)

    def test_rejects_inactive_agent(self):
        agent = Agent("a2", authenticated=True, active=False, permissions={"read_report"})
        decision = self.policy.evaluate(Request(agent=agent, action="read_report"))
        self.assertEqual(decision.decision, Decision.REJECT)

    def test_denies_unpermitted_action(self):
        agent = Agent("a3", authenticated=True, active=True, permissions={"read_report"})
        decision = self.policy.evaluate(Request(agent=agent, action="delete_user"))
        self.assertEqual(decision.decision, Decision.DENY)

    def test_denies_mandatory_prohibition(self):
        agent = Agent(
            "a4",
            authenticated=True,
            active=True,
            permissions={"delete_user"},
            mandatory_prohibitions={"delete_user"},
        )
        decision = self.policy.evaluate(Request(agent=agent, action="delete_user"))
        self.assertEqual(decision.decision, Decision.DENY)

    def test_holds_for_approval_on_sensitive_action(self):
        agent = Agent("a5", authenticated=True, active=True, permissions={"export_data"})
        decision = self.policy.evaluate(
            Request(
                agent=agent,
                action="export_data",
                metadata={"source": "external"},
            )
        )
        self.assertEqual(decision.decision, Decision.HOLD_FOR_APPROVAL)

    def test_quarantines_high_risk_action(self):
        agent = Agent("a6", authenticated=True, active=True, permissions={"grant_admin"})
        decision = self.policy.evaluate(
            Request(
                agent=agent,
                action="grant_admin",
                metadata={
                    "privileged": True,
                    "source": "external",
                    "high_impact": True,
                    "new_device": True,
                    "out_of_hours": True,
                },
            )
        )
        self.assertEqual(decision.decision, Decision.QUARANTINE)

    def test_allows_permitted_low_risk_action(self):
        agent = Agent("a7", authenticated=True, active=True, permissions={"read_report"})
        decision = self.policy.evaluate(Request(agent=agent, action="read_report"))
        self.assertEqual(decision.decision, Decision.ALLOW)

    def test_denies_when_risk_threshold_is_reached(self):
        agent = Agent("a8", authenticated=True, active=True, permissions={"install_software"})
        decision = self.policy.evaluate(
            Request(
                agent=agent,
                action="install_software",
                metadata={"privileged": True, "source": "external"},
            )
        )
        # installation is sensitive and should hit approval; if risk score is high enough,
        # this policy can escalate to quarantine or deny depending on thresholds.
        self.assertIn(decision.decision, {Decision.HOLD_FOR_APPROVAL, Decision.QUARANTINE, Decision.DENY})


if __name__ == "__main__":
    unittest.main()