from backend.models import Decision, PolicyDecision, Request, Restriction
from backend.permissions import is_permitted, is_prohibited, is_sensitive
from backend.risk import calculate_risk


class SecurityPolicy:
    """Continuous authorization security policy engine."""

    def __init__(
        self,
        risk_threshold: int = 60,
        quarantine_threshold: int = 85,
        approval_threshold: int = 40,
    ) -> None:
        self.risk_threshold = risk_threshold
        self.quarantine_threshold = quarantine_threshold
        self.approval_threshold = approval_threshold

    def evaluate(self, request: Request) -> PolicyDecision:
        agent = request.agent
        action = request.action

        # 1. Identity must be authenticated
        if not agent.authenticated:
            return PolicyDecision(
                decision=Decision.REJECT,
                reason=["Caller is not authenticated."],
                risk_score=0,
                approval_required=False,
                restriction=Restriction.NONE,
            )

        # 2. Agent must be active
        if not agent.active:
            return PolicyDecision(
                decision=Decision.REJECT,
                reason=["Agent is inactive."],
                risk_score=0,
                approval_required=False,
                restriction=Restriction.NONE,
            )

        # 3. Explicit permissions check (default deny)
        if not is_permitted(agent, action):
            return PolicyDecision(
                decision=Decision.DENY,
                reason=[f"Action '{action}' is not explicitly permitted for agent '{agent.agent_id}'."],
                risk_score=0,
                approval_required=False,
                restriction=Restriction.DENY,
            )

        # 4. Mandatory prohibitions cannot be overridden
        if is_prohibited(agent, action):
            return PolicyDecision(
                decision=Decision.DENY,
                reason=[f"Mandatory security rule prohibits action '{action}'."],
                risk_score=0,
                approval_required=False,
                restriction=Restriction.DENY,
            )

        risk_score = calculate_risk(action, request.metadata)
        approval_required = is_sensitive(action) or (risk_score >= self.approval_threshold)

        # 5. Quarantine critical risk
        if risk_score >= self.quarantine_threshold:
            return PolicyDecision(
                decision=Decision.QUARANTINE,
                reason=[f"Risk score {risk_score} exceeds quarantine threshold ({self.quarantine_threshold})."],
                risk_score=risk_score,
                approval_required=approval_required,
                restriction=Restriction.QUARANTINE,
            )

        # 6. Deny high risk
        if risk_score >= self.risk_threshold:
            return PolicyDecision(
                decision=Decision.DENY,
                reason=[f"Risk score {risk_score} exceeds risk threshold ({self.risk_threshold})."],
                risk_score=risk_score,
                approval_required=approval_required,
                restriction=Restriction.DENY,
            )

        # 7. Sensitive actions or moderate risk require approval
        if approval_required:
            return PolicyDecision(
                decision=Decision.HOLD_FOR_APPROVAL,
                reason=[f"Approval required for action '{action}' (Risk score: {risk_score})."],
                risk_score=risk_score,
                approval_required=True,
                restriction=Restriction.NONE,
            )

        # 8. Otherwise allow
        return PolicyDecision(
            decision=Decision.ALLOW,
            reason=[f"Action '{action}' allowed under policy."],
            risk_score=risk_score,
            approval_required=False,
            restriction=Restriction.NONE,
        )