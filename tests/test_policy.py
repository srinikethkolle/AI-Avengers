import pytest
from backend.models import Agent, Decision, Request, Restriction
from backend.policy_engine import SecurityPolicy
from backend.risk import calculate_risk
from backend.permissions import is_permitted, is_prohibited, is_sensitive


class TestSecurityPolicy:
    @pytest.fixture
    def policy(self):
        return SecurityPolicy(risk_threshold=60, quarantine_threshold=85, approval_threshold=40)

    def test_rejects_unauthenticated_agent(self, policy):
        agent = Agent(agent_id="agent-01", authenticated=False, active=True, permissions={"read_report"})
        req = Request(agent=agent, action="read_report")
        decision = policy.evaluate(req)
        assert decision.decision == Decision.REJECT
        assert "Caller is not authenticated" in decision.reason[0]

    def test_rejects_inactive_agent(self, policy):
        agent = Agent(agent_id="agent-02", authenticated=True, active=False, permissions={"read_report"})
        req = Request(agent=agent, action="read_report")
        decision = policy.evaluate(req)
        assert decision.decision == Decision.REJECT
        assert "Agent is inactive" in decision.reason[0]

    def test_denies_unpermitted_action(self, policy):
        agent = Agent(agent_id="agent-03", authenticated=True, active=True, permissions={"read_report"})
        req = Request(agent=agent, action="delete_user")
        decision = policy.evaluate(req)
        assert decision.decision == Decision.DENY
        assert "not explicitly permitted" in decision.reason[0]

    def test_denies_prohibited_action(self, policy):
        agent = Agent(
            agent_id="agent-04",
            authenticated=True,
            active=True,
            permissions={"delete_user"},
            prohibited={"delete_user"},
        )
        req = Request(agent=agent, action="delete_user")
        decision = policy.evaluate(req)
        assert decision.decision == Decision.DENY
        assert "Mandatory security rule prohibits" in decision.reason[0]

    def test_allows_low_risk_permitted_action(self, policy):
        agent = Agent(agent_id="agent-05", authenticated=True, active=True, permissions={"read_report"})
        req = Request(agent=agent, action="read_report", metadata={})
        decision = policy.evaluate(req)
        assert decision.decision == Decision.ALLOW
        assert decision.risk_score == 0

    def test_holds_for_approval_sensitive_action(self, policy):
        agent = Agent(agent_id="agent-06", authenticated=True, active=True, permissions={"export_data"})
        # export_data is sensitive (+35), which is < 60 risk threshold but sensitive
        req = Request(agent=agent, action="export_data", metadata={})
        decision = policy.evaluate(req)
        assert decision.decision == Decision.HOLD_FOR_APPROVAL
        assert decision.approval_required is True
        assert decision.risk_score == 35

    def test_denies_when_risk_threshold_reached(self, policy):
        # export_data (+35) + privileged (+20) + out_of_hours (+10) = 65 (>= 60 risk_threshold, < 85)
        agent = Agent(agent_id="agent-07", authenticated=True, active=True, permissions={"export_data"})
        req = Request(
            agent=agent,
            action="export_data",
            metadata={"privileged": True, "out_of_hours": True},
        )
        decision = policy.evaluate(req)
        assert decision.decision == Decision.DENY
        assert decision.risk_score == 65
        assert decision.restriction == Restriction.DENY

    def test_quarantines_critical_risk(self, policy):
        # export_data (+35) + privileged (+20) + source external (+15) + new_device (+15) + out_of_hours (+10) = 95 (>= 85)
        agent = Agent(agent_id="agent-08", authenticated=True, active=True, permissions={"export_data"})
        req = Request(
            agent=agent,
            action="export_data",
            metadata={
                "privileged": True,
                "source": "external",
                "new_device": True,
                "out_of_hours": True,
            },
        )
        decision = policy.evaluate(req)
        assert decision.decision == Decision.QUARANTINE
        assert decision.risk_score == 95
        assert decision.restriction == Restriction.QUARANTINE


class TestRiskAndPermissions:
    def test_risk_calculation(self):
        score = calculate_risk("read_report", {})
        assert score == 0

        score = calculate_risk(
            "delete_user",
            {
                "privileged": True,
                "source": "untrusted",
                "high_impact": True,
                "new_device": True,
                "out_of_hours": True,
                "admin_action": True,
            },
        )
        assert score == 100

    def test_permissions_helpers(self):
        agent = Agent("a1", permissions={"action_a"}, prohibited={"action_b"})
        assert is_permitted(agent, "action_a") is True
        assert is_permitted(agent, "action_b") is False
        assert is_prohibited(agent, "action_b") is True
        assert is_prohibited(agent, "action_a") is False
        assert is_sensitive("export_data") is True
        assert is_sensitive("read_report") is False

