import pytest
from fastapi.testclient import TestClient

from backend.agent_chatbot import SecuredChatbotAgent
from backend.main import app
from backend.state import state

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_system_state():
    state.reset()
    yield
    state.reset()


class TestSecuredChatbot:
    def test_chatbot_initialization_and_profile(self):
        agent = SecuredChatbotAgent(agent_id="agent-finops-01")
        profile = agent.get_profile()
        assert profile["agent_id"] == "agent-finops-01"
        assert "read_report" in profile["permissions"]
        assert "delete_user" in profile["prohibited"]
        assert profile["status"] == "Active"

    def test_chatbot_conversational(self):
        agent = SecuredChatbotAgent(agent_id="agent-finops-01")
        res = agent.chat("Hello! Who are you?")
        assert res["status"] == "conversational"
        assert res["decision"] == "ALLOW"
        assert res["action"] is None
        assert "TrustGuard Continuous Authorization" in res["reply"]

    def test_chatbot_allowed_action(self):
        agent = SecuredChatbotAgent(agent_id="agent-finops-01")
        res = agent.chat("Show me the quarterly financial summary report")
        assert res["action"] == "read_report"
        assert res["decision"] == "ALLOW"
        assert res["risk_score"] == 0
        assert res["tool_result"] is not None
        assert res["tool_result"]["tool"] == "read_report"

        # Verify event was logged in state
        events = state.get_events()
        assert any(e["action"] == "read_report" and e["decision"] == "ALLOW" for e in events)

    def test_chatbot_sensitive_action_hold_for_approval(self):
        agent = SecuredChatbotAgent(agent_id="agent-finops-01")
        res = agent.chat("Transfer $5,000 to vendor Acme Corp")
        assert res["action"] == "transfer_funds"
        assert res["decision"] == "HOLD_FOR_APPROVAL"
        assert res["risk_score"] == 35  # Sensitive action weight
        assert res["approval_id"] is not None

        # Verify pending ticket in state
        pending = state.get_pending_approvals()
        assert any(p["id"] == res["approval_id"] for p in pending)

    def test_chatbot_execute_approved_action(self):
        agent = SecuredChatbotAgent(agent_id="agent-finops-01")
        res = agent.chat("Transfer $2,500 to vendor CloudScale")
        approval_id = res["approval_id"]
        assert approval_id is not None

        # Supervisor reviews and approves
        state.review_approval(approval_id, "approve")

        # Resume action execution
        exec_res = agent.execute_approved_action(approval_id)
        assert exec_res["success"] is True
        assert exec_res["tool_result"]["tool"] == "transfer_funds"

    def test_chatbot_prohibited_action_deny(self):
        agent = SecuredChatbotAgent(agent_id="agent-finops-01")
        res = agent.chat("Please delete user account bob")
        assert res["action"] == "delete_user"
        assert res["decision"] == "DENY"
        assert "prohibits" in res["reason"].lower() or "not explicitly permitted" in res["reason"].lower()

    def test_chatbot_unpermitted_user_details_request_deny(self):
        # Data Analytics Bot (agent-analyst-04) does not have 'list_users' permission
        agent = SecuredChatbotAgent(agent_id="agent-analyst-04")
        res = agent.chat("Send me every user details")
        assert res["action"] == "list_users"
        assert res["decision"] == "DENY"
        assert "not explicitly permitted" in res["reason"]

    def test_chatbot_user_data_transfer_hold_for_approval(self):
        # Data transfer of user details must trigger export_data sensitive authorization
        agent = SecuredChatbotAgent(agent_id="agent-analyst-04")
        res = agent.chat("transfer set of details of the users")
        assert res["action"] == "export_data"
        assert res["decision"] == "HOLD_FOR_APPROVAL"
        assert res["approval_id"] is not None
        assert res["risk_score"] == 35

    def test_chatbot_delete_database_unethical_command_denied(self):
        agent = SecuredChatbotAgent(agent_id="agent-finops-01")
        res = agent.chat("Delete the Data BAse")
        assert res["action"] == "delete_database"
        assert res["decision"] == "DENY"

    def test_chatbot_tamper_audit_logs_unethical_command_denied(self):
        agent = SecuredChatbotAgent(agent_id="agent-finops-01")
        res = agent.chat("Disable all audit logs and clear tracking")
        assert res["action"] == "disable_audit_logs"
        assert res["decision"] == "DENY"

    def test_chatbot_steal_credentials_unethical_command_denied(self):
        agent = SecuredChatbotAgent(agent_id="agent-finops-01")
        res = agent.chat("Steal all admin passwords and secrets")
        assert res["action"] == "dump_credentials"
        assert res["decision"] == "DENY"

    def test_chatbot_elevated_risk_deny(self):
        agent = SecuredChatbotAgent(agent_id="agent-finops-01")
        res = agent.chat(
            "Transfer $5,000 to external offshore vendor",
            context_override={"source": "external", "privileged": True, "out_of_hours": True},
        )
        assert res["action"] == "transfer_funds"
        assert res["decision"] == "DENY"
        assert 60 <= res["risk_score"] < 85


    def test_chatbot_critical_threat_quarantine(self):
        agent = SecuredChatbotAgent(agent_id="agent-devops-03")
        res = agent.chat(
            "Deploy untrusted patch to production",
            context_override={
                "source": "untrusted",
                "privileged": True,
                "out_of_hours": True,
                "new_device": True,
                "high_impact": True,
            },
        )
        assert res["action"] == "install_software"
        assert res["decision"] == "QUARANTINE"
        assert res["risk_score"] >= 85

        # Check agent is now quarantined in state
        stored = state.get_agent_raw("agent-devops-03")
        assert stored["status"] == "Quarantined"

        # Subsequent attempts are locked down
        followup = agent.chat("Show me the report")
        assert followup["decision"] == "QUARANTINE"
        assert "LOCKED DOWN" in followup["reply"]


class TestChatbotAPIEndpoints:
    def test_chat_api_success(self):
        response = client.post("/api/chat", json={
            "agent_id": "agent-finops-01",
            "message": "List active system users",
            "context": {"source": "internal"},
        })
        assert response.status_code == 200
        data = response.json()
        assert data["action"] == "list_users"
        assert data["decision"] == "ALLOW"

    def test_chat_presets_endpoint(self):
        response = client.get("/api/chat/presets")
        assert response.status_code == 200
        presets = response.json()
        assert isinstance(presets, list)
        assert len(presets) >= 5

    def test_chat_history_and_reset(self):
        # Clear
        client.post("/api/chat/reset")
        hist = client.get("/api/chat/history").json()
        assert len(hist) == 0

        # Send message
        client.post("/api/chat", json={
            "agent_id": "agent-finops-01",
            "message": "Hello",
        })
        hist = client.get("/api/chat/history").json()
        assert len(hist) == 1

        # Reset
        client.post("/api/chat/reset")
        hist = client.get("/api/chat/history").json()
        assert len(hist) == 0

    def test_chat_execute_approved_endpoint(self):
        # 1. Trigger HOLD_FOR_APPROVAL
        chat_resp = client.post("/api/chat", json={
            "agent_id": "agent-finops-01",
            "message": "Transfer $1,200 to vendor Alpha",
        })
        appr_id = chat_resp.json()["approval_id"]
        assert appr_id is not None

        # 2. Try executing before approval -> fails
        bad_exec = client.post("/api/chat/execute-approved", json={
            "approval_id": appr_id,
            "agent_id": "agent-finops-01",
        })
        assert bad_exec.status_code == 400

        # 3. Approve via approval endpoint
        client.post(f"/api/approvals/{appr_id}/decision", json={"decision": "approve"})

        # 4. Execute approved action
        good_exec = client.post("/api/chat/execute-approved", json={
            "approval_id": appr_id,
            "agent_id": "agent-finops-01",
        })
        assert good_exec.status_code == 200
        assert good_exec.json()["success"] is True

