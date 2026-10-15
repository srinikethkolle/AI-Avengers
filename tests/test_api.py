from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["project"] == "TrustGuard"
    assert data["status"] == "running"


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_auth_login_success():
    response = client.post("/auth/login", json={"username": "alice", "password": "secret123"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_auth_login_invalid():
    response = client.post("/auth/login", json={"username": "alice", "password": "wrongpassword"})
    assert response.status_code == 401


def test_get_me_unauthorized():
    response = client.get("/policy/me")
    assert response.status_code == 401


def test_get_me_authorized():
    login_resp = client.post("/auth/login", json={"username": "alice", "password": "secret123"})
    token = login_resp.json()["access_token"]

    response = client.get("/policy/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    assert data["agent_id"] == "alice"
    assert "read_report" in data["permissions"]


def test_evaluate_policy_authorized():
    login_resp = client.post("/auth/login", json={"username": "alice", "password": "secret123"})
    token = login_resp.json()["access_token"]

    # Allowed action
    response = client.post(
        "/policy/evaluate",
        headers={"Authorization": f"Bearer {token}"},
        json={"action": "read_report", "metadata": {}},
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"

    # Prohibited action
    response = client.post(
        "/policy/evaluate",
        headers={"Authorization": f"Bearer {token}"},
        json={"action": "delete_user", "metadata": {}},
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "DENY"


def test_dashboard_endpoint():
    response = client.get("/api/dashboard")
    assert response.status_code == 200
    data = response.json()
    for key in ["total_agents", "allowed_requests", "denied_requests", "pending_approvals", "quarantined_agents"]:
        assert key in data
        assert isinstance(data[key], int)


def test_agents_endpoint_and_quarantine():
    response = client.get("/api/agents")
    assert response.status_code == 200
    agents = response.json()
    assert isinstance(agents, list)
    assert len(agents) > 0

    first_agent_id = agents[0]["id"]
    # Toggle quarantine
    toggle_resp = client.post(f"/api/agents/{first_agent_id}/quarantine")
    assert toggle_resp.status_code == 200
    assert toggle_resp.json()["status"] == "success"
    # Toggle back to original status
    restore_resp = client.post(f"/api/agents/{first_agent_id}/quarantine")
    assert restore_resp.status_code == 200
    assert restore_resp.json()["new_status"] == "Active"



def test_events_endpoint():
    response = client.get("/api/events")
    assert response.status_code == 200
    events = response.json()
    assert isinstance(events, list)
    assert len(events) > 0
    assert "agent_name" in events[0]
    assert "decision" in events[0]


def test_approvals_endpoint_and_decision():
    response = client.get("/api/approvals")
    assert response.status_code == 200
    approvals = response.json()
    assert isinstance(approvals, list)

    if len(approvals) > 0:
        appr_id = approvals[0]["id"]
        review_resp = client.post(f"/api/approvals/{appr_id}/decision", json={"decision": "approve"})
        assert review_resp.status_code == 200
        assert "Approved" in review_resp.json()["status"]


def test_policies_endpoints():
    get_resp = client.get("/api/policies")
    assert get_resp.status_code == 200
    assert "active_thresholds" in get_resp.json()

    update_resp = client.post("/api/policies", json={"risk_threshold": 65})
    assert update_resp.status_code == 200
    assert update_resp.json()["risk_threshold"] == 65


def test_direct_evaluate_endpoint():
    response = client.post(
        "/api/evaluate",
        json={
            "agent_id": "agent-finops-01",
            "action": "read_report",
            "metadata": {"source": "internal"},
        },
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"


def test_simulation_run_endpoint():
    response = client.post("/api/simulation/run")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["steps_executed"] >= 4
    assert len(data["results"]) >= 4


