import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from backend.models import Decision, Restriction


def now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


class SecurityState:
    """Thread-safe in-memory state store for continuous authorization monitoring."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.agents: Dict[str, Dict[str, Any]] = {
            "agent-finops-01": {
                "id": "agent-finops-01",
                "name": "FinOps Payment Agent",
                "role": "Financial Operations",
                "permissions": ["read_report", "transfer_funds", "list_users"],
                "prohibited": ["delete_user", "disable_mfa", "grant_admin"],
                "status": "Active",
                "active": True,
            },
            "agent-support-02": {
                "id": "agent-support-02",
                "name": "Customer Support AI",
                "role": "Support Triage",
                "permissions": ["read_report", "list_users"],
                "prohibited": ["delete_user", "export_data", "transfer_funds"],
                "status": "Active",
                "active": True,
            },
            "agent-devops-03": {
                "id": "agent-devops-03",
                "name": "DevOps Pipeline Runner",
                "role": "Infrastructure & CI/CD",
                "permissions": ["read_report", "install_software", "write_production_config"],
                "prohibited": ["delete_user", "disable_mfa"],
                "status": "Active",
                "active": True,
            },
            "agent-analyst-04": {
                "id": "agent-analyst-04",
                "name": "Data Analytics Bot",
                "role": "Business Intelligence",
                "permissions": ["read_report", "export_data"],
                "prohibited": ["delete_user", "write_production_config"],
                "status": "Active",
                "active": True,
            },
            "agent-compromised-05": {
                "id": "agent-compromised-05",
                "name": "Legacy Sync Agent",
                "role": "Third-Party Connector",
                "permissions": ["read_report"],
                "prohibited": ["grant_admin", "delete_user", "transfer_funds"],
                "status": "Quarantined",
                "active": False,
            },
        }

        self.events: List[Dict[str, Any]] = [
            {
                "id": "evt-1001",
                "timestamp": "2026-10-14 17:45:10",
                "agent_id": "agent-compromised-05",
                "agent_name": "Legacy Sync Agent",
                "action": "grant_admin",
                "risk_score": 95,
                "decision": "QUARANTINE",
                "reason": "Risk score 95 exceeds quarantine threshold (85). Critical anomalous source & privileged context.",
            },
            {
                "id": "evt-1002",
                "timestamp": "2026-10-14 18:02:15",
                "agent_id": "agent-support-02",
                "agent_name": "Customer Support AI",
                "action": "export_data",
                "risk_score": 50,
                "decision": "DENY",
                "reason": "Mandatory security rule prohibits action 'export_data' for support agent.",
            },
            {
                "id": "evt-1003",
                "timestamp": "2026-10-14 18:14:32",
                "agent_id": "agent-finops-01",
                "agent_name": "FinOps Payment Agent",
                "action": "read_report",
                "risk_score": 0,
                "decision": "ALLOW",
                "reason": "Action 'read_report' allowed under policy. Standard low-risk operation.",
            },
            {
                "id": "evt-1004",
                "timestamp": "2026-10-14 18:20:44",
                "agent_id": "agent-analyst-04",
                "agent_name": "Data Analytics Bot",
                "action": "export_data",
                "risk_score": 35,
                "decision": "HOLD_FOR_APPROVAL",
                "reason": "Approval required for sensitive action 'export_data' (Risk score: 35).",
            },
            {
                "id": "evt-1005",
                "timestamp": "2026-10-14 18:28:01",
                "agent_id": "agent-devops-03",
                "agent_name": "DevOps Pipeline Runner",
                "action": "write_production_config",
                "risk_score": 65,
                "decision": "DENY",
                "reason": "Risk score 65 exceeds risk threshold (60). Execution flagged out-of-hours.",
            },
        ]

        self.approvals: List[Dict[str, Any]] = [
            {
                "id": "appr-01",
                "agent_id": "agent-analyst-04",
                "agent_name": "Data Analytics Bot",
                "action": "export_data",
                "risk_score": 35,
                "reason": "Sensitive action 'export_data' requested for Quarterly Q3 Financial Summary export.",
                "timestamp": "2026-10-14 18:20:44",
                "metadata": {"source": "internal", "format": "parquet", "destination": "analytics_lake"},
                "status": "pending",
            },
            {
                "id": "appr-02",
                "agent_id": "agent-finops-01",
                "agent_name": "FinOps Payment Agent",
                "action": "transfer_funds",
                "risk_score": 55,
                "reason": "High-value vendor payment batch invoice #INV-9821 ($14,500). Elevated risk threshold.",
                "timestamp": "2026-10-14 18:31:00",
                "metadata": {"amount": 14500, "currency": "USD", "privileged": True},
                "status": "pending",
            },
        ]

        self.policy_config: Dict[str, Any] = {
            "risk_threshold": 60,
            "quarantine_threshold": 85,
            "approval_threshold": 40,
            "sensitive_actions": [
                "delete_user",
                "disable_mfa",
                "export_data",
                "grant_admin",
                "install_software",
                "reset_credentials",
                "transfer_funds",
                "write_production_config",
            ],
            "risk_weights": {
                "sensitive_action": 35,
                "privileged_context": 20,
                "untrusted_source": 15,
                "new_device": 15,
                "unknown_user": 10,
                "high_impact": 20,
                "out_of_hours": 10,
                "unusual_location": 10,
                "admin_action": 15,
            },
        }

    def get_dashboard(self) -> Dict[str, int]:
        total_agents = len(self.agents)
        quarantined = sum(1 for a in self.agents.values() if a.get("status") == "Quarantined" or not a.get("active"))
        pending = sum(1 for ap in self.approvals if ap.get("status") == "pending")

        allowed = sum(1 for e in self.events if e.get("decision") in {"ALLOW", "approved", "Approved"})
        denied = sum(
            1 for e in self.events if e.get("decision") in {"DENY", "REJECT", "rejected", "Rejected", "QUARANTINE"}
        )

        return {
            "total_agents": total_agents,
            "allowed_requests": allowed,
            "denied_requests": denied,
            "pending_approvals": pending,
            "quarantined_agents": quarantined,
        }

    def get_agents(self) -> List[Dict[str, Any]]:
        rows = []
        for a in self.agents.values():
            perms = a.get("permissions", [])
            rows.append({
                "id": a["id"],
                "name": a["name"],
                "role": a.get("role", "General Agent"),
                "permissions": ", ".join(perms) if isinstance(perms, list) else str(perms),
                "prohibited": ", ".join(a.get("prohibited", [])) if isinstance(a.get("prohibited"), list) else "",
                "status": a.get("status", "Active"),
                "active": a.get("active", True),
            })
        return rows

    def get_agent_raw(self, agent_id: str) -> Optional[Dict[str, Any]]:
        return self.agents.get(agent_id)

    def add_agent(
        self,
        agent_id: str,
        name: str,
        role: str,
        permissions: List[str],
        prohibited: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        record = {
            "id": agent_id,
            "name": name,
            "role": role,
            "permissions": permissions,
            "prohibited": prohibited or [],
            "status": "Active",
            "active": True,
        }
        self.agents[agent_id] = record
        return record

    def set_agent_status(self, agent_id: str, status: str) -> bool:
        if agent_id in self.agents:
            self.agents[agent_id]["status"] = status
            self.agents[agent_id]["active"] = status == "Active"
            return True
        return False

    def get_events(self) -> List[Dict[str, Any]]:
        return list(reversed(self.events))

    def record_event(
        self,
        agent_id: str,
        agent_name: str,
        action: str,
        risk_score: int,
        decision: str,
        reason: str,
    ) -> Dict[str, Any]:
        evt = {
            "id": f"evt-{uuid.uuid4().hex[:6]}",
            "timestamp": now_str(),
            "agent_id": agent_id,
            "agent_name": agent_name,
            "action": action,
            "risk_score": risk_score,
            "decision": decision,
            "reason": reason,
        }
        self.events.append(evt)
        return evt

    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        return [ap for ap in self.approvals if ap.get("status") == "pending"]

    def create_approval_request(
        self,
        agent_id: str,
        agent_name: str,
        action: str,
        risk_score: int,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        appr = {
            "id": f"appr-{uuid.uuid4().hex[:6]}",
            "agent_id": agent_id,
            "agent_name": agent_name,
            "action": action,
            "risk_score": risk_score,
            "reason": reason,
            "timestamp": now_str(),
            "metadata": metadata or {},
            "status": "pending",
        }
        self.approvals.append(appr)
        return appr

    def review_approval(self, approval_id: str, decision: str) -> Optional[Dict[str, Any]]:
        for ap in self.approvals:
            if ap["id"] == approval_id:
                ap["status"] = "approved" if decision == "approve" else "rejected"
                ap["resolved_at"] = now_str()

                decision_label = "ALLOW" if decision == "approve" else "DENY"
                reason_text = (
                    f"Human supervisor APPROVED action '{ap['action']}' after review."
                    if decision == "approve"
                    else f"Human supervisor REJECTED action '{ap['action']}' during review."
                )
                self.record_event(
                    agent_id=ap["agent_id"],
                    agent_name=ap["agent_name"],
                    action=ap["action"],
                    risk_score=ap["risk_score"],
                    decision=decision_label,
                    reason=reason_text,
                )
                return ap
        return None


# Global singleton instance
state = SecurityState()

