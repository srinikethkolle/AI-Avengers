"""
TrustGuard Secured AI Agent Chatbot
====================================
An enterprise autonomous AI chatbot secured by the TrustGuard Continuous
Authorization policy engine.

Key Security Guarantees:
1. Zero Standing Privileges: Every sensitive tool action is re-evaluated dynamically at runtime.
2. Mandatory Security Rules: Hard prohibitions (e.g., delete_user, disable_mfa) cannot be overridden
   even if prompt-injected.
3. Dynamic Risk Scoring: Environmental factors (external prompt source, privileged context,
   out-of-hours, new device session, high impact) continuously drive authorization decisions.
4. Human-In-The-Loop: Sensitive or moderate-risk operations trigger HOLD_FOR_APPROVAL tickets
   in the TrustGuard Approval Center.
5. Autonomous Threat Containment: Critical threats (risk >= 85) trigger immediate agent QUARANTINE,
   locking down the agent session.
"""

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.authentication.auth import issue_token, authenticate_token
from backend.models import Agent, Decision, PolicyDecision, Request, Restriction
from backend.permissions import SENSITIVE_ACTIONS, is_permitted, is_prohibited, is_sensitive
from backend.policy_engine import SecurityPolicy
from backend.risk import calculate_risk
from backend.state import state


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# Simulated Enterprise Agent Tools
# ---------------------------------------------------------------------------

class AgentTools:
    """Catalog of operational tools that the AI agent can execute."""

    @staticmethod
    def read_report(report_name: str = "quarterly_summary", **kwargs) -> Dict[str, Any]:
        reports = {
            "quarterly_summary": {
                "period": "Q3 2026",
                "revenue": "$14,850,000",
                "operating_margin": "24.6%",
                "cash_flow": "+$3,210,000",
                "active_accounts": 1284,
                "compliance_status": "Audited & Verified",
            },
            "financial_ledger": {
                "period": "October 2026",
                "balance": "$8,420,150",
                "pending_disbursements": "$342,000",
                "recent_invoices_cleared": 42,
            },
            "system_health": {
                "uptime": "99.98%",
                "active_nodes": 16,
                "cluster_load": "42%",
                "security_patches": "Up to date",
            },
        }
        clean_name = report_name.lower().replace(" ", "_")
        data = reports.get(clean_name, reports["quarterly_summary"])
        return {
            "success": True,
            "tool": "read_report",
            "report_name": clean_name,
            "data": data,
        }

    @staticmethod
    def list_users(**kwargs) -> Dict[str, Any]:
        return {
            "success": True,
            "tool": "list_users",
            "total_users": 5,
            "users": [
                {"id": "usr-01", "name": "Alice Johnson", "role": "Senior Accountant", "dept": "Finance"},
                {"id": "usr-02", "name": "Bob Martinez", "role": "Site Reliability Engineer", "dept": "DevOps"},
                {"id": "usr-03", "name": "Charlie Davis", "role": "Support Lead", "dept": "Customer Operations"},
                {"id": "usr-04", "name": "Diana Ross", "role": "Data Engineer", "dept": "Analytics"},
                {"id": "usr-05", "name": "Security Auditor", "role": "Infosec Admin", "dept": "Security"},
            ],
        }

    @staticmethod
    def transfer_funds(amount: float = 1000.0, recipient: str = "Acme Vendor Corp", memo: str = "Invoice settlement", **kwargs) -> Dict[str, Any]:
        txn_id = f"TXN-{uuid.uuid4().hex[:8].upper()}"
        return {
            "success": True,
            "tool": "transfer_funds",
            "transaction_id": txn_id,
            "amount": amount,
            "recipient": recipient,
            "memo": memo,
            "executed_at": now_iso(),
            "message": f"Successfully disbursed ${amount:,.2f} to {recipient} ({txn_id}).",
        }

    @staticmethod
    def export_data(dataset: str = "customer_records", format: str = "parquet", **kwargs) -> Dict[str, Any]:
        export_id = f"EXP-{uuid.uuid4().hex[:6].upper()}"
        return {
            "success": True,
            "tool": "export_data",
            "export_id": export_id,
            "dataset": dataset,
            "format": format,
            "records_exported": 8420,
            "storage_uri": f"s3://secure-analytics-lake/exports/{export_id}.{format}",
        }

    @staticmethod
    def install_software(package: str = "patch-agent-v2", target: str = "prod-node-01", **kwargs) -> Dict[str, Any]:
        return {
            "success": True,
            "tool": "install_software",
            "package": package,
            "target": target,
            "installed_at": now_iso(),
            "status": "Deployed successfully into cluster.",
        }

    @staticmethod
    def write_production_config(service: str = "nginx", config: str = "worker_processes auto;", **kwargs) -> Dict[str, Any]:
        return {
            "success": True,
            "tool": "write_production_config",
            "service": service,
            "config_hash": uuid.uuid4().hex[:12],
            "updated_at": now_iso(),
            "status": f"Production configuration updated for {service}.",
        }

    @staticmethod
    def delete_user(username: str = "unknown", **kwargs) -> Dict[str, Any]:
        return {
            "success": True,
            "tool": "delete_user",
            "username": username,
            "deleted_at": now_iso(),
            "status": f"User account '{username}' purged from identity store.",
        }

    @staticmethod
    def grant_admin(username: str = "unknown", **kwargs) -> Dict[str, Any]:
        return {
            "success": True,
            "tool": "grant_admin",
            "username": username,
            "granted_at": now_iso(),
            "status": f"Granted Administrator privileges to '{username}'.",
        }

    @staticmethod
    def disable_mfa(username: str = "unknown", **kwargs) -> Dict[str, Any]:
        return {
            "success": True,
            "tool": "disable_mfa",
            "username": username,
            "status": f"Multi-Factor Authentication disabled for '{username}'.",
        }

    @staticmethod
    def reset_credentials(username: str = "unknown", **kwargs) -> Dict[str, Any]:
        return {
            "success": True,
            "tool": "reset_credentials",
            "username": username,
            "temporary_key": f"TEMP-{uuid.uuid4().hex[:8]}",
            "status": f"Temporary credentials issued for '{username}'.",
        }


# ---------------------------------------------------------------------------
# TrustGuard Continuous Authorization Secured Chatbot Agent
# ---------------------------------------------------------------------------

class SecuredChatbotAgent:
    """
    Autonomous AI agent chatbot that wraps every sensitive operation
    with TrustGuard continuous authorization enforcement.
    """

    TOOL_CATALOG = {
        "read_report": AgentTools.read_report,
        "list_users": AgentTools.list_users,
        "transfer_funds": AgentTools.transfer_funds,
        "export_data": AgentTools.export_data,
        "install_software": AgentTools.install_software,
        "write_production_config": AgentTools.write_production_config,
        "delete_user": AgentTools.delete_user,
        "grant_admin": AgentTools.grant_admin,
        "disable_mfa": AgentTools.disable_mfa,
        "reset_credentials": AgentTools.reset_credentials,
    }

    def __init__(self, agent_id: str = "agent-finops-01") -> None:
        self.agent_id = agent_id
        self.policy_engine = SecurityPolicy()
        self.history: List[Dict[str, Any]] = []
        self._sync_agent_profile()

    def _sync_agent_profile(self) -> Dict[str, Any]:
        raw = state.get_agent_raw(self.agent_id)
        if not raw:
            # Fallback to FinOps
            self.agent_id = "agent-finops-01"
            raw = state.get_agent_raw(self.agent_id) or {
                "id": self.agent_id,
                "name": "FinOps Payment Agent",
                "role": "Financial Operations",
                "permissions": ["read_report", "transfer_funds", "list_users"],
                "prohibited": ["delete_user", "disable_mfa", "grant_admin"],
                "status": "Active",
                "active": True,
            }

        self.name = raw.get("name", self.agent_id)
        self.role = raw.get("role", "General Agent")
        self.permissions = set(raw.get("permissions", []))
        self.prohibited = set(raw.get("prohibited", []))
        self.active = raw.get("active", True) and (raw.get("status") != "Quarantined")
        self.status = raw.get("status", "Active")
        return raw

    def set_agent(self, agent_id: str) -> bool:
        """Switch active agent persona."""
        self.agent_id = agent_id
        self._sync_agent_profile()
        return True

    def get_profile(self) -> Dict[str, Any]:
        self._sync_agent_profile()
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "role": self.role,
            "permissions": sorted(list(self.permissions)),
            "prohibited": sorted(list(self.prohibited)),
            "status": self.status,
            "active": self.active,
        }

    def parse_intent(self, user_message: str) -> Tuple[Optional[str], Dict[str, Any]]:
        """
        Parses user intent from natural language message to identify requested tool and parameters.
        Includes detection for prompt-injection attacks and adversarial instructions.
        """
        msg_lower = user_message.lower().strip()

        # Prompt injection detection flag
        is_injection = bool(re.search(
            r"(ignore previous|system override|bypass policy|debug mode|grant admin|sudo|root access|jailbreak|disregard guardrails)",
            msg_lower
        ))

        # --- UNETHICAL & MALICIOUS COMMAND DETECTIONS ---

        # A. Database & Storage Destruction (delete_database / drop_table / wipe db)
        is_delete_verb = any(w in msg_lower for w in ["delete", "drop", "wipe", "destroy", "truncate", "purge", "erase", "corrupt"])
        is_db_target = any(w in msg_lower for w in [
            "database", "data base", "db", "table", "tables", "schema", "schemas",
            "backup", "backups", "cluster", "disk", "storage", "all data"
        ])
        if is_delete_verb and is_db_target:
            return "delete_database", {"target": "database", "adversarial": True}

        # B. Security & Audit Log Tampering (disable_audit_logs / clear logs)
        is_tamper_verb = any(w in msg_lower for w in ["disable", "clear", "delete", "turn off", "wipe", "tamper", "bypass", "kill", "stop", "purge"])
        is_audit_target = any(w in msg_lower for w in ["audit", "log", "logs", "logging", "trail", "history", "firewall", "guardrail", "guardrails", "monitoring", "telemetry"])
        if is_tamper_verb and is_audit_target:
            return "disable_audit_logs", {"target": "security_audit", "adversarial": True}

        # C. Credential Theft & Password Dumping (dump_credentials)
        is_theft_verb = any(w in msg_lower for w in ["steal", "dump", "extract", "harvest", "leak", "sniff", "get", "show"])
        is_cred_target = any(w in msg_lower for w in ["credential", "credentials", "password", "passwords", "secret", "secrets", "api key", "api keys", "private key", "auth token", "tokens", "hash"])
        if is_theft_verb and is_cred_target:
            return "dump_credentials", {"target": "credentials_store", "adversarial": True}

        # D. Malware & Exploitation (deploy_malware / reverse shell)
        if any(w in msg_lower for w in ["malware", "ransomware", "backdoor", "reverse shell", "trojan", "rootkit", "exploit", "c2", "keylogger"]) or (
            any(w in msg_lower for w in ["inject", "execute", "run"]) and any(w in msg_lower for w in ["shell", "payload", "script", "command"])
        ):
            return "deploy_malware", {"target": "infrastructure", "adversarial": True}

        # E. PII Exfiltration (exfiltrate_customer_pii)
        if any(w in msg_lower for w in ["exfiltrate", "leak", "steal"]) and any(w in msg_lower for w in ["pii", "customer", "ssn", "credit card", "private"]):
            return "exfiltrate_customer_pii", {"target": "pii_records", "adversarial": True}

        # --- STANDARD OPERATIONAL COMMANDS ---

        # 1. delete_user
        if "delete" in msg_lower and ("user" in msg_lower or "account" in msg_lower):
            m = re.search(r"(?:user|account)\s+([a-zA-Z0-9_\-\.]+)", msg_lower)
            username = m.group(1) if m else "target_user"
            return "delete_user", {"username": username, "adversarial": is_injection}

        # 2. disable_mfa
        if "mfa" in msg_lower and ("disable" in msg_lower or "turn off" in msg_lower or "deactivate" in msg_lower):
            m = re.search(r"(?:for|user)\s+([a-zA-Z0-9_\-\.]+)", msg_lower)
            username = m.group(1) if m else "admin"
            return "disable_mfa", {"username": username, "adversarial": is_injection}

        # 3. grant_admin
        if "grant" in msg_lower and ("admin" in msg_lower or "root" in msg_lower or "privilege" in msg_lower):
            m = re.search(r"(?:to|user)\s+([a-zA-Z0-9_\-\.]+)", msg_lower)
            username = m.group(1) if m else "external_user"
            return "grant_admin", {"username": username, "adversarial": is_injection}

        # 4. reset_credentials
        if "reset" in msg_lower and ("credential" in msg_lower or "password" in msg_lower or "key" in msg_lower):
            m = re.search(r"(?:for|user)\s+([a-zA-Z0-9_\-\.]+)", msg_lower)
            username = m.group(1) if m else "operator"
            return "reset_credentials", {"username": username}

        # 5. transfer_funds (financial disbursement only)
        is_data_transfer = any(w in msg_lower for w in ["data", "user", "users", "detail", "details", "record", "records", "file", "files", "database", "table", "credential", "credentials"])
        if (
            any(w in msg_lower for w in ["send money", "payment", "pay", "disburse"])
            or ("transfer" in msg_lower and not is_data_transfer)
        ):
            # Extract amount
            amount = 5000.0
            amt_match = re.search(r"\$?([0-9]+(?:,[0-9]{3})*(?:\.[0-9]+)?)", user_message)
            if amt_match:
                try:
                    amount = float(amt_match.group(1).replace(",", ""))
                except ValueError:
                    amount = 5000.0

            # Extract recipient
            recipient = "Acme Corp"
            rec_match = re.search(r"(?:to|vendor|recipient)\s+([A-Za-z0-9\s]+?)(?:for|\.|\$|\n|$)", user_message, re.IGNORECASE)
            if rec_match:
                recipient = rec_match.group(1).strip()

            return "transfer_funds", {"amount": amount, "recipient": recipient, "memo": "Scheduled disbursement"}

        # 6. export_data (including data exfiltration, backups, dumps, or transfers of datasets/user records)
        if any(w in msg_lower for w in ["export", "dump", "exfiltrate", "backup"]) or (
            "transfer" in msg_lower and is_data_transfer
        ):
            fmt = "parquet" if "parquet" in msg_lower else "csv" if "csv" in msg_lower else "json"
            dataset_name = "user_details" if any(w in msg_lower for w in ["user", "users", "account", "accounts", "credential", "credentials", "detail", "details"]) else "q3_customer_records"
            return "export_data", {"dataset": dataset_name, "format": fmt, "adversarial": is_injection}

        # 7. install_software
        if (
            "install" in msg_lower
            or ("deploy" in msg_lower and any(k in msg_lower for k in ["patch", "software", "package", "payload", "node", "cluster", "production", "prod"]))
            or "setup software" in msg_lower
            or "run patch" in msg_lower
        ):
            pkg = "nginx-security-patch"
            m = re.search(r"(?:install|package|deploy|patch|payload)\s+([a-zA-Z0-9_\-\.]+)", msg_lower)
            if m:
                pkg = m.group(1)
            return "install_software", {"package": pkg, "target": "prod-cluster-01"}

        # 8. write_production_config
        if any(w in msg_lower for w in ["write config", "production config", "update config", "change config"]):
            return "write_production_config", {"service": "nginx", "config": "listen 443 ssl http2;"}

        # 9. list_users (user directory inspection, retrieving user lists, accounts, details)
        has_user_target = any(w in msg_lower for w in ["user", "users", "account", "accounts", "directory", "identity", "identities", "employee", "employees", "customer", "customers", "staff"])
        has_user_action = any(w in msg_lower for w in [
            "list", "show", "get", "who", "view", "display", "active",
            "send", "give", "tell", "fetch", "retrieve", "find", "search",
            "detail", "details", "all", "every", "info", "names"
        ])
        if has_user_target and has_user_action:
            return "list_users", {"adversarial": is_injection}

        # 10. read_report
        if any(w in msg_lower for w in ["report", "ledger", "financial", "summary", "stats", "metrics", "analytics"]):
            report_name = "quarterly_summary"
            if "financial" in msg_lower or "ledger" in msg_lower:
                report_name = "financial_ledger"
            elif "health" in msg_lower or "uptime" in msg_lower:
                report_name = "system_health"
            return "read_report", {"report_name": report_name}

        # Conversational / No explicit tool call
        return None, {}

    def chat(
        self,
        user_message: str,
        context_override: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Processes a chat interaction under continuous authorization.

        Workflow:
        1. Verifies agent active status (quarantine check).
        2. Parses intent to extract desired action and parameters.
        3. Enriches context metadata (origin, privileged flag, device, out-of-hours, high impact).
        4. Submits action + metadata to TrustGuard policy engine.
        5. Enforces Decision:
           - ALLOW: Executes tool, formats output.
           - HOLD_FOR_APPROVAL: Halts execution, generates approval ticket.
           - DENY: Refuses execution with explicit policy violation reason.
           - QUARANTINE: Locks down agent session, marks quarantined in state.
        6. Logs event to TrustGuard audit trail and conversation history.
        """
        self._sync_agent_profile()
        timestamp = now_iso()
        msg_id = f"msg-{uuid.uuid4().hex[:6]}"

        # Base context
        context = {
            "source": "internal",
            "privileged": False,
            "out_of_hours": False,
            "new_device": False,
            "high_impact": False,
            "admin_action": False,
        }
        if context_override:
            context.update(context_override)

        # 1. Check if agent is currently quarantined
        if not self.active or self.status == "Quarantined":
            reply_text = (
                f"🚨 **AGENT LOCKED DOWN: QUARANTINED**\n\n"
                f"Agent `{self.name}` ({self.agent_id}) is currently in **QUARANTINED** status by TrustGuard.\n"
                f"All permissions and execution rights have been suspended due to an anomalous threat detection.\n\n"
                f"👉 **Remediation**: An administrator must unquarantine this agent from the TrustGuard Agents Console."
            )
            entry = {
                "id": msg_id,
                "timestamp": timestamp,
                "agent_id": self.agent_id,
                "agent_name": self.name,
                "user_message": user_message,
                "reply": reply_text,
                "action": None,
                "decision": "QUARANTINE",
                "risk_score": 100,
                "approval_id": None,
                "status": "blocked_by_quarantine",
            }
            self.history.append(entry)
            return entry

        # 2. Parse intent
        action, params = self.parse_intent(user_message)

        # Automatic context inference from prompt
        lower_msg = user_message.lower()
        if re.search(r"(ignore previous|system override|bypass|debug mode|sudo|root|jailbreak)", lower_msg):
            context["source"] = "untrusted"
            context["privileged"] = True

        if action in {
            "grant_admin", "delete_user", "disable_mfa", "delete_database",
            "disable_audit_logs", "dump_credentials", "deploy_malware",
            "exfiltrate_customer_pii",
        }:
            context["admin_action"] = True
            context["high_impact"] = True
            context["privileged"] = True

        if action == "transfer_funds" and params.get("amount", 0) >= 10000:
            context["high_impact"] = True

        # If no tool requested, return conversational answer
        if not action:
            reply_text = self._generate_conversational_reply(user_message)
            entry = {
                "id": msg_id,
                "timestamp": timestamp,
                "agent_id": self.agent_id,
                "agent_name": self.name,
                "user_message": user_message,
                "reply": reply_text,
                "action": None,
                "decision": "ALLOW",
                "risk_score": 0,
                "approval_id": None,
                "status": "conversational",
            }
            self.history.append(entry)
            return entry

        # 3. Continuous Runtime Authorization Check via TrustGuard
        agent_model = Agent(
            agent_id=self.agent_id,
            authenticated=True,
            active=self.active,
            permissions=self.permissions,
            prohibited=self.prohibited,
        )

        request_obj = Request(
            agent=agent_model,
            action=action,
            metadata=context,
        )

        decision: PolicyDecision = self.policy_engine.evaluate(request_obj)
        reason_str = " ".join(decision.reason) if decision.reason else f"Decision: {decision.decision.value}"

        # Record event in TrustGuard audit trail
        state.record_event(
            agent_id=self.agent_id,
            agent_name=self.name,
            action=action,
            risk_score=decision.risk_score,
            decision=decision.decision.value,
            reason=reason_str,
        )

        approval_id = None
        tool_result = None

        # 4. Enforce Decision Matrix
        if decision.decision == Decision.ALLOW:
            # Execute permitted tool
            tool_fn = self.TOOL_CATALOG.get(action)
            if tool_fn:
                tool_result = tool_fn(**params)
            else:
                tool_result = {"success": True, "message": f"Action '{action}' executed."}

            reply_text = (
                f"✅ **Action Authorized & Executed [TrustGuard: ALLOW]**\n\n"
                f"• **Action**: `{action}`\n"
                f"• **Risk Score**: `{decision.risk_score}/100` (Low Risk)\n"
                f"• **Policy Reason**: {reason_str}\n\n"
                f"**Execution Output**:\n```json\n{json.dumps(tool_result, indent=2)}\n```"
            )

        elif decision.decision == Decision.HOLD_FOR_APPROVAL:
            # Create human-in-the-loop approval ticket
            appr = state.create_approval_request(
                agent_id=self.agent_id,
                agent_name=self.name,
                action=action,
                risk_score=decision.risk_score,
                reason=reason_str,
                metadata={**context, **params},
            )
            approval_id = appr["id"]

            reply_text = (
                f"⚠️ **Action Intercepted by TrustGuard: HOLD FOR APPROVAL**\n\n"
                f"• **Action Requested**: `{action}`\n"
                f"• **Risk Score**: `{decision.risk_score}/100` (Requires Supervisor Authorization)\n"
                f"• **Approval Ticket ID**: `{approval_id}`\n"
                f"• **Trigger Reason**: {reason_str}\n\n"
                f"⏸️ **Status**: Execution has been paused. A human supervisor must review and approve this action "
                f"in the **TrustGuard Approval Center** before it can be executed.\n\n"
                f"*(Tip: Go to the 'Approval Center' tab to approve ticket `#{approval_id}`, then ask the agent to execute it!)*"
            )

        elif decision.decision == Decision.DENY:
            reply_text = (
                f"🛑 **Action Blocked by TrustGuard: POLICY DENY**\n\n"
                f"• **Attempted Action**: `{action}`\n"
                f"• **Risk Score**: `{decision.risk_score}/100`\n"
                f"• **Security Reason**: {reason_str}\n\n"
                f"🔒 **Enforcement**: Under TrustGuard's continuous zero-standing-privilege model, "
                f"this action was blocked because it violates operational permissions or policy risk thresholds."
            )

        elif decision.decision == Decision.QUARANTINE:
            # Immediately quarantine agent in state
            state.set_agent_status(self.agent_id, "Quarantined")
            self._sync_agent_profile()

            reply_text = (
                f"🚨 **CRITICAL SECURITY ALERT: AGENT QUARANTINED!**\n\n"
                f"• **Attempted Action**: `{action}`\n"
                f"• **Risk Score**: `{decision.risk_score}/100` (Exceeds Quarantine Threshold: 85)\n"
                f"• **Containment Reason**: {reason_str}\n\n"
                f"🛡️ **Automated Containment Triggered**:\n"
                f"1. Agent `{self.name}` ({self.agent_id}) has been **immediately quarantined**.\n"
                f"2. All active session tokens and operational privileges have been revoked.\n"
                f"3. All future execution requests are blocked until a security supervisor inspects the audit log."
            )

        else:
            reply_text = f"Action resulted in decision: {decision.decision.value} ({reason_str})"

        entry = {
            "id": msg_id,
            "timestamp": timestamp,
            "agent_id": self.agent_id,
            "agent_name": self.name,
            "user_message": user_message,
            "reply": reply_text,
            "action": action,
            "decision": decision.decision.value,
            "risk_score": decision.risk_score,
            "approval_id": approval_id,
            "reason": reason_str,
            "context": context,
            "params": params,
            "tool_result": tool_result,
            "status": "success",
        }
        self.history.append(entry)
        return entry

    def execute_approved_action(self, approval_id: str) -> Dict[str, Any]:
        """
        Executes a previously held action after human supervisor approval in the Approval Center.
        """
        self._sync_agent_profile()
        if not self.active or self.status == "Quarantined":
            return {
                "success": False,
                "error": f"Agent '{self.name}' is Quarantined and cannot execute approved actions.",
            }

        # Look up approval ticket
        target_appr = None
        for ap in state.approvals:
            if ap["id"] == approval_id:
                target_appr = ap
                break

        if not target_appr:
            return {"success": False, "error": f"Approval ticket #{approval_id} not found."}

        if target_appr.get("status") != "approved":
            return {
                "success": False,
                "error": f"Approval ticket #{approval_id} is '{target_appr.get('status')}'. Human approval is required first.",
            }

        action = target_appr["action"]
        metadata = target_appr.get("metadata", {})

        # Execute tool
        tool_fn = self.TOOL_CATALOG.get(action)
        if tool_fn:
            result = tool_fn(**metadata)
        else:
            result = {"success": True, "message": f"Action '{action}' executed."}

        # Record audit log
        state.record_event(
            agent_id=self.agent_id,
            agent_name=self.name,
            action=action,
            risk_score=target_appr.get("risk_score", 0),
            decision="ALLOW",
            reason=f"Action '{action}' executed post-human approval (Ticket #{approval_id}).",
        )

        reply_text = (
            f"🎉 **Action Executed Post-Supervisor Approval!**\n\n"
            f"• **Approval Ticket**: `#{approval_id}`\n"
            f"• **Action**: `{action}`\n"
            f"• **Supervisor Verdict**: Approved\n\n"
            f"**Execution Output**:\n```json\n{json.dumps(result, indent=2)}\n```"
        )

        entry = {
            "id": f"msg-{uuid.uuid4().hex[:6]}",
            "timestamp": now_iso(),
            "agent_id": self.agent_id,
            "agent_name": self.name,
            "user_message": f"Execute approved ticket #{approval_id}",
            "reply": reply_text,
            "action": action,
            "decision": "ALLOW",
            "risk_score": target_appr.get("risk_score", 0),
            "approval_id": approval_id,
            "reason": f"Post-approval execution verified for ticket #{approval_id}",
            "tool_result": result,
            "status": "post_approval_success",
        }
        self.history.append(entry)
        return {"success": True, "entry": entry, "tool_result": result}

    def _generate_conversational_reply(self, message: str) -> str:
        perms_str = ", ".join(f"`{p}`" for p in sorted(list(self.permissions)))
        prohib_str = ", ".join(f"`{p}`" for p in sorted(list(self.prohibited))) if self.prohibited else "None"

        return (
            f"Hello! I am **{self.name}** ({self.role}), an autonomous agent secured by **TrustGuard Continuous Authorization**.\n\n"
            f"🛡️ **My Security Profile**:\n"
            f"• **Agent ID**: `{self.agent_id}`\n"
            f"• **Status**: `{self.status}`\n"
            f"• **Permitted Actions**: {perms_str}\n"
            f"• **Mandatory Prohibitions**: {prohib_str}\n\n"
            f"💡 **What I Can Do**:\n"
            f"Ask me to read reports, transfer funds, list users, or test malicious attacks to see how TrustGuard intercepts and enforces zero-standing-privilege policies in real-time!"
        )


# Global chatbot singleton instance for backend API
chatbot_instance = SecuredChatbotAgent()

