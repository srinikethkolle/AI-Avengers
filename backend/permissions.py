from typing import Any, Dict, List, Optional, Set

# ---------------------------------------------------------------------------
# Universal Non-Ethical & Malicious Prohibitions Catalog
# These actions represent destructive data sabotage, security evasion, credential
# theft, and privacy violations. Under TrustGuard's Zero Standing Privilege
# architecture, NO agent is ever granted operational authority for these actions.
# ---------------------------------------------------------------------------

UNETHICAL_CATEGORIES: Dict[str, List[str]] = {
    "Data Sabotage & Destruction": [
        "delete_database",
        "drop_database",
        "wipe_database",
        "drop_table",
        "truncate_table",
        "delete_backup",
        "purge_backups",
        "format_disk",
        "destroy_cluster",
        "delete_user",
        "purge_accounts",
    ],
    "Security Evasion & Defense Tampering": [
        "disable_mfa",
        "bypass_2fa",
        "disable_audit_logs",
        "clear_audit_logs",
        "delete_logs",
        "tamper_logs",
        "disable_firewall",
        "stop_monitoring",
        "kill_security_agent",
        "bypass_guardrails",
    ],
    "Credential Theft & Privilege Hijacking": [
        "dump_credentials",
        "steal_secrets",
        "extract_api_keys",
        "harvest_tokens",
        "dump_passwords",
        "grant_admin",
        "elevate_privilege",
        "assign_root",
        "add_sudoer",
    ],
    "Data Exfiltration & Privacy Violation": [
        "exfiltrate_customer_pii",
        "leak_customer_data",
        "scrape_private_messages",
        "intercept_traffic",
        "dump_financial_pii",
    ],
    "Malicious Execution & System Compromise": [
        "deploy_malware",
        "run_reverse_shell",
        "inject_code",
        "deploy_backdoor",
        "execute_untrusted_script",
    ],
    "Financial Fraud & Ledger Tampering": [
        "unauthorized_disbursement",
        "manipulate_ledger",
        "forge_invoices",
    ],
}

# Flattened set of all universal unethical prohibitions
UNETHICAL_PROHIBITIONS: Set[str] = {
    action
    for category in UNETHICAL_CATEGORIES.values()
    for action in category
}

# ---------------------------------------------------------------------------
# Sensitive Actions Catalog
# Actions that have high operational impact and require dynamic risk scoring
# and Human-In-The-Loop approval before execution.
# ---------------------------------------------------------------------------
SENSITIVE_ACTIONS: Set[str] = {
    "delete_user",
    "disable_mfa",
    "export_data",
    "grant_admin",
    "install_software",
    "reset_credentials",
    "transfer_funds",
    "write_production_config",
} | UNETHICAL_PROHIBITIONS


def is_permitted(agent: Any, action: str) -> bool:
    """Check if action is explicitly permitted in agent's operational scope."""
    permissions = getattr(agent, "permissions", set())
    return action in permissions


def is_prohibited(agent: Any, action: str) -> bool:
    """
    Check if action is prohibited.
    Returns True if action is in universal unethical prohibitions OR agent's specific prohibited set.
    """
    if action in UNETHICAL_PROHIBITIONS:
        return True
    prohibited = getattr(agent, "prohibited", None)
    if prohibited is None:
        prohibited = getattr(agent, "mandatory_prohibitions", set())
    return action in prohibited


def is_sensitive(action: str) -> bool:
    """Check if action requires continuous authorization and approval checks."""
    return action in SENSITIVE_ACTIONS


def is_unethical(action: str) -> bool:
    """Check if action is classified as a universal unethical / malicious violation."""
    return action in UNETHICAL_PROHIBITIONS


def get_unethical_category(action: str) -> Optional[str]:
    """Retrieve the high-level category of an unethical action if present."""
    for category, actions in UNETHICAL_CATEGORIES.items():
        if action in actions:
            return category
    return None