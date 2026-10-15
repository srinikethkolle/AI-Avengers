import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Set

import jwt
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("APP_SECRET_KEY", "dev-secret-key-change-in-production-12345")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Demonstration agent/user database
USER_DB: Dict[str, Dict[str, Any]] = {
    "alice": {
        "password": "secret123",
        "active": True,
        "permissions": {"read_report", "list_users"},
        "prohibited": {"delete_user"},
    },
    "admin": {
        "password": "adminsecret123",
        "active": True,
        "permissions": {
            "read_report",
            "list_users",
            "export_data",
            "grant_admin",
            "delete_user",
        },
        "prohibited": set(),
    },
    "agent-finops-01": {
        "password": "agentsecret123",
        "active": True,
        "permissions": {"read_report", "transfer_funds", "list_users"},
        "prohibited": {"delete_user", "disable_mfa", "grant_admin"},
    },
    "agent-support-02": {
        "password": "agentsecret123",
        "active": True,
        "permissions": {"read_report", "list_users"},
        "prohibited": {"delete_user", "export_data", "transfer_funds"},
    },
    "agent-devops-03": {
        "password": "agentsecret123",
        "active": True,
        "permissions": {"read_report", "install_software", "write_production_config"},
        "prohibited": {"delete_user", "disable_mfa"},
    },
    "agent-analyst-04": {
        "password": "agentsecret123",
        "active": True,
        "permissions": {"read_report", "export_data"},
        "prohibited": {"delete_user", "write_production_config"},
    },
    "agent-compromised-05": {
        "password": "agentsecret123",
        "active": False,
        "permissions": {"read_report"},
        "prohibited": {"grant_admin", "delete_user", "transfer_funds"},
    },
}


def verify_password(username: str, password: str) -> bool:
    user = USER_DB.get(username)
    if not user or not user.get("active"):
        return False

    stored_password = user.get("password", "")
    return secrets.compare_digest(password, stored_password)


def issue_token(
    agent_id: str,
    permissions: Optional[Set[str]] = None,
    prohibited: Optional[Set[str]] = None,
) -> str:
    user = USER_DB.get(agent_id)
    if not user or not user.get("active"):
        raise PermissionError("Unknown or inactive user")

    actual_permissions = permissions if permissions is not None else user.get("permissions", set())
    actual_prohibited = prohibited if prohibited is not None else user.get("prohibited", set())

    payload = {
        "sub": agent_id,
        "permissions": sorted(list(actual_permissions)),
        "prohibited": sorted(list(actual_prohibited)),
        "active": True,
        "exp": (
            datetime.now(timezone.utc)
            + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        ),
    }

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def authenticate_token(token: str) -> Dict[str, Any]:
    # Support tokens passed as "Bearer <token>" or raw token
    if token.startswith("Bearer "):
        token = token[7:].strip()

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        if not payload.get("sub"):
            raise ValueError("Missing user identity in token")

        if payload.get("active") is not True:
            raise ValueError("User identity is inactive")

        return payload

    except jwt.ExpiredSignatureError as exc:
        raise PermissionError("Token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise PermissionError("Invalid token signature or format") from exc
    except Exception as exc:
        raise PermissionError(f"Authentication failed: {exc}") from exc