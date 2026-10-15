from typing import Any, Dict, Optional
from backend.permissions import is_sensitive


def calculate_risk(action: str, metadata: Optional[Dict[str, Any]] = None) -> int:
    score = 0
    meta = metadata or {}

    if is_sensitive(action):
        score += 35

    if meta.get("privileged"):
        score += 20

    if meta.get("source") in {"external", "untrusted"}:
        score += 15

    if meta.get("new_device"):
        score += 15

    if meta.get("unknown_user"):
        score += 10

    if meta.get("high_impact"):
        score += 20

    if meta.get("out_of_hours"):
        score += 10

    if meta.get("unusual_location"):
        score += 10

    if meta.get("admin_action"):
        score += 15

    return min(score, 100)