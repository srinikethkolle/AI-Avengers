from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field



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
    prohibited: Set[str] = field(default_factory=set)

    @property
    def mandatory_prohibitions(self) -> Set[str]:
        return self.prohibited


@dataclass
class Request:
    agent: Agent
    action: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyDecision:
    decision: Decision
    reason: List[str]
    risk_score: int = 0
    approval_required: bool = False
    restriction: Restriction = Restriction.NONE


# ---------------------------------------------------------------------------
# API Request / Response Schemas (Pydantic)
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class EvaluateRequest(BaseModel):
    action: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EvaluateResponse(BaseModel):
    decision: Decision
    reason: List[str]
    risk_score: int
    approval_required: bool
    restriction: Restriction = Restriction.NONE


class ApprovalDecisionRequest(BaseModel):
    decision: str


class DirectEvaluateRequest(BaseModel):
    agent_id: str
    action: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentCreateRequest(BaseModel):
    agent_id: str
    name: str
    role: str
    permissions: List[str]
    prohibited: List[str] = Field(default_factory=list)


class PolicyConfigUpdate(BaseModel):
    risk_threshold: Optional[int] = None
    quarantine_threshold: Optional[int] = None
    approval_threshold: Optional[int] = None


class ChatRequest(BaseModel):
    agent_id: Optional[str] = "agent-finops-01"
    message: str
    context: Optional[Dict[str, Any]] = None


class ExecuteApprovedRequest(BaseModel):
    approval_id: str
    agent_id: Optional[str] = None


