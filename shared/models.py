from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

@dataclass
class Endpoint:
    url: str
    method: str
    params: Dict[str, Any]
    auth_required: bool
    roles_allowed: List[str]

@dataclass
class AppMap:
    target_url: str
    endpoints: List[Endpoint]
    roles: List[str]

@dataclass
class AttackResult:
    endpoint: Endpoint
    payload: Dict[str, Any]
    response_code: int
    response_body: str
    diff_from_baseline: Optional[str]

@dataclass
class VulnReport:
    id: str
    type: str
    severity: str
    chain: List[AttackResult]
    narrative: str
    fp_score: float
    evidence: str

@dataclass
class RoleCredential:
    username: str
    password: str
    role: str
