"""Pydantic request and response schemas for IntelliVAPT API."""

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class Register(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class Login(BaseModel):
    email: EmailStr
    password: str


class ProjectIn(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    client: str = ""
    description: str = ""
    assessment_type: str = "Web Application VAPT"


class TargetIn(BaseModel):
    value: str = Field(min_length=3, max_length=512)
    excluded: bool = False


class ScanIn(BaseModel):
    profile: str = Field(default="SAFE", pattern="^(SAFE|BALANCED|AGGRESSIVE)$")


class FindingUpdate(BaseModel):
    finding_status: str = Field(
        pattern="^(OPEN|CONFIRMED|FALSE_POSITIVE|IN_PROGRESS|REMEDIATED|ACCEPTED_RISK)$"
    )
    remediation: str | None = None


class RemediationIn(BaseModel):
    assigned_to: str = ""
    due_date: str = ""
    notes: str = ""
    status: str = "OPEN"


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------

class UserOut(BaseModel):
    id: str
    name: str
    email: str
    role: str


class AuthOut(BaseModel):
    access_token: str
    user: UserOut


class ProjectOut(BaseModel):
    id: str
    name: str
    client: str
    description: str
    assessment_type: str
    status: str
    created_at: datetime
    targets: int
    scans: int


class TargetOut(BaseModel):
    id: str
    value: str
    type: str
    excluded: bool


class ScanOut(BaseModel):
    id: str
    status: str
    progress: int


class ScanDetailOut(BaseModel):
    id: str
    status: str
    progress: int
    created_at: datetime


class ScanListOut(BaseModel):
    id: str
    status: str
    profile: str
    progress: int
    created_at: datetime


class ScanLogOut(BaseModel):
    scan_id: str
    log: str


class AssetOut(BaseModel):
    id: str
    hostname: str
    type: str
    ip: str
    http_status: int | None
    title: str
    technologies: str
    criticality: str
    last_seen: datetime | None = None


class AssetDetailOut(BaseModel):
    id: str
    hostname: str
    type: str
    ip: str
    http_status: int | None
    title: str
    technologies: str
    criticality: str


class FindingOut(BaseModel):
    id: str
    title: str
    description: str
    asset_id: str | None
    endpoint: str
    scanner: str
    severity: str
    cvss_score: float
    cwe: str
    cve: str
    owasp_category: str
    remediation: str
    status: str
    first_seen: datetime
    last_seen: datetime


class EvidenceOut(BaseModel):
    id: str
    type: str
    path: str
    sha256: str
    description: str
    created_at: datetime


class RemediationOut(BaseModel):
    id: str
    finding_id: str
    status: str
    assigned_to: str
    due_date: str
    notes: str


class RemediationListOut(BaseModel):
    id: str
    finding_id: str
    title: str
    severity: str
    status: str
    assigned_to: str
    due_date: str
    notes: str


class GraphNode(BaseModel):
    id: str
    label: str
    type: str


class GraphEdge(BaseModel):
    source: str
    target: str


class AttackSurfaceOut(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class ReportOut(BaseModel):
    id: str
    name: str
    format: str
    created_at: datetime


class ToolStatusOut(BaseModel):
    tool: str
    configured_path: str
    installed: bool
    path: str | None


class HealthOut(BaseModel):
    status: str
    demo_mode: bool
