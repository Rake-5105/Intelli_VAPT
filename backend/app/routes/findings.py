"""Vulnerability finding routes with authorization guards and audit logging."""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..audit import log_security_event
from ..auth import current_user, require, verify_project_access
from ..models import Asset, Finding, Project, Role, User, get_db
from ..schemas import FindingOut, FindingUpdate
from ..serializers import serialize_finding

router = APIRouter(tags=["Findings"])


@router.get("/api/projects/{project_id}/vulnerabilities", response_model=list[FindingOut])
def findings(project_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """List all vulnerability findings for a project with authorization check."""
    project = db.get(Project, project_id)
    verify_project_access(project, user, "view vulnerabilities for")

    return [serialize_finding(f) for f in db.query(Finding).filter_by(project_id=project_id)]


@router.get("/api/vulnerabilities/{finding_id}", response_model=FindingOut)
def finding(finding_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Retrieve a single finding by ID with authorization check."""
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    project = db.get(Project, f.project_id)
    verify_project_access(project, user, "view this vulnerability on")

    return serialize_finding(f)


@router.patch("/api/vulnerabilities/{finding_id}", response_model=FindingOut)
def update_finding(
    finding_id: str,
    data: FindingUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.ADMIN, Role.SECURITY_ANALYST)),
):
    """Update a finding's status and optionally its remediation notes with authorization check."""
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    project = db.get(Project, f.project_id)
    verify_project_access(project, user, "update findings on")

    old_status = f.finding_status
    f.finding_status = data.finding_status
    if data.remediation is not None:
        f.remediation = data.remediation
    f.last_seen = datetime.now(UTC)
    db.commit()

    log_security_event(
        db,
        action="UPDATE_FINDING_STATUS",
        resource_type="finding",
        resource_id=f.id,
        detail=f"Changed finding '{f.title}' status from {old_status} to {f.finding_status} in project '{project.name}'",
        user=user,
        request=request,
    )

    return serialize_finding(f)


@router.get("/api/projects/{project_id}/attack-surface", response_model=None)
def attack_surface(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Generate attack-surface graph data linking assets and findings with authorization check."""
    project = db.get(Project, project_id)
    verify_project_access(project, user, "view attack surface on")

    project_assets = db.query(Asset).filter_by(project_id=project_id).all()
    project_findings = db.query(Finding).filter_by(project_id=project_id).all()

    nodes = [{"id": "internet", "label": "Internet", "type": "root"}]
    edges = []

    for a in project_assets:
        nodes.append({"id": a.id, "label": a.hostname, "type": "asset"})
        edges.append({"source": "internet", "target": a.id})

    for f in project_findings:
        nodes.append({"id": f.id, "label": f.title, "type": f.severity.lower()})
        if f.asset_id:
            edges.append({"source": f.asset_id, "target": f.id})

    return {"nodes": nodes, "edges": edges}
