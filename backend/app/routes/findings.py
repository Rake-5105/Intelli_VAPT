"""Vulnerability finding routes."""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..auth import current_user, require
from ..models import Asset, Finding, Role, User, get_db
from ..schemas import FindingOut, FindingUpdate
from ..serializers import serialize_finding

router = APIRouter(tags=["Findings"])


@router.get("/api/projects/{project_id}/vulnerabilities", response_model=list[FindingOut])
def findings(project_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """List all vulnerability findings for a project."""
    return [serialize_finding(f) for f in db.query(Finding).filter_by(project_id=project_id)]


@router.get("/api/vulnerabilities/{finding_id}", response_model=FindingOut)
def finding(finding_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Retrieve a single finding by ID."""
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    return serialize_finding(f)


@router.patch("/api/vulnerabilities/{finding_id}", response_model=FindingOut)
def update_finding(
    finding_id: str,
    data: FindingUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.ADMIN, Role.SECURITY_ANALYST)),
):
    """Update a finding's status and optionally its remediation notes."""
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")

    f.finding_status = data.finding_status
    if data.remediation is not None:
        f.remediation = data.remediation
    f.last_seen = datetime.now(UTC)
    db.commit()

    return serialize_finding(f)


@router.get("/api/projects/{project_id}/attack-surface", response_model=None)
def attack_surface(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Generate attack-surface graph data linking assets and findings."""
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
