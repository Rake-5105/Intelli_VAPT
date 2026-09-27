"""Asset inventory routes with authorization guards."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..auth import current_user, verify_project_access
from ..models import Asset, Project, User, get_db
from ..schemas import AssetDetailOut, AssetOut

router = APIRouter(tags=["Assets"])


@router.get("/api/projects/{project_id}/assets", response_model=list[AssetOut])
def assets(project_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """List all discovered assets for a project with authorization check."""
    project = db.get(Project, project_id)
    verify_project_access(project, user, "view assets on")

    return [
        {
            "id": a.id,
            "hostname": a.hostname,
            "type": a.asset_type,
            "ip": a.ip_address,
            "http_status": a.http_status,
            "title": a.title,
            "technologies": a.technologies,
            "criticality": a.criticality,
            "last_seen": a.last_seen,
        }
        for a in db.query(Asset).filter_by(project_id=project_id)
    ]


@router.get("/api/assets/{asset_id}", response_model=AssetDetailOut)
def asset(asset_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Retrieve a single asset by ID with authorization check."""
    a = db.get(Asset, asset_id)
    if not a:
        raise HTTPException(404, "Asset not found")

    project = db.get(Project, a.project_id)
    verify_project_access(project, user, "view this asset on")

    return {
        "id": a.id,
        "hostname": a.hostname,
        "type": a.asset_type,
        "ip": a.ip_address,
        "http_status": a.http_status,
        "title": a.title,
        "technologies": a.technologies,
        "criticality": a.criticality,
    }
