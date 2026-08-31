"""Asset inventory routes."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..auth import current_user
from ..models import Asset, User, get_db
from ..schemas import AssetDetailOut, AssetOut

router = APIRouter(tags=["Assets"])


@router.get("/api/projects/{project_id}/assets", response_model=list[AssetOut])
def assets(project_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """List all discovered assets for a project."""
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
    """Retrieve a single asset by ID."""
    a = db.get(Asset, asset_id)
    if not a:
        raise HTTPException(404, "Asset not found")
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
