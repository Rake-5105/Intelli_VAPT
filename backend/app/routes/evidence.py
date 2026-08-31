"""Evidence metadata routes."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..auth import current_user
from ..models import Evidence, User, get_db
from ..schemas import EvidenceOut

router = APIRouter(tags=["Evidence"])


@router.get("/api/projects/{project_id}/evidence", response_model=list[EvidenceOut])
def evidence(project_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """List all evidence records for a project."""
    return [
        {
            "id": e.id,
            "type": e.evidence_type,
            "path": e.path,
            "sha256": e.sha256,
            "description": e.description,
            "created_at": e.created_at,
        }
        for e in db.query(Evidence).filter_by(project_id=project_id)
    ]
