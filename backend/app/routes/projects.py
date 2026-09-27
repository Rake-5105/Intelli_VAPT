"""Project management routes with object-level authorization and security auditing."""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..audit import log_security_event
from ..auth import current_user, require, verify_project_access
from ..models import Project, Role, User, get_db
from ..schemas import ProjectIn, ProjectOut
from ..serializers import serialize_project

router = APIRouter(prefix="/api/projects", tags=["Projects"])


@router.get("", response_model=list[ProjectOut])
def projects(db: Session = Depends(get_db), user: User = Depends(current_user)):
    """List projects accessible to the caller (all for ADMIN, created/owned for others)."""
    if user.role == Role.ADMIN:
        return [serialize_project(p) for p in db.query(Project).all()]
    return [serialize_project(p) for p in db.query(Project).filter_by(owner_id=user.id).all()]


@router.post("", status_code=201, response_model=ProjectOut)
def create_project(
    request: Request,
    data: ProjectIn,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.ADMIN, Role.SECURITY_ANALYST)),
):
    """Create a new assessment project."""
    p = Project(**data.model_dump(), owner_id=user.id)
    db.add(p)
    db.commit()
    db.refresh(p)

    log_security_event(
        db,
        action="CREATE_PROJECT",
        resource_type="project",
        resource_id=p.id,
        detail=f"Created assessment project '{p.name}' for client '{p.client}'",
        user=user,
        request=request,
    )
    return serialize_project(p)


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(project_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Retrieve a single project by ID with object-level authorization."""
    p = db.get(Project, project_id)
    verify_project_access(p, user, "view")
    return serialize_project(p)


@router.delete("/{project_id}", status_code=204)
def delete_project(
    project_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.ADMIN, Role.SECURITY_ANALYST)),
):
    """Delete a project and all associated records with authorization check."""
    p = db.get(Project, project_id)
    verify_project_access(p, user, "delete")

    log_security_event(
        db,
        action="DELETE_PROJECT",
        resource_type="project",
        resource_id=p.id,
        detail=f"Permanently removed project '{p.name}' and all associated telemetry",
        user=user,
        request=request,
    )
    db.delete(p)
    db.commit()
