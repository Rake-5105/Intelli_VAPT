"""Project management routes."""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..auth import current_user, require
from ..models import AuditLog, Project, Role, User, get_db
from ..schemas import ProjectIn, ProjectOut
from ..serializers import serialize_project

router = APIRouter(prefix="/api/projects", tags=["Projects"])


def log_action(
    db: Session,
    user: User,
    action: str,
    resource_type: str,
    resource_id: str,
    detail: str = "",
    request: Request | None = None,
):
    ip = request.client.host if request and request.client else ""
    log_entry = AuditLog(
        user_id=user.id,
        user_email=user.email,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        detail=detail,
        ip_address=ip,
    )
    db.add(log_entry)


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
    log_action(db, user, "CREATE_PROJECT", "project", p.id, f"Created project '{p.name}'", request)
    db.commit()
    return serialize_project(p)


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(project_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Retrieve a single project by ID with access authorization check."""
    p = db.get(Project, project_id)
    if not p:
        raise HTTPException(404, "Project not found")
    if user.role != Role.ADMIN and p.owner_id != user.id:
        raise HTTPException(403, "Access to this project is forbidden")
    return serialize_project(p)


@router.delete("/{project_id}", status_code=204)
def delete_project(
    project_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.ADMIN, Role.SECURITY_ANALYST)),
):
    """Delete a project and all associated records."""
    p = db.get(Project, project_id)
    if not p:
        raise HTTPException(404, "Project not found")
    if user.role != Role.ADMIN and p.owner_id != user.id:
        raise HTTPException(403, "Cannot delete a project you do not own")
    log_action(db, user, "DELETE_PROJECT", "project", p.id, f"Deleted project '{p.name}'", request)
    db.delete(p)
    db.commit()

