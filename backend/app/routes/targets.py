"""Target management routes with object-level authorization and security auditing."""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..audit import log_security_event
from ..auth import current_user, require, verify_project_access
from ..models import Project, Role, Target, User, get_db
from ..schemas import TargetIn, TargetOut
from ..serializers import classify_target

router = APIRouter(prefix="/api/projects/{project_id}/targets", tags=["Targets"])


@router.post("", status_code=201, response_model=TargetOut)
def add_target(
    project_id: str,
    data: TargetIn,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.ADMIN, Role.SECURITY_ANALYST)),
):
    """Add an authorized target to a project with strict validation."""
    project = db.get(Project, project_id)
    verify_project_access(project, user, "modify targets on")

    value = data.value.strip().lower()
    target_type = classify_target(value)

    target = Target(
        project_id=project_id,
        value=value,
        target_type=target_type,
        excluded=data.excluded,
    )
    db.add(target)
    db.commit()
    db.refresh(target)

    log_security_event(
        db,
        action="ADD_TARGET",
        resource_type="target",
        resource_id=target.id,
        detail=f"Added target '{target.value}' ({target_type}, excluded={target.excluded}) to project '{project.name}'",
        user=user,
        request=request,
    )

    return {"id": target.id, "value": target.value, "type": target.target_type, "excluded": target.excluded}


@router.get("", response_model=list[TargetOut])
def targets(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """List all targets for a project with authorization check."""
    project = db.get(Project, project_id)
    verify_project_access(project, user, "view targets on")

    return [
        {"id": t.id, "value": t.value, "type": t.target_type, "excluded": t.excluded}
        for t in db.query(Target).filter_by(project_id=project_id)
    ]


@router.delete("/{target_id}", status_code=204)
def delete_target(
    project_id: str,
    target_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.ADMIN, Role.SECURITY_ANALYST)),
):
    """Delete a target from a project with authorization check."""
    project = db.get(Project, project_id)
    verify_project_access(project, user, "modify targets on")

    target = db.get(Target, target_id)
    if not target or target.project_id != project_id:
        raise HTTPException(404, "Target not found")

    log_security_event(
        db,
        action="DELETE_TARGET",
        resource_type="target",
        resource_id=target.id,
        detail=f"Removed target '{target.value}' from project '{project.name}'",
        user=user,
        request=request,
    )

    db.delete(target)
    db.commit()


@router.patch("/{target_id}/toggle", response_model=TargetOut)
def toggle_target_exclusion(
    project_id: str,
    target_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.ADMIN, Role.SECURITY_ANALYST)),
):
    """Toggle in-scope vs excluded status of a target with authorization check."""
    project = db.get(Project, project_id)
    verify_project_access(project, user, "modify targets on")

    target = db.get(Target, target_id)
    if not target or target.project_id != project_id:
        raise HTTPException(404, "Target not found")

    target.excluded = not target.excluded
    db.commit()

    log_security_event(
        db,
        action="TOGGLE_TARGET_SCOPE",
        resource_type="target",
        resource_id=target.id,
        detail=f"Updated target '{target.value}' scope (excluded={target.excluded}) in project '{project.name}'",
        user=user,
        request=request,
    )

    return {"id": target.id, "value": target.value, "type": target.target_type, "excluded": target.excluded}
