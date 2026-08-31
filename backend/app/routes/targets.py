"""Target management routes."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..auth import current_user, require
from ..models import Project, Role, Target, User, get_db
from ..schemas import TargetIn, TargetOut
from ..serializers import classify_target

router = APIRouter(prefix="/api/projects/{project_id}/targets", tags=["Targets"])


@router.post("", status_code=201, response_model=TargetOut)
def add_target(
    project_id: str,
    data: TargetIn,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.ADMIN, Role.SECURITY_ANALYST)),
):
    """Add an authorized target to a project."""
    if not db.get(Project, project_id):
        raise HTTPException(404, "Project not found")

    value = data.value.strip().lower()
    target = Target(
        project_id=project_id,
        value=value,
        target_type=classify_target(value),
        excluded=data.excluded,
    )
    db.add(target)
    db.commit()

    return {"id": target.id, "value": target.value, "type": target.target_type, "excluded": target.excluded}


@router.get("", response_model=list[TargetOut])
def targets(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """List all targets for a project."""
    return [
        {"id": t.id, "value": t.value, "type": t.target_type, "excluded": t.excluded}
        for t in db.query(Target).filter_by(project_id=project_id)
    ]


@router.delete("/{target_id}", status_code=204)
def delete_target(
    project_id: str,
    target_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.ADMIN, Role.SECURITY_ANALYST)),
):
    """Delete a target from a project."""
    target = db.get(Target, target_id)
    if not target or target.project_id != project_id:
        raise HTTPException(404, "Target not found")
    db.delete(target)
    db.commit()


@router.patch("/{target_id}/toggle", response_model=TargetOut)
def toggle_target_exclusion(
    project_id: str,
    target_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.ADMIN, Role.SECURITY_ANALYST)),
):
    """Toggle in-scope vs excluded status of a target."""
    target = db.get(Target, target_id)
    if not target or target.project_id != project_id:
        raise HTTPException(404, "Target not found")
    target.excluded = not target.excluded
    db.commit()
    return {"id": target.id, "value": target.value, "type": target.target_type, "excluded": target.excluded}

