"""Remediation task routes with authorization guards and audit logging."""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..audit import log_security_event
from ..auth import current_user, require, verify_project_access
from ..models import Finding, Project, RemediationTask, Role, User, get_db
from ..schemas import RemediationIn, RemediationListOut, RemediationOut

router = APIRouter(tags=["Remediation"])


@router.post("/api/vulnerabilities/{finding_id}/remediation", response_model=RemediationOut)
def remediate(
    finding_id: str,
    data: RemediationIn,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.ADMIN, Role.SECURITY_ANALYST)),
):
    """Create or update a remediation task for a finding with authorization check."""
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")

    project = db.get(Project, f.project_id)
    verify_project_access(project, user, "assign remediation on")

    task = db.query(RemediationTask).filter_by(finding_id=finding_id).first() or RemediationTask(
        finding_id=finding_id
    )
    task.assigned_to = data.assigned_to
    task.due_date = data.due_date
    task.notes = data.notes
    task.status = data.status
    db.add(task)
    db.commit()
    db.refresh(task)

    log_security_event(
        db,
        action="ASSIGN_REMEDIATION",
        resource_type="remediation_task",
        resource_id=task.id,
        detail=f"Assigned remediation for finding '{f.title}' to '{task.assigned_to}' (due: {task.due_date}) in project '{project.name}'",
        user=user,
        request=request,
    )

    return {
        "id": task.id,
        "finding_id": task.finding_id,
        "status": task.status,
        "assigned_to": task.assigned_to,
        "due_date": task.due_date,
        "notes": task.notes,
    }


@router.get("/api/projects/{project_id}/remediation", response_model=list[RemediationListOut])
def remediation(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """List all remediation tasks for a project's findings with authorization check."""
    project = db.get(Project, project_id)
    verify_project_access(project, user, "view remediation tasks on")

    return [
        {
            "id": t.id,
            "finding_id": t.finding_id,
            "title": f.title,
            "severity": f.severity,
            "status": t.status,
            "assigned_to": t.assigned_to,
            "due_date": t.due_date,
            "notes": t.notes,
        }
        for t in db.query(RemediationTask).join(Finding).filter(Finding.project_id == project_id)
        for f in [db.get(Finding, t.finding_id)]
        if f
    ]
