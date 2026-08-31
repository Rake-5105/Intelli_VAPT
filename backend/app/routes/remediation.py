"""Remediation task routes."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..auth import current_user, require
from ..models import Finding, RemediationTask, Role, User, get_db
from ..schemas import RemediationIn, RemediationListOut, RemediationOut

router = APIRouter(tags=["Remediation"])


@router.post("/api/vulnerabilities/{finding_id}/remediation", response_model=RemediationOut)
def remediate(
    finding_id: str,
    data: RemediationIn,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.ADMIN, Role.SECURITY_ANALYST)),
):
    """Create or update a remediation task for a finding."""
    if not db.get(Finding, finding_id):
        raise HTTPException(404, "Finding not found")

    task = db.query(RemediationTask).filter_by(finding_id=finding_id).first() or RemediationTask(
        finding_id=finding_id
    )
    task.assigned_to = data.assigned_to
    task.due_date = data.due_date
    task.notes = data.notes
    task.status = data.status
    db.add(task)
    db.commit()

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
    """List all remediation tasks for a project's findings."""
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
