"""Scan management routes with authorization guards and audit logging."""

import os

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..audit import log_security_event
from ..auth import current_user, require, verify_project_access
from ..middleware import limiter
from ..models import Project, Role, Scan, ScanStatus, User, get_db
from ..schemas import ScanDetailOut, ScanIn, ScanListOut, ScanLogOut, ScanOut
from ..simulation import start_simulation_thread
from ..scanner import start_live_scan_thread

DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"

router = APIRouter(tags=["Scans"])


@router.post("/api/projects/{project_id}/scans", status_code=202, response_model=ScanOut)
@limiter.limit("5/minute")
def start_scan(
    project_id: str,
    data: ScanIn,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.ADMIN, Role.SECURITY_ANALYST)),
):
    """Queue an authorized scan for a project with scope and rate limit validation."""
    project = db.get(Project, project_id)
    verify_project_access(project, user, "launch scans on")

    if not any(not t.excluded for t in project.targets):
        raise HTTPException(422, "Add at least one non-excluded authorized target before scanning")

    scan = Scan(
        project_id=project_id,
        profile=data.profile,
        log="[authorized] Scope validated; assessment queued.\n",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    log_security_event(
        db,
        action="START_SCAN",
        resource_type="scan",
        resource_id=scan.id,
        detail=f"Queued {data.profile} scan on project '{project.name}' with {len(project.targets)} configured targets",
        user=user,
        request=request,
    )

    is_demo = os.getenv("DEMO_MODE", "false").lower() == "true"
    if is_demo:
        start_simulation_thread(scan.id)
    else:
        start_live_scan_thread(scan.id)

    return {"id": scan.id, "status": scan.status, "progress": scan.progress}


@router.get("/api/scans/{scan_id}", response_model=ScanDetailOut)
def get_scan(scan_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Retrieve scan status and progress with authorization check."""
    s = db.get(Scan, scan_id)
    if not s:
        raise HTTPException(404, "Scan not found")
    project = db.get(Project, s.project_id)
    verify_project_access(project, user, "view scans on")

    return {"id": s.id, "status": s.status, "progress": s.progress, "created_at": s.created_at}


@router.get("/api/projects/{project_id}/scans", response_model=list[ScanListOut])
def scans(project_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """List all scans for a project with authorization check."""
    project = db.get(Project, project_id)
    verify_project_access(project, user, "view scans on")

    return [
        {
            "id": s.id,
            "status": s.status,
            "profile": s.profile,
            "progress": s.progress,
            "created_at": s.created_at,
        }
        for s in db.query(Scan).filter_by(project_id=project_id).order_by(Scan.created_at.desc())
    ]


@router.get("/api/scans/{scan_id}/logs", response_model=ScanLogOut)
def scan_logs(scan_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Retrieve scan execution logs with authorization check."""
    s = db.get(Scan, scan_id)
    if not s:
        raise HTTPException(404, "Scan not found")
    project = db.get(Project, s.project_id)
    verify_project_access(project, user, "view scan logs on")

    return {"scan_id": s.id, "log": s.log}


@router.post("/api/scans/{scan_id}/cancel")
def cancel_scan(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.ADMIN, Role.SECURITY_ANALYST)),
):
    """Cancel a running or queued scan with authorization check."""
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    project = db.get(Project, scan.project_id)
    verify_project_access(project, user, "cancel scans on")

    if scan.status in (ScanStatus.COMPLETED, ScanStatus.CANCELLED):
        raise HTTPException(409, "Scan is already final")

    scan.status = ScanStatus.CANCELLED
    scan.log += f"[control] Scan cancelled by analyst {user.email}.\n"
    db.commit()

    log_security_event(
        db,
        action="CANCEL_SCAN",
        resource_type="scan",
        resource_id=scan.id,
        detail=f"Cancelled scan on project '{project.name}'",
        user=user,
        request=request,
    )

    return {"id": scan.id, "status": scan.status}
