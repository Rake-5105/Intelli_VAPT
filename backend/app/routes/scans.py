"""Scan management routes."""

import os

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..auth import current_user, require
from ..models import Project, Role, Scan, ScanStatus, User, get_db
from ..schemas import ScanDetailOut, ScanIn, ScanListOut, ScanLogOut, ScanOut
from ..simulation import start_simulation_thread
from ..scanner import start_live_scan_thread

DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"

router = APIRouter(tags=["Scans"])


@router.post("/api/projects/{project_id}/scans", status_code=202, response_model=ScanOut)
def start_scan(
    project_id: str,
    data: ScanIn,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.ADMIN, Role.SECURITY_ANALYST)),
):
    """Queue a scan for a project. Requires at least one non-excluded target."""
    p = db.get(Project, project_id)
    if not p:
        raise HTTPException(404, "Project not found")
    if not any(not t.excluded for t in p.targets):
        raise HTTPException(422, "Add at least one non-excluded authorized target before scanning")

    scan = Scan(
        project_id=project_id,
        profile=data.profile,
        log="[authorized] Scope validated; assessment queued.\n",
    )
    db.add(scan)
    db.commit()

    is_demo = os.getenv("DEMO_MODE", "false").lower() == "true"
    if is_demo:
        start_simulation_thread(scan.id)
    else:
        start_live_scan_thread(scan.id)

    return {"id": scan.id, "status": scan.status, "progress": scan.progress}


@router.get("/api/scans/{scan_id}", response_model=ScanDetailOut)
def get_scan(scan_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Retrieve scan status and progress."""
    s = db.get(Scan, scan_id)
    if not s:
        raise HTTPException(404, "Scan not found")
    return {"id": s.id, "status": s.status, "progress": s.progress, "created_at": s.created_at}


@router.get("/api/projects/{project_id}/scans", response_model=list[ScanListOut])
def scans(project_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """List all scans for a project."""
    return [
        {
            "id": s.id,
            "status": s.status,
            "profile": s.profile,
            "progress": s.progress,
            "created_at": s.created_at,
        }
        for s in db.query(Scan).filter_by(project_id=project_id)
    ]


@router.get("/api/scans/{scan_id}/logs", response_model=ScanLogOut)
def scan_logs(scan_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Retrieve scan execution logs."""
    s = db.get(Scan, scan_id)
    if not s:
        raise HTTPException(404, "Scan not found")
    return {"scan_id": s.id, "log": s.log}


@router.post("/api/scans/{scan_id}/cancel")
def cancel_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.ADMIN, Role.SECURITY_ANALYST)),
):
    """Cancel a running or queued scan."""
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status in (ScanStatus.COMPLETED, ScanStatus.CANCELLED):
        raise HTTPException(409, "Scan is already final")

    scan.status = ScanStatus.CANCELLED
    scan.log += "[control] Scan cancelled by analyst.\n"
    db.commit()

    return {"id": scan.id, "status": scan.status}
