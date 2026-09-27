"""Report generation and download routes supporting PDF, CSV, and JSON."""

import csv
import html
import json
import os
import uuid
from datetime import datetime, UTC
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from ..audit import log_security_event
from ..auth import current_user, require, verify_project_access
from ..middleware import limiter
from ..models import Asset, Finding, Project, Report, Role, User, get_db
from ..schemas import ReportOut

router = APIRouter(tags=["Reports"])


@router.post("/api/projects/{project_id}/reports", status_code=201, response_model=ReportOut)
@limiter.limit("10/minute")
async def generate_report(
    project_id: str,
    request: Request,
    format: str = Query("PDF", description="Report format: PDF, CSV, or JSON"),
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.ADMIN, Role.SECURITY_ANALYST)),
):
    """Generate an assessment report for a project in PDF, CSV, or JSON format."""
    project = db.get(Project, project_id)
    verify_project_access(project, user, "generate reports for")

    # Check if format was also passed in JSON body
    try:
        body = await request.json()
        if isinstance(body, dict) and "format" in body and body["format"]:
            format = body["format"]
    except Exception:
        pass

    fmt = format.strip().upper()
    if fmt not in ("PDF", "CSV", "JSON"):
        fmt = "PDF"

    findings = db.query(Finding).filter_by(project_id=project_id).all()
    project_assets = db.query(Asset).filter_by(project_id=project_id).all()

    report_id = str(uuid.uuid4())
    folder = Path(os.getenv("STORAGE_PATH", "./storage")) / "reports"
    folder.mkdir(parents=True, exist_ok=True)

    if fmt == "CSV":
        path = folder / f"{report_id}.csv"
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Finding ID",
                "Project ID",
                "Project Name",
                "Title",
                "Severity",
                "CVSS Score",
                "Endpoint",
                "Scanner",
                "CWE",
                "CVE",
                "OWASP Category",
                "Status",
                "Remediation Guidance",
                "First Seen",
                "Last Seen",
            ])
            for item in findings:
                writer.writerow([
                    item.id,
                    project.id,
                    project.name,
                    item.title,
                    item.severity,
                    f"{item.cvss_score:.1f}",
                    item.endpoint,
                    item.scanner,
                    item.cwe or "",
                    item.cve or "",
                    item.owasp_category or "",
                    item.status,
                    item.remediation or "",
                    item.first_seen.isoformat() if item.first_seen else "",
                    item.last_seen.isoformat() if item.last_seen else "",
                ])

    elif fmt == "JSON":
        path = folder / f"{report_id}.json"
        report_data = {
            "report_id": report_id,
            "platform": "IntelliVAPT Security Platform",
            "format": "JSON",
            "generated_at": datetime.now(UTC).isoformat(),
            "project": {
                "id": project.id,
                "name": project.name,
                "client": project.client,
                "description": project.description,
                "status": project.status,
                "created_at": project.created_at.isoformat() if project.created_at else None,
            },
            "summary": {
                "total_assets": len(project_assets),
                "total_findings": len(findings),
                "critical": sum(1 for f in findings if f.severity.upper() == "CRITICAL"),
                "high": sum(1 for f in findings if f.severity.upper() == "HIGH"),
                "medium": sum(1 for f in findings if f.severity.upper() == "MEDIUM"),
                "low": sum(1 for f in findings if f.severity.upper() == "LOW"),
                "informational": sum(1 for f in findings if f.severity.upper() in ("INFO", "INFORMATIONAL")),
            },
            "assets": [
                {
                    "id": a.id,
                    "hostname": a.hostname,
                    "ip": a.ip,
                    "http_status": a.http_status,
                    "title": a.title,
                    "technologies": a.technologies,
                    "criticality": a.criticality,
                }
                for a in project_assets
            ],
            "findings": [
                {
                    "id": item.id,
                    "title": item.title,
                    "severity": item.severity,
                    "cvss_score": item.cvss_score,
                    "endpoint": item.endpoint,
                    "scanner": item.scanner,
                    "cwe": item.cwe,
                    "cve": item.cve,
                    "owasp_category": item.owasp_category,
                    "status": item.status,
                    "remediation": item.remediation,
                    "first_seen": item.first_seen.isoformat() if item.first_seen else None,
                    "last_seen": item.last_seen.isoformat() if item.last_seen else None,
                }
                for item in findings
            ],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

    else:
        # Default: PDF Report
        path = folder / f"{report_id}.pdf"
        from reportlab.lib.colors import HexColor
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        def safe_text(val: str | None) -> str:
            return html.escape(str(val or ""))

        styles = getSampleStyleSheet()
        story = [
            Paragraph("IntelliVAPT Assessment Report", styles["Title"]),
            Spacer(1, 14),
            Paragraph(f"Project: {safe_text(project.name)}", styles["Heading2"]),
            Paragraph(f"Client: {safe_text(project.client) or 'Not specified'}", styles["Normal"]),
            Spacer(1, 16),
        ]

        data = [["Severity", "Finding", "Endpoint", "CVSS"]] + [
            [f.severity, safe_text(f.title), safe_text(f.endpoint), f"{f.cvss_score:.1f}"] for f in findings
        ]
        table = Table(data, colWidths=[68, 190, 220, 45])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), HexColor("#3C3836")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#EBDBB2")),
                    ("GRID", (0, 0), (-1, -1), 0.4, HexColor("#A89984")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 7),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ]
            )
        )

        story.extend(
            [
                Paragraph("Finding Summary", styles["Heading2"]),
                table,
                Spacer(1, 16),
                Paragraph(
                    "This report was automatically compiled by the IntelliVAPT Automated Security Assessment Platform.",
                    styles["Normal"],
                ),
            ]
        )

        SimpleDocTemplate(str(path), pagesize=A4, title=f"{project.name} VAPT Report").build(story)

    report = Report(
        id=report_id,
        project_id=project_id,
        name=f"{project.name} VAPT Report ({fmt})",
        format=fmt,
        path=str(path),
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    log_security_event(
        db,
        action="GENERATE_REPORT",
        resource_type="report",
        resource_id=report.id,
        detail=f"Compiled {fmt} deliverable for project '{project.name}'",
        user=user,
        request=request,
    )

    return {"id": report.id, "name": report.name, "format": report.format, "created_at": report.created_at}


@router.get("/api/projects/{project_id}/reports", response_model=list[ReportOut])
def reports(project_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """List all generated reports for a project with authorization check."""
    project = db.get(Project, project_id)
    verify_project_access(project, user, "view reports for")

    return [
        {"id": r.id, "name": r.name, "format": r.format, "created_at": r.created_at}
        for r in db.query(Report).filter_by(project_id=project_id).order_by(Report.created_at.desc())
    ]


@router.get("/api/reports/{report_id}/download")
def download_report(
    report_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Download a previously generated report with strict IDOR and Path Traversal verification."""
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(404, "Report not found")

    project = db.get(Project, report.project_id)
    verify_project_access(project, user, "download reports for")

    reports_base = (Path(os.getenv("STORAGE_PATH", "./storage")) / "reports").resolve()
    report_file = Path(report.path).resolve()

    # Guard against Path Traversal and Local File Inclusion (LFI)
    try:
        report_file.relative_to(reports_base)
    except ValueError:
        raise HTTPException(403, "Access to report file outside storage directory is forbidden")

    if not report_file.is_file():
        raise HTTPException(404, "Report file not found or inaccessible")

    fmt = (report.format or "PDF").upper()
    if fmt == "CSV":
        media_type = "text/csv"
        ext = "csv"
    elif fmt == "JSON":
        media_type = "application/json"
        ext = "json"
    else:
        media_type = "application/pdf"
        ext = "pdf"

    clean_name = report.name.replace(" ", "_").replace("(", "").replace(")", "")
    if not clean_name.lower().endswith(f".{ext}"):
        clean_name = f"{clean_name}.{ext}"

    log_security_event(
        db,
        action="DOWNLOAD_REPORT",
        resource_type="report",
        resource_id=report.id,
        detail=f"Downloaded {fmt} report '{report.name}' for project '{project.name}'",
        user=user,
        request=request,
    )

    return FileResponse(report.path, media_type=media_type, filename=clean_name)

