"""Report generation and download routes."""

import os
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from ..auth import current_user, require
from ..models import Finding, Project, Report, Role, User, get_db
from ..schemas import ReportOut

router = APIRouter(tags=["Reports"])


@router.post("/api/projects/{project_id}/reports", status_code=201, response_model=ReportOut)
def generate_report(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.ADMIN, Role.SECURITY_ANALYST)),
):
    """Generate a PDF assessment report for a project."""
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "Project not found")

    findings = db.query(Finding).filter_by(project_id=project_id).all()
    report_id = str(uuid.uuid4())
    folder = Path(os.getenv("STORAGE_PATH", "./storage")) / "reports"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{report_id}.pdf"

    from reportlab.lib.colors import HexColor
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    import html

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
                "This report contains simulation training data only. "
                "No external targets were contacted.",
                styles["Normal"],
            ),
        ]
    )

    SimpleDocTemplate(str(path), pagesize=A4, title=f"{project.name} VAPT Report").build(story)

    report = Report(
        id=report_id,
        project_id=project_id,
        name=f"{project.name} VAPT Report",
        format="PDF",
        path=str(path),
    )
    db.add(report)
    db.commit()

    return {"id": report.id, "name": report.name, "format": report.format, "created_at": report.created_at}


@router.get("/api/projects/{project_id}/reports", response_model=list[ReportOut])
def reports(project_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """List all generated reports for a project."""
    return [
        {"id": r.id, "name": r.name, "format": r.format, "created_at": r.created_at}
        for r in db.query(Report).filter_by(project_id=project_id)
    ]


@router.get("/api/reports/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Download a previously generated PDF report."""
    report = db.get(Report, report_id)
    if not report or not Path(report.path).is_file():
        raise HTTPException(404, "Report file not found")
    return FileResponse(report.path, media_type="application/pdf", filename=f"{report.name}.pdf")
