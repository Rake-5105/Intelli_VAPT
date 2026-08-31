"""Offline scan simulation for demo/training mode.

The simulation never starts a subprocess or makes a network request.
It walks through fictional assessment stages with timed delays,
updating the scan record in the database at each step.
"""

import time
import threading

from .models import Asset, Finding, Scan, ScanStatus, SessionLocal, Target


# Simulation stages: (stage_name, progress_percentage, log_message)
STAGES = [
    ("Reconnaissance", 12, "Preparing approved fictional scope"),
    ("Asset discovery", 28, "3 fictional hosts identified"),
    ("HTTP probing", 45, "3 live simulated services"),
    ("Technology detection", 61, "Nginx, Node.js, Express correlated"),
    ("Safe security checks", 78, "Headers and TLS review simulated"),
    ("Evidence correlation", 91, "2 findings normalized"),
    ("Risk analysis", 100, "Simulation completed successfully"),
]


def run_simulation(scan_id: str) -> None:
    """Walk through offline assessment stages, updating the scan record.

    This function is designed to run in a background thread.
    It never starts a subprocess or network request.
    """
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return

        scan.status = ScanStatus.RUNNING
        scan.log += "[simulation] Offline assessment started.\n"
        db.commit()

        for stage, progress, message in STAGES:
            time.sleep(2)
            db.refresh(scan)

            if scan.status == ScanStatus.CANCELLED:
                return

            scan.progress = progress
            scan.log += f"[simulation] {stage}: {message}.\n"
            db.commit()

        scan.status = ScanStatus.COMPLETED
        
        # Populate discovered assets and findings if this project has none yet
        project_assets = db.query(Asset).filter_by(project_id=scan.project_id).all()
        if not project_assets:
            target = db.query(Target).filter_by(project_id=scan.project_id, excluded=False).first()
            host = target.value if target else "target.example.com"
            clean_host = host.replace("https://", "").replace("http://", "").split("/")[0]
            
            asset1 = Asset(
                project_id=scan.project_id,
                scan_id=scan.id,
                hostname=clean_host,
                ip_address="198.51.100.42",
                http_status=200,
                title=f"{clean_host} - Primary Service",
                technologies="Nginx 1.24, React, TLS 1.3",
                criticality="HIGH",
            )
            asset2 = Asset(
                project_id=scan.project_id,
                scan_id=scan.id,
                hostname=f"api.{clean_host}",
                ip_address="198.51.100.43",
                http_status=200,
                title="REST API Gateway",
                technologies="Node.js 20, Express, PostgreSQL",
                criticality="HIGH",
            )
            db.add_all([asset1, asset2])
            db.flush()

            finding1 = Finding(
                project_id=scan.project_id,
                asset_id=asset1.id,
                title="Missing Strict-Transport-Security (HSTS) Header",
                description="The application does not enforce HTTPS connections via HSTS response header.",
                endpoint=f"https://{clean_host}/",
                scanner="HTTP Header Analyzer",
                severity="MEDIUM",
                cvss_score=4.8,
                cwe="CWE-319",
                owasp_category="A05: Security Misconfiguration",
                remediation="Configure the 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
            )
            finding2 = Finding(
                project_id=scan.project_id,
                asset_id=asset2.id,
                title="CORS Misconfiguration — Arbitrary Origin Allowed",
                description="API endpoint reflects arbitrary Origin headers in Access-Control-Allow-Origin.",
                endpoint=f"https://api.{clean_host}/v1/users",
                scanner="Nuclei",
                severity="HIGH",
                cvss_score=7.4,
                cwe="CWE-942",
                owasp_category="A01: Broken Access Control",
                remediation="Restrict Access-Control-Allow-Origin to trusted domains only.",
            )
            db.add_all([finding1, finding2])

        db.commit()
    finally:
        db.close()


def start_simulation_thread(scan_id: str) -> None:
    """Launch the simulation in a daemon background thread."""
    threading.Thread(target=run_simulation, args=(scan_id,), daemon=True).start()
