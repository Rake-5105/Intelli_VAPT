"""Real Scanner Orchestrator: executes native security tools and normalizes findings."""

import json
import re
import threading
from urllib.parse import urlparse

from .models import Asset, Finding, Project, Scan, ScanStatus, SessionLocal, Target
from .services import get_tool_binary, safe_run


def run_live_scan(scan_id: str) -> None:
    """Execute live assessment using available native binaries (Subfinder, HTTPX, Nuclei, Nmap)."""
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return

        project = db.get(Project, scan.project_id)
        if not project:
            return

        scan.status = ScanStatus.RUNNING
        scan.log += "[live-scan] Authorized live assessment initialized.\n"
        db.commit()

        # Gather target domains / hosts
        targets = [t for t in project.targets if not t.excluded]
        if not targets:
            scan.status = ScanStatus.FAILED
            scan.log += "[live-scan] No non-excluded targets in scope.\n"
            db.commit()
            return

        primary_target = targets[0].value.strip()
        host = urlparse(primary_target).hostname if "://" in primary_target else primary_target.split("/")[0]
        # Strict validation: alphanumeric, dashes, dots only (safe domain / IP)
        if not re.match(r"^[a-zA-Z0-9.\-_]+$", host) or host.startswith("-"):
            scan.status = ScanStatus.FAILED
            scan.log += f"[security] Invalid or potentially unsafe host format: '{host}'\n"
            db.commit()
            return

        # -------------------------------------------------------------------
        # Step 1: Subdomain Enumeration (Subfinder)
        # -------------------------------------------------------------------
        scan.progress = 15
        scan.log += f"[live-scan] Stage 1/4: Enumerating subdomains for {host}...\n"
        db.commit()

        if get_tool_binary("subfinder"):
            try:
                res = safe_run("subfinder", ["-d", host, "-silent"], timeout=120)
                if res.returncode == 0 and res.stdout:
                    for line in res.stdout.strip().splitlines():
                        cleaned = line.strip().lower()
                        if cleaned:
                            discovered_hosts.add(cleaned)
                    scan.log += f"[subfinder] Discovered {len(discovered_hosts)} host(s).\n"
            except Exception as e:
                scan.log += f"[subfinder] Notice: {e}\n"
        else:
            scan.log += "[subfinder] Binary not available, skipping passive subdomain discovery.\n"
        db.commit()

        # -------------------------------------------------------------------
        # Step 2: HTTP Probing & Technology Detection (HTTPX)
        # -------------------------------------------------------------------
        scan.progress = 45
        scan.log += f"[live-scan] Stage 2/4: Probing live web services with HTTPX across {len(discovered_hosts)} host(s)...\n"
        db.commit()

        httpx_results = []
        if get_tool_binary("httpx"):
            try:
                args = ["-silent", "-status-code", "-title", "-tech-detect", "-json"]
                for h in discovered_hosts:
                    args.extend(["-u", h])
                
                res = safe_run("httpx", args, timeout=180)
                if res.stdout:
                    for line in res.stdout.strip().splitlines():
                        try:
                            data = json.loads(line)
                            httpx_results.append(data)
                        except Exception:
                            pass
                scan.log += f"[httpx] Identified {len(httpx_results)} responsive web service(s).\n"
            except Exception as e:
                scan.log += f"[httpx] Notice: {e}\n"
        else:
            scan.log += "[httpx] Binary not available, creating baseline assets.\n"
        db.commit()

        # Save discovered assets to Database
        if httpx_results:
            for item in httpx_results:
                asset_host = item.get("input", item.get("host", host))
                clean_asset_host = urlparse(asset_host).hostname if "://" in asset_host else asset_host.split(":")[0]
                tech_list = item.get("tech", [])
                tech_str = ", ".join(tech_list) if tech_list else "HTTP Service"
                
                # Avoid duplicates in DB
                existing = db.query(Asset).filter_by(project_id=project.id, hostname=clean_asset_host).first()
                if not existing:
                    asset = Asset(
                        project_id=project.id,
                        scan_id=scan.id,
                        hostname=clean_asset_host,
                        ip_address=item.get("host", ""),
                        http_status=item.get("status_code", 200),
                        title=item.get("title", ""),
                        technologies=tech_str,
                        criticality="HIGH" if item.get("status_code", 0) == 200 else "MEDIUM",
                    )
                    db.add(asset)
            db.commit()
        else:
            # Baseline asset fallback
            if not db.query(Asset).filter_by(project_id=project.id, hostname=host).first():
                db.add(Asset(
                    project_id=project.id,
                    scan_id=scan.id,
                    hostname=host,
                    ip_address="Resolved in scope",
                    http_status=200,
                    title=f"{host} Primary Target",
                    technologies="Web Service",
                    criticality="HIGH"
                ))
                db.commit()

        # -------------------------------------------------------------------
        # Step 3: Vulnerability & Misconfiguration Scanning (Nuclei)
        # -------------------------------------------------------------------
        scan.progress = 75
        scan.log += "[live-scan] Stage 3/4: Executing security misconfiguration & vulnerability checks (Nuclei)...\n"
        db.commit()

        nuclei_findings = []
        if get_tool_binary("nuclei"):
            try:
                nuclei_args = ["-u", f"https://{host}", "-silent", "-jsonl", "-severity", "low,medium,high,critical", "-timeout", "5"]
                res = safe_run("nuclei", nuclei_args, timeout=240)
                if res.stdout:
                    for line in res.stdout.strip().splitlines():
                        try:
                            data = json.loads(line)
                            nuclei_findings.append(data)
                        except Exception:
                            pass
                scan.log += f"[nuclei] Correlated {len(nuclei_findings)} finding(s).\n"
            except Exception as e:
                scan.log += f"[nuclei] Notice: {e}\n"
        else:
            scan.log += "[nuclei] Binary not available, skipping template checks.\n"
        db.commit()

        # Save findings to Database
        first_asset = db.query(Asset).filter_by(project_id=project.id).first()
        asset_id = first_asset.id if first_asset else None

        for item in nuclei_findings:
            info = item.get("info", {})
            f_title = info.get("name", item.get("template-id", "Security Finding"))
            f_desc = info.get("description", "Vulnerability detected by Nuclei engine.")
            f_sev = info.get("severity", "LOW").upper()
            f_cwe = ", ".join(info.get("classification", {}).get("cwe-id", [])) if isinstance(info.get("classification", {}).get("cwe-id", []), list) else ""
            f_cve = ", ".join(info.get("classification", {}).get("cve-id", [])) if isinstance(info.get("classification", {}).get("cve-id", []), list) else ""

            db.add(Finding(
                project_id=project.id,
                asset_id=asset_id,
                title=f_title,
                description=f_desc,
                endpoint=item.get("matched-at", f"https://{host}"),
                scanner="Nuclei Engine",
                severity=f_sev,
                cvss_score=8.5 if f_sev == "CRITICAL" else 7.2 if f_sev == "HIGH" else 5.0 if f_sev == "MEDIUM" else 2.5,
                cwe=f_cwe,
                cve=f_cve,
                owasp_category="Security Misconfiguration",
                remediation="Apply vendor patch or secure configuration recommendations.",
            ))

        # -------------------------------------------------------------------
        # Step 4: Finalization
        # -------------------------------------------------------------------
        scan.progress = 100
        scan.status = ScanStatus.COMPLETED
        scan.log += f"[live-scan] Live scan completed successfully. Correlated {len(discovered_hosts)} assets and {len(nuclei_findings)} findings.\n"
        db.commit()

    except Exception as err:
        if db:
            scan = db.get(Scan, scan_id)
            if scan:
                scan.status = ScanStatus.FAILED
                scan.log += f"[error] Live scan encountered an unexpected error: {err}\n"
                db.commit()
    finally:
        db.close()


def start_live_scan_thread(scan_id: str) -> None:
    """Launch the live scanner orchestrator in a background thread."""
    threading.Thread(target=run_live_scan, args=(scan_id,), daemon=True).start()
