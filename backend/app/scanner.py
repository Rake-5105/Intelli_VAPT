"""Real Scanner Orchestrator: executes security tools and streams output in real-time.

5-Stage Pipeline:
  1. Subdomain Discovery (Subfinder)
  2. Port Scanning & Service Risk Analysis (Nmap)
  3. HTTP Probing & Technology Detection (HTTPX)
  4. Vulnerability & Misconfiguration Scanning (Nuclei)
  5. Finalization & Report Generation
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import threading
from typing import Callable
from urllib.parse import urlparse

from .models import Asset, Finding, Project, Scan, ScanStatus, SessionLocal, Target
from .services import get_tool_binary, safe_run
from .websocket import scan_event_bus
from .wsl_check import check_wsl_tool, wsl_popen, wsl_run_command, check_wsl_available

logger = logging.getLogger("intellivapt.scanner")

# Whether to prefer WSL tools over native binaries
_wsl_available: bool | None = None


def _is_wsl_available() -> bool:
    """Lazy-check WSL once per process lifetime."""
    global _wsl_available
    if _wsl_available is None:
        _wsl_available = check_wsl_available()
    return _wsl_available


def _tool_ready(tool: str) -> str | None:
    """Return execution mode: 'wsl', 'native', or None if not available."""
    if _is_wsl_available():
        installed, _ = check_wsl_tool(tool)
        if installed:
            return "wsl"
    if get_tool_binary(tool):
        return "native"
    return None


def _run_tool_streaming(
    tool: str,
    arguments: list[str],
    scan_id: str,
    timeout: int = 300,
    on_line: Callable[[str], None] | None = None,
    stdin_data: str | None = None,
) -> list[str]:
    """Run a tool and stream each stdout line via WebSocket. Returns all output lines."""
    mode = _tool_ready(tool)
    lines: list[str] = []

    if mode == "wsl":
        proc = wsl_popen(tool, arguments)
        try:
            if stdin_data and proc.stdin:
                proc.stdin.write(stdin_data)
                proc.stdin.flush()
                proc.stdin.close()
            for raw_line in proc.stdout:  # type: ignore[union-attr]
                line = raw_line.rstrip("\n\r")
                if line:
                    lines.append(line)
                    scan_event_bus.emit_log(scan_id, f"[{tool}] {line}")
                    if on_line:
                        try:
                            on_line(line)
                        except Exception:
                            pass
            proc.wait(timeout=timeout)
        except Exception as e:
            if proc.poll() is None:
                proc.kill()
            scan_event_bus.emit_log(scan_id, f"[{tool}] Process error: {e}")
        finally:
            if proc.stdout:
                proc.stdout.close()  # type: ignore[union-attr]
            if proc.stderr:
                proc.stderr.close()  # type: ignore[union-attr]

    elif mode == "native":
        binary = get_tool_binary(tool)
        if not binary:
            scan_event_bus.emit_log(scan_id, f"[{tool}] Binary not found")
            return lines

        try:
            proc = subprocess.Popen(
                [binary, *arguments],
                stdin=subprocess.PIPE if stdin_data else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            if stdin_data and proc.stdin:
                proc.stdin.write(stdin_data)
                proc.stdin.flush()
                proc.stdin.close()

            for raw_line in proc.stdout:  # type: ignore[union-attr]
                line = raw_line.rstrip("\n\r")
                if line:
                    lines.append(line)
                    scan_event_bus.emit_log(scan_id, f"[{tool}] {line}")
                    if on_line:
                        try:
                            on_line(line)
                        except Exception:
                            pass

            proc.wait(timeout=timeout)
        except Exception as e:
            if "proc" in locals() and proc.poll() is None:
                proc.kill()
            scan_event_bus.emit_log(scan_id, f"[{tool}] Process notice/error: {e}")
        finally:
            if "proc" in locals():
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()

    return lines


def _run_tool_blocking(tool: str, arguments: list[str], timeout: int = 300) -> str:
    """Run a tool and return stdout as a single string. No streaming."""
    mode = _tool_ready(tool)
    if mode == "wsl":
        res = wsl_run_command(tool, arguments, timeout=timeout)
        return res.stdout if res.returncode == 0 else ""
    elif mode == "native":
        try:
            res = safe_run(tool, arguments, timeout=timeout)
            return res.stdout or ""
        except Exception:
            return ""
    return ""


def _update_scan(db, scan, progress: int = None, log_line: str = None, status: ScanStatus = None):
    """Helper to update scan record and broadcast via WebSocket."""
    if progress is not None:
        scan.progress = progress
        scan_event_bus.emit_progress(scan.id, progress)
    if log_line:
        scan.log += log_line + "\n"
        scan_event_bus.emit_log(scan.id, log_line)
    if status is not None:
        scan.status = status
        scan_event_bus.emit_status(scan.id, status.value)
    db.commit()


def run_live_scan(scan_id: str) -> None:
    """Execute live 5-stage assessment with real-time streaming and vulnerability correlation."""
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return

        project = db.get(Project, scan.project_id)
        if not project:
            return

        _update_scan(
            db,
            scan,
            progress=0,
            status=ScanStatus.RUNNING,
            log_line="[live-scan] Authorized live assessment initialized.",
        )

        # Determine execution environment
        wsl_ok = _is_wsl_available()
        in_docker = os.path.exists("/.dockerenv") or os.environ.get("WSL_ENABLED", "true").lower() == "false"
        exec_mode = "WSL (Linux)" if wsl_ok else ("Docker (Linux native)" if in_docker else "Windows native")
        _update_scan(db, scan, log_line=f"[live-scan] Execution environment: {exec_mode}")

        # Gather target domains / hosts
        targets = [t for t in project.targets if not t.excluded]
        if not targets:
            _update_scan(
                db,
                scan,
                status=ScanStatus.FAILED,
                log_line="[live-scan] No non-excluded targets in scope.",
            )
            return

        primary_target = targets[0].value.strip()
        host = urlparse(primary_target).hostname if "://" in primary_target else primary_target.split("/")[0]

        # Strict validation: alphanumeric, dashes, dots only
        if not re.match(r"^[a-zA-Z0-9.\-_]+$", host) or host.startswith("-"):
            _update_scan(
                db,
                scan,
                status=ScanStatus.FAILED,
                log_line=f"[security] Invalid or potentially unsafe host format: '{host}'",
            )
            return

        discovered_hosts: set[str] = {host}

        # ===================================================================
        # STAGE 1: Subdomain Discovery (Subfinder)
        # ===================================================================
        scan_event_bus.emit_stage(scan_id, "Subdomain Discovery", 1, 5)
        _update_scan(db, scan, progress=5, log_line=f"[live-scan] ── Stage 1/5: Subdomain enumeration for {host} ──")

        if _tool_ready("subfinder"):
            try:
                lines = _run_tool_streaming("subfinder", ["-d", host, "-silent"], scan_id, timeout=120)
                for line in lines:
                    cleaned = line.strip().lower()
                    if cleaned and re.match(r"^[a-zA-Z0-9.\-_]+$", cleaned):
                        discovered_hosts.add(cleaned)
                _update_scan(
                    db,
                    scan,
                    progress=15,
                    log_line=f"[subfinder] Discovered {len(discovered_hosts)} unique host(s).",
                )
            except Exception as e:
                _update_scan(db, scan, log_line=f"[subfinder] Warning: {e}")
        else:
            _update_scan(db, scan, progress=15, log_line="[subfinder] Not available, skipping subdomain discovery.")

        # ===================================================================
        # STAGE 2: Port Scanning (Nmap) & Network Exposure Detection
        # ===================================================================
        scan_event_bus.emit_stage(scan_id, "Port Scanning", 2, 5)
        _update_scan(db, scan, progress=20, log_line=f"[live-scan] ── Stage 2/5: Port scanning {host} (top 100 ports) ──")

        open_ports_found: list[dict] = []
        if _tool_ready("nmap"):
            try:
                nmap_args = ["-sT", "--top-ports", "100", "-T4", "--open", host]
                lines = _run_tool_streaming("nmap", nmap_args, scan_id, timeout=180)

                # Parse open ports
                for line in lines:
                    match = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", line.strip())
                    if match:
                        p_num = int(match.group(1))
                        p_proto = match.group(2)
                        p_svc = match.group(3)
                        open_ports_found.append({"port": p_num, "proto": p_proto, "service": p_svc})

                # Check for known security misconfigurations & exposed services
                for p_info in open_ports_found:
                    port = p_info["port"]
                    svc = p_info["service"]
                    finding_data = None

                    if port == 21:
                        finding_data = {
                            "title": "Cleartext File Transfer Protocol (FTP) Service Exposed",
                            "severity": "MEDIUM",
                            "cvss": 5.3,
                            "cwe": "CWE-319",
                            "desc": f"FTP service running on port {port}/{p_info['proto']}. FTP transmits credentials and files in unencrypted cleartext.",
                            "remediation": "Disable unencrypted FTP and migrate to SFTP (SSH File Transfer Protocol) or FTPS with TLS.",
                        }
                    elif port == 23:
                        finding_data = {
                            "title": "Insecure Cleartext Telnet Management Protocol Exposed",
                            "severity": "HIGH",
                            "cvss": 7.5,
                            "cwe": "CWE-319",
                            "desc": f"Telnet service active on port {port}. Telnet transmits administrative sessions without encryption, enabling credential sniffing.",
                            "remediation": "Disable Telnet immediately and enforce SSH with public key authentication.",
                        }
                    elif port in (3306, 5432, 6379, 27017, 9200, 1433, 1521):
                        finding_data = {
                            "title": f"Direct Internet Exposure of Database Service ({svc.upper()} Port {port})",
                            "severity": "HIGH",
                            "cvss": 7.5,
                            "cwe": "CWE-284",
                            "desc": f"Database port {port} ({svc}) is directly reachable from the public internet, exposing the system to brute force and authentication bypass attempts.",
                            "remediation": "Restrict database network access to localhost or authorized internal subnets using firewall rules.",
                        }
                    elif port in (3389, 5900):
                        finding_data = {
                            "title": f"Remote Desktop Interface Exposed ({svc.upper()} Port {port})",
                            "severity": "MEDIUM",
                            "cvss": 5.5,
                            "cwe": "CWE-284",
                            "desc": f"Remote management service {svc} is exposed on port {port}.",
                            "remediation": "Place remote desktop services behind a VPN or bastion host with multi-factor authentication.",
                        }
                    elif port == 445:
                        finding_data = {
                            "title": "Exposed Server Message Block (SMB) Port 445",
                            "severity": "HIGH",
                            "cvss": 7.5,
                            "cwe": "CWE-284",
                            "desc": f"SMB service is reachable on port {port}. Internet-exposed SMB is frequently targeted by worms and ransomware.",
                            "remediation": "Block SMB port 445 at the network perimeter firewall.",
                        }
                    elif port == 80:
                        finding_data = {
                            "title": "Unencrypted Plaintext HTTP Service Active (Port 80)",
                            "severity": "LOW",
                            "cvss": 3.7,
                            "cwe": "CWE-319",
                            "desc": "Port 80 HTTP is open without guaranteed HTTPS redirection.",
                            "remediation": "Configure HTTP to automatically redirect to HTTPS (301 Permanent Redirect) and enforce HSTS headers.",
                        }

                    if finding_data:
                        f_exist = (
                            db.query(Finding)
                            .filter_by(project_id=project.id, title=finding_data["title"], endpoint=f"{host}:{port}")
                            .first()
                        )
                        if not f_exist:
                            new_f = Finding(
                                project_id=project.id,
                                title=finding_data["title"],
                                description=finding_data["desc"],
                                endpoint=f"{host}:{port}",
                                scanner="Nmap Network Scanner",
                                severity=finding_data["severity"],
                                cvss_score=finding_data["cvss"],
                                cwe=finding_data["cwe"],
                                owasp_category="Security Misconfiguration",
                                remediation=finding_data["remediation"],
                            )
                            db.add(new_f)
                            db.commit()
                            scan_event_bus.emit_finding(
                                scan_id,
                                {
                                    "title": new_f.title,
                                    "severity": new_f.severity,
                                    "endpoint": new_f.endpoint,
                                    "cve": "",
                                },
                            )

                _update_scan(
                    db,
                    scan,
                    progress=35,
                    log_line=f"[nmap] Port scan complete: identified {len(open_ports_found)} open port(s).",
                )
            except Exception as e:
                _update_scan(db, scan, log_line=f"[nmap] Warning: {e}")
        else:
            _update_scan(db, scan, progress=35, log_line="[nmap] Not available, skipping port scanning.")

        # ===================================================================
        # STAGE 3: HTTP Probing & Technology Detection (HTTPX)
        # ===================================================================
        scan_event_bus.emit_stage(scan_id, "HTTP Probing", 3, 5)
        _update_scan(
            db,
            scan,
            progress=40,
            log_line=f"[live-scan] ── Stage 3/5: HTTP probing across {len(discovered_hosts)} host(s) ──",
        )

        # Build candidate URLs
        candidate_urls: list[str] = []
        for h in discovered_hosts:
            candidate_urls.append(f"https://{h}")
            candidate_urls.append(f"http://{h}")

        for p in open_ports_found:
            if p["port"] in (8080, 8443, 8000, 8888, 9090, 3000, 5000):
                proto = "https" if "ssl" in p["service"] or p["port"] == 8443 else "http"
                candidate_urls.append(f"{proto}://{host}:{p['port']}")

        candidate_urls = list(dict.fromkeys(candidate_urls))
        httpx_results: list[dict] = []
        responsive_web_targets: list[str] = []

        if _tool_ready("httpx"):
            try:
                stdin_payload = "\n".join(candidate_urls) + "\n"
                httpx_args = [
                    "-silent",
                    "-status-code",
                    "-title",
                    "-tech-detect",
                    "-json",
                    "-timeout", "6",
                    "-threads", "25",
                    "-retries", "1",
                ]

                def on_httpx_line(line: str):
                    try:
                        data = json.loads(line)
                        httpx_results.append(data)
                        url_found = data.get("url") or data.get("input")
                        if url_found:
                            responsive_web_targets.append(url_found)
                    except json.JSONDecodeError:
                        pass

                _run_tool_streaming(
                    "httpx",
                    httpx_args,
                    scan_id,
                    timeout=180,
                    on_line=on_httpx_line,
                    stdin_data=stdin_payload,
                )

                _update_scan(
                    db,
                    scan,
                    progress=55,
                    log_line=f"[httpx] Identified {len(httpx_results)} responsive web service(s).",
                )
            except Exception as e:
                _update_scan(db, scan, log_line=f"[httpx] Warning: {e}")
        else:
            _update_scan(db, scan, progress=55, log_line="[httpx] Not available, creating baseline assets.")

        # --- Save discovered assets to Database ---
        if httpx_results:
            for item in httpx_results:
                asset_host = item.get("input", item.get("host", host))
                clean_asset_host = urlparse(asset_host).hostname if "://" in asset_host else asset_host.split(":")[0]
                tech_list = item.get("tech", [])
                tech_str = ", ".join(tech_list) if tech_list else "HTTP Service"

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
                    db.flush()
                    scan_event_bus.emit_asset(
                        scan_id,
                        {
                            "hostname": clean_asset_host,
                            "technologies": tech_str,
                            "http_status": item.get("status_code", 200),
                        },
                    )
            db.commit()
        else:
            # Baseline asset fallback
            if not db.query(Asset).filter_by(project_id=project.id, hostname=host).first():
                db.add(
                    Asset(
                        project_id=project.id,
                        scan_id=scan.id,
                        hostname=host,
                        ip_address="Resolved in scope",
                        http_status=200,
                        title=f"{host} Primary Target",
                        technologies="Web Service",
                        criticality="HIGH",
                    )
                )
                db.commit()

        # ===================================================================
        # STAGE 4: Vulnerability Scanning (Nuclei)
        # ===================================================================
        targets_to_scan = list(dict.fromkeys(responsive_web_targets))
        if not targets_to_scan:
            targets_to_scan = [f"https://{host}", f"http://{host}"]

        # Scan primary active targets (limit to top 6 to ensure snappy scans)
        targets_to_scan = targets_to_scan[:6]

        scan_event_bus.emit_stage(scan_id, "Vulnerability Scanning", 4, 5)
        _update_scan(
            db,
            scan,
            progress=60,
            log_line=f"[live-scan] ── Stage 4/5: Vulnerability & misconfiguration scanning (Nuclei) on {len(targets_to_scan)} target(s) ──",
        )

        nuclei_findings: list[dict] = []
        if _tool_ready("nuclei"):
            try:
                nuclei_args = [
                    "-silent",
                    "-jsonl",
                    "-severity", "info,low,medium,high,critical",
                    "-tags", "cve,exposure,misconfig,vuln,network,tech,default-login,ssl",
                    "-etags", "fuzz,dos",
                    "-c", "25",
                    "-rate-limit", "150",
                    "-timeout", "5",
                    "-retries", "1",
                    "-nmhe",
                ]
                for t in targets_to_scan:
                    nuclei_args.extend(["-u", t])

                first_asset = db.query(Asset).filter_by(project_id=project.id).first()
                asset_id = first_asset.id if first_asset else None

                def on_nuclei_line(line: str):
                    try:
                        data = json.loads(line)
                        nuclei_findings.append(data)

                        info = data.get("info", {})
                        f_title = info.get("name", data.get("template-id", "Security Finding"))
                        f_desc = info.get("description", "Vulnerability detected by Nuclei engine.")
                        f_sev = info.get("severity", "LOW").upper()
                        classification = info.get("classification", {})
                        f_cwe_list = classification.get("cwe-id", [])
                        f_cve_list = classification.get("cve-id", [])
                        f_cwe = ", ".join(f_cwe_list) if isinstance(f_cwe_list, list) else ""
                        f_cve = ", ".join(f_cve_list) if isinstance(f_cve_list, list) else ""
                        matched_ep = data.get("matched-at", targets_to_scan[0])

                        # Save finding immediately to DB in real time
                        f_exist = (
                            db.query(Finding)
                            .filter_by(project_id=project.id, title=f_title, endpoint=matched_ep)
                            .first()
                        )
                        if not f_exist:
                            new_finding = Finding(
                                project_id=project.id,
                                asset_id=asset_id,
                                title=f_title,
                                description=f_desc,
                                endpoint=matched_ep,
                                scanner="Nuclei Engine",
                                severity=f_sev,
                                cvss_score=(
                                    8.5
                                    if f_sev == "CRITICAL"
                                    else 7.2
                                    if f_sev == "HIGH"
                                    else 5.0
                                    if f_sev == "MEDIUM"
                                    else 2.5
                                    if f_sev == "LOW"
                                    else 0.5
                                ),
                                cwe=f_cwe,
                                cve=f_cve,
                                owasp_category="Security Misconfiguration",
                                remediation="Apply vendor patch or secure configuration recommendations.",
                            )
                            db.add(new_finding)
                            db.commit()

                            # Emit live finding to dashboard
                            scan_event_bus.emit_finding(
                                scan_id,
                                {
                                    "title": f_title,
                                    "severity": f_sev,
                                    "endpoint": matched_ep,
                                    "cve": f_cve,
                                },
                            )
                    except Exception:
                        pass

                _run_tool_streaming("nuclei", nuclei_args, scan_id, timeout=300, on_line=on_nuclei_line)

                _update_scan(
                    db,
                    scan,
                    progress=90,
                    log_line=f"[nuclei] Correlated {len(nuclei_findings)} finding(s).",
                )
            except Exception as e:
                _update_scan(db, scan, log_line=f"[nuclei] Warning: {e}")
        else:
            _update_scan(
                db,
                scan,
                progress=90,
                log_line="[nuclei] Not available, skipping template-based scanning.",
            )

        # ===================================================================
        # STAGE 5: Finalization & Metrics
        # ===================================================================
        scan_event_bus.emit_stage(scan_id, "Finalization", 5, 5)
        total_assets = db.query(Asset).filter_by(project_id=project.id).count()
        total_findings = db.query(Finding).filter_by(project_id=project.id).count()

        _update_scan(
            db,
            scan,
            progress=100,
            status=ScanStatus.COMPLETED,
            log_line=f"[live-scan] ✓ Assessment complete. {total_assets} asset(s), {total_findings} finding(s), {len(discovered_hosts)} host(s) enumerated.",
        )

    except Exception as err:
        logger.exception("Live scan failed: %s", err)
        if db:
            scan = db.get(Scan, scan_id)
            if scan:
                _update_scan(
                    db,
                    scan,
                    status=ScanStatus.FAILED,
                    log_line=f"[error] Live scan encountered an unexpected error: {err}",
                )
    finally:
        db.close()


def start_live_scan_thread(scan_id: str) -> None:
    """Launch the live scanner orchestrator in a background thread."""
    threading.Thread(target=run_live_scan, args=(scan_id,), daemon=True).start()
