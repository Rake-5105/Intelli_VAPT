"""Real Scanner Orchestrator: executes security tools via WSL and streams output in real-time.

5-Stage Pipeline:
  1. Subdomain Discovery (Subfinder)
  2. Port Scanning (Nmap)
  3. HTTP Probing & Technology Detection (HTTPX)
  4. Vulnerability Scanning (Nuclei)
  5. Finalization & Report
"""

import json
import logging
import re
import threading
from urllib.parse import urlparse

from .models import Asset, Finding, Project, Scan, ScanStatus, SessionLocal, Target
from .services import get_tool_binary, safe_run
from .websocket import scan_event_bus
from .wsl_check import check_wsl_tool, wsl_popen, wsl_run_command, check_wsl_available

logger = logging.getLogger("intellivapt.scanner")

# Whether to prefer WSL tools over Windows binaries
_wsl_available: bool | None = None


def _is_wsl_available() -> bool:
    """Lazy-check WSL once per process lifetime."""
    global _wsl_available
    if _wsl_available is None:
        _wsl_available = check_wsl_available()
    return _wsl_available


def _tool_ready(tool: str) -> str | None:
    """Return execution mode: 'wsl', 'windows', or None if not available."""
    if _is_wsl_available():
        installed, _ = check_wsl_tool(tool)
        if installed:
            return "wsl"
    if get_tool_binary(tool):
        return "windows"
    return None


def _run_tool_streaming(tool: str, arguments: list[str], scan_id: str, timeout: int = 300) -> list[str]:
    """Run a tool and stream each stdout line via WebSocket. Returns all output lines."""
    mode = _tool_ready(tool)
    lines: list[str] = []

    if mode == "wsl":
        proc = wsl_popen(tool, arguments)
        try:
            for raw_line in proc.stdout:  # type: ignore[union-attr]
                line = raw_line.rstrip("\n\r")
                if line:
                    lines.append(line)
                    scan_event_bus.emit_log(scan_id, f"[{tool}] {line}")
            proc.wait(timeout=timeout)
        except Exception as e:
            proc.kill()
            scan_event_bus.emit_log(scan_id, f"[{tool}] Process error: {e}")
        finally:
            proc.stdout.close()  # type: ignore[union-attr]
            proc.stderr.close()  # type: ignore[union-attr]

    elif mode == "windows":
        try:
            res = safe_run(tool, arguments, timeout=timeout)
            if res.stdout:
                for raw_line in res.stdout.strip().splitlines():
                    line = raw_line.strip()
                    if line:
                        lines.append(line)
                        scan_event_bus.emit_log(scan_id, f"[{tool}] {line}")
        except Exception as e:
            scan_event_bus.emit_log(scan_id, f"[{tool}] Error: {e}")

    return lines


def _run_tool_blocking(tool: str, arguments: list[str], timeout: int = 300) -> str:
    """Run a tool and return stdout as a single string. No streaming."""
    mode = _tool_ready(tool)
    if mode == "wsl":
        res = wsl_run_command(tool, arguments, timeout=timeout)
        return res.stdout if res.returncode == 0 else ""
    elif mode == "windows":
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
    """Execute live 5-stage assessment using WSL tools (fallback to Windows binaries)."""
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return

        project = db.get(Project, scan.project_id)
        if not project:
            return

        _update_scan(db, scan, progress=0, status=ScanStatus.RUNNING,
                     log_line="[live-scan] Authorized live assessment initialized.")

        # Determine execution mode
        wsl_ok = _is_wsl_available()
        exec_mode = "WSL (Linux)" if wsl_ok else "Windows native"
        _update_scan(db, scan, log_line=f"[live-scan] Execution mode: {exec_mode}")

        # Gather target domains / hosts
        targets = [t for t in project.targets if not t.excluded]
        if not targets:
            _update_scan(db, scan, status=ScanStatus.FAILED,
                         log_line="[live-scan] No non-excluded targets in scope.")
            return

        primary_target = targets[0].value.strip()
        host = urlparse(primary_target).hostname if "://" in primary_target else primary_target.split("/")[0]

        # Strict validation: alphanumeric, dashes, dots only
        if not re.match(r"^[a-zA-Z0-9.\-_]+$", host) or host.startswith("-"):
            _update_scan(db, scan, status=ScanStatus.FAILED,
                         log_line=f"[security] Invalid or potentially unsafe host format: '{host}'")
            return

        discovered_hosts: set[str] = {host}

        # ===================================================================
        # STAGE 1: Subdomain Discovery (Subfinder)
        # ===================================================================
        scan_event_bus.emit_stage(scan_id, "Subdomain Discovery", 1, 5)
        _update_scan(db, scan, progress=5,
                     log_line=f"[live-scan] ── Stage 1/5: Subdomain enumeration for {host} ──")

        if _tool_ready("subfinder"):
            try:
                lines = _run_tool_streaming("subfinder", ["-d", host, "-silent"], scan_id, timeout=120)
                for line in lines:
                    cleaned = line.strip().lower()
                    if cleaned and re.match(r"^[a-zA-Z0-9.\-_]+$", cleaned):
                        discovered_hosts.add(cleaned)
                _update_scan(db, scan, progress=12,
                             log_line=f"[subfinder] Discovered {len(discovered_hosts)} unique host(s).")
            except Exception as e:
                _update_scan(db, scan, log_line=f"[subfinder] Warning: {e}")
        else:
            _update_scan(db, scan, progress=12,
                         log_line="[subfinder] Not available, skipping subdomain discovery.")

        # ===================================================================
        # STAGE 2: Port Scanning (Nmap)
        # ===================================================================
        scan_event_bus.emit_stage(scan_id, "Port Scanning", 2, 5)
        _update_scan(db, scan, progress=15,
                     log_line=f"[live-scan] ── Stage 2/5: Port scanning {host} (top 100 ports) ──")

        nmap_results: list[str] = []
        if _tool_ready("nmap"):
            try:
                nmap_args = ["-sT", "--top-ports", "100", "-T4", "--open", host]
                lines = _run_tool_streaming("nmap", nmap_args, scan_id, timeout=180)
                nmap_results = lines
                _update_scan(db, scan, progress=30,
                             log_line=f"[nmap] Port scan complete ({len(lines)} output lines).")
            except Exception as e:
                _update_scan(db, scan, log_line=f"[nmap] Warning: {e}")
        else:
            _update_scan(db, scan, progress=30,
                         log_line="[nmap] Not available, skipping port scanning.")

        # ===================================================================
        # STAGE 3: HTTP Probing & Technology Detection (HTTPX)
        # ===================================================================
        scan_event_bus.emit_stage(scan_id, "HTTP Probing", 3, 5)
        _update_scan(db, scan, progress=35,
                     log_line=f"[live-scan] ── Stage 3/5: HTTP probing across {len(discovered_hosts)} host(s) ──")

        httpx_results: list[dict] = []
        if _tool_ready("httpx"):
            try:
                # Build host list as stdin input for httpx
                host_list = "\n".join(discovered_hosts)
                mode = _tool_ready("httpx")

                if mode == "wsl":
                    # Pipe hosts via echo into httpx
                    import subprocess as _sp
                    distro_env = __import__("os").getenv("WSL_DISTRO", "")
                    wsl_cmd = ["wsl"]
                    if distro_env:
                        wsl_cmd.extend(["-d", distro_env])
                    wsl_cmd.extend(["-e", "bash", "-c",
                                    f"echo '{host_list}' | httpx -silent -status-code -title -tech-detect -json"])
                    proc = _sp.Popen(wsl_cmd, stdout=_sp.PIPE, stderr=_sp.PIPE, text=True, shell=False)
                    for raw_line in proc.stdout:  # type: ignore[union-attr]
                        line = raw_line.strip()
                        if line:
                            scan_event_bus.emit_log(scan_id, f"[httpx] {line}")
                            try:
                                data = json.loads(line)
                                httpx_results.append(data)
                            except json.JSONDecodeError:
                                pass
                    proc.wait(timeout=180)
                    proc.stdout.close()  # type: ignore[union-attr]
                    proc.stderr.close()  # type: ignore[union-attr]
                else:
                    # Windows fallback: pass hosts as -u arguments
                    args = ["-silent", "-status-code", "-title", "-tech-detect", "-json"]
                    for h in discovered_hosts:
                        args.extend(["-u", h])
                    res = safe_run("httpx", args, timeout=180)
                    if res.stdout:
                        for line in res.stdout.strip().splitlines():
                            try:
                                data = json.loads(line)
                                httpx_results.append(data)
                                scan_event_bus.emit_log(scan_id, f"[httpx] Found: {data.get('input', 'unknown')}")
                            except json.JSONDecodeError:
                                pass

                _update_scan(db, scan, progress=50,
                             log_line=f"[httpx] Identified {len(httpx_results)} responsive web service(s).")
            except Exception as e:
                _update_scan(db, scan, log_line=f"[httpx] Warning: {e}")
        else:
            _update_scan(db, scan, progress=50,
                         log_line="[httpx] Not available, creating baseline assets.")

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
                    scan_event_bus.emit_asset(scan_id, {
                        "hostname": clean_asset_host,
                        "technologies": tech_str,
                        "http_status": item.get("status_code", 200),
                    })
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
                    criticality="HIGH",
                ))
                db.commit()

        # ===================================================================
        # STAGE 4: Vulnerability Scanning (Nuclei)
        # ===================================================================
        scan_event_bus.emit_stage(scan_id, "Vulnerability Scanning", 4, 5)
        _update_scan(db, scan, progress=55,
                     log_line="[live-scan] ── Stage 4/5: Vulnerability & misconfiguration scanning (Nuclei) ──")

        nuclei_findings: list[dict] = []
        if _tool_ready("nuclei"):
            try:
                nuclei_args = ["-u", f"https://{host}", "-silent", "-jsonl",
                               "-severity", "low,medium,high,critical", "-timeout", "5"]
                lines = _run_tool_streaming("nuclei", nuclei_args, scan_id, timeout=300)
                for line in lines:
                    try:
                        data = json.loads(line)
                        nuclei_findings.append(data)
                    except json.JSONDecodeError:
                        pass
                _update_scan(db, scan, progress=85,
                             log_line=f"[nuclei] Correlated {len(nuclei_findings)} finding(s).")
            except Exception as e:
                _update_scan(db, scan, log_line=f"[nuclei] Warning: {e}")
        else:
            _update_scan(db, scan, progress=85,
                         log_line="[nuclei] Not available, skipping template-based scanning.")

        # --- Save findings to Database ---
        first_asset = db.query(Asset).filter_by(project_id=project.id).first()
        asset_id = first_asset.id if first_asset else None

        for item in nuclei_findings:
            info = item.get("info", {})
            f_title = info.get("name", item.get("template-id", "Security Finding"))
            f_desc = info.get("description", "Vulnerability detected by Nuclei engine.")
            f_sev = info.get("severity", "LOW").upper()
            classification = info.get("classification", {})
            f_cwe_list = classification.get("cwe-id", [])
            f_cve_list = classification.get("cve-id", [])
            f_cwe = ", ".join(f_cwe_list) if isinstance(f_cwe_list, list) else ""
            f_cve = ", ".join(f_cve_list) if isinstance(f_cve_list, list) else ""

            finding = Finding(
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
            )
            db.add(finding)
            db.flush()

            # Broadcast finding to WebSocket clients
            scan_event_bus.emit_finding(scan_id, {
                "title": f_title,
                "severity": f_sev,
                "endpoint": item.get("matched-at", ""),
                "cve": f_cve,
            })

        db.commit()

        # ===================================================================
        # STAGE 5: Finalization
        # ===================================================================
        scan_event_bus.emit_stage(scan_id, "Finalization", 5, 5)
        total_assets = db.query(Asset).filter_by(project_id=project.id).count()
        total_findings = db.query(Finding).filter_by(project_id=project.id).count()

        _update_scan(db, scan, progress=100, status=ScanStatus.COMPLETED,
                     log_line=f"[live-scan] ✓ Assessment complete. {total_assets} asset(s), {total_findings} finding(s), {len(discovered_hosts)} host(s) enumerated.")

    except Exception as err:
        logger.exception("Live scan failed: %s", err)
        if db:
            scan = db.get(Scan, scan_id)
            if scan:
                _update_scan(db, scan, status=ScanStatus.FAILED,
                             log_line=f"[error] Live scan encountered an unexpected error: {err}")
    finally:
        db.close()


def start_live_scan_thread(scan_id: str) -> None:
    """Launch the live scanner orchestrator in a background thread."""
    threading.Thread(target=run_live_scan, args=(scan_id,), daemon=True).start()
