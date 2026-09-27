"""IntelliVAPT API: safe orchestration for explicitly authorized assessments.

This module creates the FastAPI application, registers middleware and routers,
seeds default administrator on startup, and provides the WebSocket endpoint for real-time
scan streaming.
"""

import asyncio
import logging
import os

from argon2 import PasswordHasher
from celery import Celery
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .auth import hasher
from .middleware import RequestSizeLimiterMiddleware, SecurityHeadersMiddleware, register_rate_limiter
from .models import (
    Asset,
    Base,
    Finding,
    Project,
    ProjectStatus,
    Role,
    Target,
    User,
    engine,
    SessionLocal,
)
from .routes import all_routers
from .websocket import scan_event_bus
from .wsl_check import get_wsl_status

logger = logging.getLogger("intellivapt")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"
celery_app = Celery("intellivapt", broker=os.getenv("REDIS_URL", "redis://localhost:6379/0"))

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = FastAPI(title="IntelliVAPT API", version="2.0.0")

# CORS
development_origins = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174"
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", development_origins).split(","),
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

# Security middleware
app.add_middleware(RequestSizeLimiterMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
register_rate_limiter(app)

# Register all route modules
for router in all_routers:
    app.include_router(router)


# ---------------------------------------------------------------------------
# WebSocket endpoint for real-time scan streaming
# ---------------------------------------------------------------------------

@app.websocket("/ws/scans/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: str):
    """Stream real-time scan events to connected clients.

    Events sent: log, progress, status, finding, asset, stage
    """
    await scan_event_bus.connect(scan_id, websocket)
    try:
        while True:
            # Keep the connection alive; we only send data server → client
            # but we still read to detect disconnects and handle pings
            await websocket.receive_text()
    except WebSocketDisconnect:
        scan_event_bus.disconnect(scan_id, websocket)
    except Exception:
        scan_event_bus.disconnect(scan_id, websocket)


# ---------------------------------------------------------------------------
# Startup — create tables, seed admin account, configure WebSocket event loop
# ---------------------------------------------------------------------------

@app.on_event("startup")
def on_startup():
    """Create database tables, configure WebSocket bus, and ensure administrator exists."""
    # Bind the running asyncio loop to ScanEventBus for thread-safe broadcasts
    try:
        loop = asyncio.get_running_loop()
        scan_event_bus.set_loop(loop)
        logger.info("WebSocket scan event bus bound to running event loop.")
    except RuntimeError:
        logger.warning("No running asyncio event loop detected during startup.")

    # Detect WSL environment
    status = get_wsl_status()
    if status.available:
        logger.info("WSL detected: %s", status.distro)
        installed_tools = [t for t, ok in status.tools.items() if ok]
        missing_tools = [t for t, ok in status.tools.items() if not ok]
        if installed_tools:
            logger.info("  WSL tools available: %s", ", ".join(installed_tools))
        if missing_tools:
            logger.info("  WSL tools missing: %s (run scripts/install_wsl_tools.sh)", ", ".join(missing_tools))
    else:
        logger.info("WSL not available — falling back to Windows binaries in tools/bin/.")

    # Create database tables
    Base.metadata.create_all(engine)

    db = SessionLocal()
    try:
        # Ensure default administrator exists
        admin = db.query(User).filter_by(email="admin@intellivapt.local").first()
        if not admin:
            # Upgrade existing demo account if present, otherwise create new administrator
            legacy_user = db.query(User).filter(
                User.email.in_(["demo@intellivapt.example.com", "demo@intellivapt.local"])
            ).first()
            if legacy_user:
                legacy_user.name = "Security Administrator"
                legacy_user.email = "admin@intellivapt.local"
                legacy_user.password_hash = hasher.hash("AdminSecure!2026")
                legacy_user.role = Role.ADMIN
                db.commit()
                admin = legacy_user
                logger.info("Upgraded legacy demo account to: admin@intellivapt.local")
            else:
                new_admin = User(
                    name="Security Administrator",
                    email="admin@intellivapt.local",
                    password_hash=hasher.hash("AdminSecure!2026"),
                    role=Role.ADMIN,
                )
                db.add(new_admin)
                db.commit()
                admin = new_admin
                logger.info("Created default administrator: admin@intellivapt.local")

        # Only seed demo project data if DEMO_MODE is explicitly enabled
        if DEMO_MODE and not db.query(Project).filter_by(name="ACME External VAPT").first():
            project = Project(
                name="ACME External VAPT",
                client="ACME Corporation",
                description="Authorized external assessment demo.",
                status=ProjectStatus.ACTIVE,
                owner_id=admin.id,
            )
            db.add(project)
            db.flush()

            db.add_all(
                [
                    Target(project_id=project.id, value="example.com", target_type="DOMAIN"),
                    Target(
                        project_id=project.id,
                        value="admin.example.com",
                        target_type="DOMAIN",
                        excluded=True,
                    ),
                ]
            )

            asset = Asset(
                project_id=project.id,
                hostname="example.com",
                ip_address="93.184.216.34",
                http_status=200,
                title="Example Domain",
                technologies="Nginx, TLS 1.3",
            )
            api_asset = Asset(
                project_id=project.id,
                hostname="api.example.com",
                ip_address="93.184.216.34",
                http_status=200,
                title="ACME API",
                technologies="Node.js, Express",
            )
            db.add_all([asset, api_asset])
            db.flush()

            db.add_all(
                [
                    Finding(
                        project_id=project.id,
                        asset_id=asset.id,
                        title="Missing Content-Security-Policy header",
                        description="The application response does not include a Content-Security-Policy header.",
                        endpoint="https://example.com",
                        scanner="Custom headers",
                        severity="MEDIUM",
                        cvss_score=5.3,
                        cwe="CWE-693",
                        owasp_category="A05: Security Misconfiguration",
                        remediation="Define a restrictive Content-Security-Policy appropriate to the application.",
                    ),
                    Finding(
                        project_id=project.id,
                        asset_id=api_asset.id,
                        title="Server version disclosure",
                        description="Response headers disclose the web server version.",
                        endpoint="https://api.example.com",
                        scanner="Nuclei",
                        severity="LOW",
                        cvss_score=2.6,
                        cwe="CWE-200",
                        owasp_category="A05: Security Misconfiguration",
                        remediation="Remove unnecessary version banners from responses.",
                    ),
                ]
            )
            db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    """Basic liveness probe with WSL status."""
    wsl_ok = os.getenv("WSL_ENABLED", "true").lower() == "true"
    return {"status": "ok", "demo_mode": DEMO_MODE, "wsl_enabled": wsl_ok}
