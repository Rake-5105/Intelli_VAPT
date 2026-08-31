"""IntelliVAPT API: safe orchestration for explicitly authorized assessments.

This module creates the FastAPI application, registers middleware and routers,
and seeds demo data on startup. All business logic has been moved to dedicated
modules under app.routes, app.auth, app.models, etc.
"""

import os

from argon2 import PasswordHasher
from celery import Celery
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .auth import hasher
from .middleware import SecurityHeadersMiddleware, register_rate_limiter
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

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"
celery_app = Celery("intellivapt", broker=os.getenv("REDIS_URL", "redis://localhost:6379/0"))

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = FastAPI(title="IntelliVAPT API", version="0.1.0")

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
app.add_middleware(SecurityHeadersMiddleware)
register_rate_limiter(app)

# Register all route modules
for router in all_routers:
    app.include_router(router)


# ---------------------------------------------------------------------------
# Startup — create tables and seed demo data
# ---------------------------------------------------------------------------

@app.on_event("startup")
def startup():
    """Create database tables and optionally seed demo data."""
    Base.metadata.create_all(engine)

    db = SessionLocal()
    try:
        if DEMO_MODE and not db.query(User).filter_by(email="demo@intellivapt.example.com").first():
            user = User(
                name="Demo Analyst",
                email="demo@intellivapt.example.com",
                password_hash=hasher.hash("DemoPassword!2026"),
                role=Role.ADMIN,
            )
            db.add(user)
            db.flush()

            project = Project(
                name="ACME External VAPT",
                client="ACME Corporation",
                description="Authorized external assessment demo.",
                status=ProjectStatus.ACTIVE,
                owner_id=user.id,
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
    """Basic liveness probe."""
    return {"status": "ok", "demo_mode": DEMO_MODE}
