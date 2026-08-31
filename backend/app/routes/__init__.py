"""Route package — collects all APIRouters for easy registration."""

from .auth import router as auth_router
from .projects import router as projects_router
from .targets import router as targets_router
from .scans import router as scans_router
from .assets import router as assets_router
from .findings import router as findings_router
from .evidence import router as evidence_router
from .remediation import router as remediation_router
from .reports import router as reports_router
from .tools import router as tools_router

all_routers = [
    auth_router,
    projects_router,
    targets_router,
    scans_router,
    assets_router,
    findings_router,
    evidence_router,
    remediation_router,
    reports_router,
    tools_router,
]
