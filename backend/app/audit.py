"""Centralized security audit logging system.

Provides structured, immutable logging of security-relevant events including:
- Authentication (login success/failure, logout, registration, password changes)
- Project lifecycle operations (create, update, delete)
- Target scope modifications (add, remove, toggle exclusion)
- Assessment executions (start scan, cancel scan)
- Vulnerability triage (status updates, remediation assignment)
- Deliverable exports (report compilation, report download)
"""

from datetime import UTC, datetime
import logging
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from .models import AuditLog, User

logger = logging.getLogger("intellivapt.audit")


def get_client_ip(request: Request | None) -> str:
    """Extract real client IP considering reverse proxy headers safely."""
    if not request:
        return ""
    # Forwarded / X-Forwarded-For check
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        # First IP in list is the original client
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else ""


def log_security_event(
    db: Session,
    action: str,
    resource_type: str = "",
    resource_id: str = "",
    detail: str = "",
    user: User | None = None,
    user_id: str | None = None,
    user_email: str = "",
    request: Request | None = None,
    ip_address: str | None = None,
    commit: bool = True,
) -> AuditLog:
    """Record an immutable security audit event in the database."""
    resolved_user_id = user.id if user else user_id
    resolved_email = user.email if user else user_email
    resolved_ip = ip_address or get_client_ip(request)

    entry = AuditLog(
        user_id=resolved_user_id,
        user_email=resolved_email,
        action=action.upper(),
        resource_type=resource_type.lower(),
        resource_id=str(resource_id),
        detail=detail[:2000] if detail else "",
        ip_address=resolved_ip,
        created_at=datetime.now(UTC),
    )
    db.add(entry)
    if commit:
        try:
            db.commit()
            db.refresh(entry)
        except Exception as e:
            db.rollback()
            logger.error("Failed to commit audit log entry: %s", e)
    return entry
