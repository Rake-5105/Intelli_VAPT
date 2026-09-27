"""Security audit log retrieval routes."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..auth import current_user, require
from ..models import AuditLog, Role, User, get_db
from ..schemas import AuditLogOut

router = APIRouter(prefix="/api/audit-logs", tags=["Audit"])


@router.get("", response_model=list[AuditLogOut])
def get_audit_logs(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: str | None = Query(None),
    resource_type: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.ADMIN, Role.SECURITY_ANALYST)),
):
    """Retrieve immutable security audit trail with role filtering."""
    query = db.query(AuditLog)

    # Role-based visibility: Non-admins only view their own activity
    if user.role != Role.ADMIN:
        query = query.filter_by(user_id=user.id)

    if action:
        query = query.filter(AuditLog.action.ilike(f"%{action.strip()}%"))

    if resource_type:
        query = query.filter_by(resource_type=resource_type.strip().lower())

    logs = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()

    return [
        {
            "id": l.id,
            "user_id": l.user_id,
            "user_email": l.user_email,
            "action": l.action,
            "resource_type": l.resource_type,
            "resource_id": l.resource_id,
            "detail": l.detail,
            "ip_address": l.ip_address,
            "created_at": l.created_at,
        }
        for l in logs
    ]
