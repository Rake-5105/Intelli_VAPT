"""Scanner tool status routes."""

from fastapi import APIRouter, Depends

from ..auth import require
from ..models import Role, User
from ..schemas import ToolStatusOut
from ..services import tool_status

router = APIRouter(tags=["Tools"])


@router.get("/api/tools/status", response_model=list[ToolStatusOut])
def tools(user: User = Depends(require(Role.ADMIN))):
    """Check installation status of all configured scanner tools."""
    return tool_status()
