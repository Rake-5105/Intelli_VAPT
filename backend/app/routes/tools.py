"""Scanner tool status routes — reports WSL and Windows tool availability."""

from fastapi import APIRouter, Depends

from ..auth import current_user
from ..models import User
from ..schemas import ToolStatusOut
from ..services import tool_status
from ..wsl_check import get_wsl_status

router = APIRouter(tags=["Tools"])


@router.get("/api/tools/status", response_model=list[ToolStatusOut])
def tools(user: User = Depends(current_user)):
    """Check installation status of all configured scanner tools.

    Reports execution mode for each tool (WSL, Windows, or unavailable).
    """
    return tool_status()


@router.get("/api/tools/wsl")
def wsl_status(user: User = Depends(current_user)):
    """Detailed WSL environment status."""
    status = get_wsl_status()
    return {
        "available": status.available,
        "distro": status.distro,
        "version": status.version,
        "tools": status.tools,
        "tool_paths": status.tool_paths,
    }
