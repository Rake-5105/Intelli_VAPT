"""WSL detection and tool validation for IntelliVAPT.

Detects whether WSL is available, identifies the active distribution,
and checks which security tools are installed inside the WSL environment.
"""

from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass, field
from functools import lru_cache

logger = logging.getLogger("intellivapt.wsl")

# Tools that IntelliVAPT can orchestrate via WSL
WSL_TOOLS = ["nmap", "subfinder", "httpx", "nuclei", "nikto", "whatweb"]


@dataclass
class WSLStatus:
    """Snapshot of WSL environment availability."""

    available: bool = False
    distro: str = ""
    version: str = ""
    tools: dict[str, bool] = field(default_factory=dict)
    tool_paths: dict[str, str] = field(default_factory=dict)


def _run_wsl(*args: str, timeout: int = 10) -> subprocess.CompletedProcess[str]:
    """Run a command inside WSL, raising on failure."""
    distro = os.getenv("WSL_DISTRO", "")
    cmd = ["wsl"]
    if distro:
        cmd.extend(["-d", distro])
    cmd.extend(["-e", *args])
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False, shell=False,
    )


def check_wsl_available() -> bool:
    """Return True if WSL is accessible and can execute commands."""
    try:
        res = _run_wsl("echo", "ok")
        return res.returncode == 0 and "ok" in res.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def get_wsl_distro_info() -> tuple[str, str]:
    """Return (distro_name, version_id) from /etc/os-release inside WSL."""
    try:
        res = _run_wsl("cat", "/etc/os-release")
        if res.returncode != 0:
            return ("", "")
        info: dict[str, str] = {}
        for line in res.stdout.strip().splitlines():
            if "=" in line:
                key, _, val = line.partition("=")
                info[key.strip()] = val.strip().strip('"')
        return (info.get("PRETTY_NAME", info.get("NAME", "")), info.get("VERSION_ID", ""))
    except Exception:
        return ("", "")


def check_wsl_tool(tool: str) -> tuple[bool, str]:
    """Check if a tool is installed in WSL. Returns (installed, path)."""
    try:
        res = _run_wsl("which", tool)
        if res.returncode == 0 and res.stdout.strip():
            return (True, res.stdout.strip())
        return (False, "")
    except Exception:
        return (False, "")


def get_wsl_status() -> WSLStatus:
    """Comprehensive WSL environment check. Results are NOT cached — call sparingly."""
    status = WSLStatus()

    if not os.getenv("WSL_ENABLED", "true").lower() == "true":
        logger.info("WSL_ENABLED is not true, skipping WSL checks.")
        return status

    status.available = check_wsl_available()
    if not status.available:
        logger.warning("WSL is not available on this system.")
        return status

    status.distro, status.version = get_wsl_distro_info()
    logger.info("WSL detected: %s (version %s)", status.distro, status.version)

    for tool in WSL_TOOLS:
        installed, path = check_wsl_tool(tool)
        status.tools[tool] = installed
        status.tool_paths[tool] = path
        if installed:
            logger.info("  ✓ %s → %s", tool, path)
        else:
            logger.info("  ✗ %s not found in WSL", tool)

    return status


def wsl_run_command(
    tool: str,
    arguments: list[str],
    timeout: int = 300,
) -> subprocess.CompletedProcess[str]:
    """Execute a tool inside WSL with argument safety checks.

    This is the blocking variant — waits for the tool to finish.
    For streaming output, use ``wsl_popen`` instead.
    """
    if any("\x00" in arg or len(arg) > 2048 for arg in arguments):
        raise ValueError("Unsafe argument detected")
    return _run_wsl(tool, *arguments, timeout=timeout)


def wsl_popen(
    tool: str,
    arguments: list[str],
) -> subprocess.Popen[str]:
    """Spawn a tool inside WSL and return a Popen handle for streaming output.

    Caller is responsible for reading stdout/stderr and calling wait()/terminate().
    """
    if any("\x00" in arg or len(arg) > 2048 for arg in arguments):
        raise ValueError("Unsafe argument detected")

    distro = os.getenv("WSL_DISTRO", "")
    cmd = ["wsl"]
    if distro:
        cmd.extend(["-d", distro])
    cmd.extend(["-e", tool, *arguments])

    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
    )
