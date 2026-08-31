"""Safe scanner and reporting primitives used by the API and worker."""
from __future__ import annotations
import hashlib
import os
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from fastapi import HTTPException

TOOL_ENV = {
    "nmap": "NMAP_PATH",
    "subfinder": "SUBFINDER_PATH",
    "httpx": "HTTPX_PATH",
    "whatweb": "WHATWEB_PATH",
    "nuclei": "NUCLEI_PATH",
    "nikto": "NIKTO_PATH",
    "eyewitness": "EYEWITNESS_PATH",
}

PROJECT_TOOLS_DIR = Path(__file__).resolve().parent.parent.parent / "tools" / "bin"


def get_tool_binary(tool: str) -> str | None:
    """Find binary from environment variable, system PATH, or local tools/bin folder."""
    env_name = TOOL_ENV.get(tool, "")
    configured = os.getenv(env_name, tool) if env_name else tool

    # 1. Check configured path or system PATH
    found = shutil.which(configured) or (configured if Path(configured).is_file() else None)
    if found:
        return found

    # 2. Check local tools/bin folder
    local_binary = PROJECT_TOOLS_DIR / f"{tool}.exe"
    if local_binary.is_file():
        return str(local_binary)

    return None


def tool_status():
    result = []
    for tool, env in TOOL_ENV.items():
        configured = os.getenv(env, tool)
        binary = get_tool_binary(tool)
        result.append({
            "tool": tool,
            "configured_path": configured,
            "installed": bool(binary),
            "path": binary,
        })
    return result

def safe_run(tool: str, arguments: list[str], timeout: int = 300) -> subprocess.CompletedProcess[str]:
    """Execute only configured tools using argument arrays, never a shell string."""
    if tool not in TOOL_ENV:
        raise HTTPException(400, "Unsupported scanner")
    binary = get_tool_binary(tool)
    if not binary:
        raise HTTPException(424, f"{tool} is not installed")
    if any("\x00" in arg or len(arg) > 2048 for arg in arguments):
        raise HTTPException(422, "Unsafe scanner argument")
    return subprocess.run([binary, *arguments], text=True, capture_output=True, timeout=timeout, check=False, shell=False)

def host_from_target(value: str) -> str:
    return urlparse(value).hostname if "://" in value else value.split("/")[0]

def severity_for_score(score: float) -> str:
    if score >= 9: return "CRITICAL"
    if score >= 7: return "HIGH"
    if score >= 4: return "MEDIUM"
    if score > 0: return "LOW"
    return "INFORMATIONAL"

def evidence_hash(path: Path) -> str:
    digest=hashlib.sha256()
    with path.open("rb") as evidence:
        for chunk in iter(lambda: evidence.read(1024 * 1024), b""): digest.update(chunk)
    return digest.hexdigest()
