"""Serialization helpers and input sanitizers with SSRF and command-injection defenses."""

import ipaddress
import os
import re
from urllib.parse import urlparse

from fastapi import HTTPException, status

from .models import Finding, Project

# Dangerous cloud metadata services & link-local networks
DANGEROUS_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata",
    "instance-data",
    "100.100.100.200",  # Alibaba Cloud metadata
}

ALLOW_INTERNAL_TARGETS = os.getenv("ALLOW_INTERNAL_TARGETS", "false").lower() == "true"


def serialize_project(p: Project) -> dict:
    """Convert a Project ORM instance to an API-friendly dictionary."""
    return {
        "id": p.id,
        "name": p.name,
        "client": p.client,
        "description": p.description,
        "assessment_type": p.assessment_type,
        "status": p.status,
        "created_at": p.created_at,
        "targets": len(p.targets),
        "scans": len(p.scans),
    }


def serialize_finding(f: Finding) -> dict:
    """Convert a Finding ORM instance to an API-friendly dictionary."""
    return {
        "id": f.id,
        "title": f.title,
        "description": f.description,
        "asset_id": f.asset_id,
        "endpoint": f.endpoint,
        "scanner": f.scanner,
        "severity": f.severity,
        "cvss_score": f.cvss_score,
        "cwe": f.cwe,
        "cve": f.cve,
        "owasp_category": f.owasp_category,
        "remediation": f.remediation,
        "status": f.finding_status,
        "first_seen": f.first_seen,
        "last_seen": f.last_seen,
    }


def classify_target(value: str) -> str:
    """Determine the target type from its value string while enforcing strict SSRF and injection defenses.

    Returns one of: URL, CIDR, IP, DOMAIN.
    Raises HTTPException(422) for invalid, dangerous, or malformed inputs.
    """
    clean_val = value.strip().lower()

    # 1. Reject shell metacharacters and control characters
    if re.search(r"[\x00-\x1f\x7f;`$&|><!*{}()\[\]\\'\"]", clean_val.replace("*.", "", 1)):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Target contains prohibited shell metacharacters or control symbols",
        )

    # 2. URL Classification & SSRF Defense
    if clean_val.startswith(("http://", "https://")):
        try:
            parsed = urlparse(clean_val)
        except Exception:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid URL structure")

        if parsed.scheme not in ("http", "https"):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Target URL scheme must be HTTP or HTTPS")

        host = (parsed.hostname or "").strip().lower()
        if not host:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Target URL must contain a valid host")

        if not ALLOW_INTERNAL_TARGETS:
            if host in DANGEROUS_METADATA_HOSTS or host in ("localhost", "127.0.0.1", "::1"):
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    "Targeting cloud metadata endpoints (169.254.169.254) or localhost is prohibited",
                )
            try:
                ip = ipaddress.ip_address(host)
                if ip.is_loopback or ip.is_link_local or str(ip) == "169.254.169.254":
                    raise HTTPException(
                        status.HTTP_422_UNPROCESSABLE_ENTITY,
                        "Targeting internal loopback or cloud metadata services is prohibited",
                    )
            except ValueError:
                pass  # Host is a domain name

        return "URL"

    # 3. IP / CIDR Classification & SSRF Defense
    try:
        net = ipaddress.ip_network(clean_val, strict=False)
        if not ALLOW_INTERNAL_TARGETS:
            if net.is_loopback or net.is_link_local or any(
                str(h) == "169.254.169.254" for h in [net.network_address]
            ):
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    "Targeting loopback addresses or cloud metadata endpoints is prohibited",
                )
        return "CIDR" if "/" in clean_val else "IP"
    except ValueError:
        pass

    # 4. Domain Classification
    # Allow wildcard prefix (*.) for scope definition
    domain_candidate = clean_val
    if domain_candidate.startswith("*."):
        domain_candidate = domain_candidate[2:]

    if not ALLOW_INTERNAL_TARGETS:
        if domain_candidate in DANGEROUS_METADATA_HOSTS or domain_candidate in ("localhost",):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "Targeting cloud metadata services or localhost is prohibited",
            )

    if (
        re.fullmatch(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$", domain_candidate)
        and len(domain_candidate) <= 253
        and "." in domain_candidate
    ):
        return "DOMAIN"

    raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Target must be a valid domain, URL, IP address, or CIDR")
