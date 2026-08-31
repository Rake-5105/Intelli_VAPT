"""Serialization helpers for converting ORM models to API response dicts."""

import ipaddress
import re

from fastapi import HTTPException

from .models import Finding, Project


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
    """Determine the target type from its value string.

    Returns one of: URL, CIDR, IP, DOMAIN.
    Raises HTTPException(422) for invalid inputs.
    """
    value = value.strip().lower()

    if value.startswith(("http://", "https://")):
        return "URL"

    try:
        ipaddress.ip_network(value, strict=False)
        return "CIDR" if "/" in value else "IP"
    except ValueError:
        pass

    if re.fullmatch(r"(?:\*\.)?[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", value):
        return "DOMAIN"

    raise HTTPException(422, "Target must be a valid domain, URL, IP address, or CIDR")
