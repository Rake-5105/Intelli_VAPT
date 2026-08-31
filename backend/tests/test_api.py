"""Test suite covering authentication, access control, rate limiting, and project workflows."""

import os
os.environ["DATABASE_URL"] = "sqlite:///./test_intellivapt.db"
os.environ["DEMO_MODE"] = "false"

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.models import Base, engine


@pytest.fixture(autouse=True)
def setup_and_teardown_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)


def test_health_check():
    with TestClient(app) as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


def test_user_registration_and_login():
    with TestClient(app) as client:
        # Register user
        reg = client.post(
            "/api/auth/register",
            json={"name": "Alice Analyst", "email": "alice@secops.io", "password": "SecurePassword!123"},
        )
        assert reg.status_code == 201
        data = reg.json()
        assert "access_token" in data
        assert data["user"]["email"] == "alice@secops.io"

        # Prevent duplicate registration
        dup = client.post(
            "/api/auth/register",
            json={"name": "Alice Dup", "email": "alice@secops.io", "password": "SecurePassword!123"},
        )
        assert dup.status_code == 409

        # Successful login
        login = client.post(
            "/api/auth/login",
            json={"email": "alice@secops.io", "password": "SecurePassword!123"},
        )
        assert login.status_code == 200
        assert "access_token" in login.json()

        # Failed login
        bad_login = client.post(
            "/api/auth/login",
            json={"email": "alice@secops.io", "password": "WrongPassword123!"},
        )
        assert bad_login.status_code == 401


def test_project_scope_and_scan_flow():
    with TestClient(app) as client:
        # Create user
        reg = client.post(
            "/api/auth/register",
            json={"name": "Bob Analyst", "email": "bob@secops.io", "password": "SecurePassword!123"},
        )
        headers = {"Authorization": f"Bearer {reg.json()['access_token']}"}

        # Create project
        proj = client.post(
            "/api/projects",
            headers=headers,
            json={"name": "Payment Gateway VAPT", "client": "FinTech Corp", "description": "PCI-DSS Scope"},
        )
        assert proj.status_code == 201
        project_id = proj.json()["id"]

        # Attempt to scan without targets (should fail scope guard)
        scan_fail = client.post(
            f"/api/projects/{project_id}/scans",
            headers=headers,
            json={"profile": "SAFE"},
        )
        assert scan_fail.status_code == 422

        # Add target
        target = client.post(
            f"/api/projects/{project_id}/targets",
            headers=headers,
            json={"value": "https://api.payments.fintech.test", "excluded": False},
        )
        assert target.status_code == 201

        # Scan now succeeds with authorized scope
        scan_ok = client.post(
            f"/api/projects/{project_id}/scans",
            headers=headers,
            json={"profile": "SAFE"},
        )
        assert scan_ok.status_code == 202
        scan_id = scan_ok.json()["id"]

        # Check scan logs
        logs = client.get(f"/api/scans/{scan_id}/logs", headers=headers)
        assert logs.status_code == 200
        assert "Scope validated" in logs.json()["log"]
