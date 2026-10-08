"""
API tests for the scan routes (/scan/*).

The real scan runs as a background task (ARP, nmap, NVD...). These tests
replace it with a recorder so they only check what the route itself does:
validate input, persist a ScanSession and schedule the right background job.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.routes import scan as scan_routes
from app.models.scan import ScanSession


@pytest.fixture
def scheduled(monkeypatch):
    """Replace both background scan jobs and record how they were called."""
    calls = []

    async def fake_network(scan_id, interface):
        calls.append(("network", scan_id, interface))

    async def fake_domain(scan_id, target):
        calls.append(("domain", scan_id, target))

    monkeypatch.setattr(scan_routes, "_background_network_scan", fake_network)
    monkeypatch.setattr(scan_routes, "_background_domain_scan", fake_domain)
    return calls


class TestStartNetworkScan:

    def test_creates_pending_session_and_schedules_job(self, client: TestClient, test_db: Session, scheduled):
        response = client.post("/scan/network", json={"interface": "eth0"})

        assert response.status_code == 200
        body = response.json()
        scan_id = body["scan_id"]
        assert body["websocket"] == f"/ws/{scan_id}"

        scan = test_db.query(ScanSession).filter(ScanSession.id == scan_id).one()
        assert scan.type == "network"
        assert scan.interface == "eth0"
        assert scan.status == "pending"

        assert scheduled == [("network", scan_id, "eth0")]

    def test_missing_interface_is_rejected(self, client: TestClient, scheduled):
        response = client.post("/scan/network", json={})

        assert response.status_code == 422
        assert scheduled == []


class TestStartDomainScan:

    def test_valid_target_is_accepted(self, client: TestClient, test_db: Session, scheduled):
        response = client.post("/scan/domain", json={"target": "  scanme.nmap.org  "})

        assert response.status_code == 200
        scan_id = response.json()["scan_id"]

        scan = test_db.query(ScanSession).filter(ScanSession.id == scan_id).one()
        assert scan.type == "domain"
        assert scan.target == "scanme.nmap.org"   # surrounding whitespace stripped
        assert scheduled == [("domain", scan_id, "scanme.nmap.org")]

    def test_empty_target_is_rejected(self, client: TestClient, scheduled):
        response = client.post("/scan/domain", json={"target": "   "})

        assert response.status_code == 422
        assert scheduled == []

    def test_too_long_target_is_rejected(self, client: TestClient, scheduled):
        response = client.post("/scan/domain", json={"target": "a" * 254})

        assert response.status_code == 422
        assert scheduled == []

    @pytest.mark.parametrize("target", [
        "example.com; rm -rf /",
        "example.com | id",
        "$(whoami).example.com",
        "`id`.example.com",
    ])
    def test_shell_metacharacters_are_rejected(self, client: TestClient, scheduled, target):
        response = client.post("/scan/domain", json={"target": target})

        assert response.status_code == 422
        assert scheduled == []


class TestScanStatus:

    def test_returns_scan_details(self, client: TestClient, test_db: Session):
        scan = ScanSession(type="network", target="192.168.1.0/24", status="completed")
        test_db.add(scan)
        test_db.commit()

        response = client.get(f"/scan/status/{scan.id}")

        assert response.status_code == 200
        body = response.json()
        assert body["id"] == scan.id
        assert body["status"] == "completed"
        assert body["hosts_count"] == 0

    def test_reflects_status_changes(self, client: TestClient, test_db: Session):
        scan = ScanSession(type="network", target="192.168.1.0/24", status="pending")
        test_db.add(scan)
        test_db.commit()

        for status in ("running", "completed"):
            scan.status = status
            test_db.commit()
            assert client.get(f"/scan/status/{scan.id}").json()["status"] == status

    def test_unknown_scan_returns_404(self, client: TestClient):
        response = client.get("/scan/status/does-not-exist")

        assert response.status_code == 404
