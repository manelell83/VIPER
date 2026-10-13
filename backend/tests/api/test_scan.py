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

# The user's confirmation that they may scan the target (required by the API)
CONFIRMED = {"authorization_confirmed": True}


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
    # Pretend this machine has exactly one interface, "eth0"
    monkeypatch.setattr(scan_routes, "get_interface_by_name",
                        lambda name: {"name": "eth0", "subnet": "10.0.0.0/24"} if name == "eth0" else None)
    return calls


class TestStartNetworkScan:

    def test_creates_pending_session_and_schedules_job(self, client: TestClient, test_db: Session, scheduled):
        response = client.post("/scan/network", json={"interface": "eth0", **CONFIRMED})

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

    def test_unknown_interface_is_rejected(self, client: TestClient, test_db: Session, scheduled):
        response = client.post("/scan/network", json={"interface": "does-not-exist", **CONFIRMED})

        assert response.status_code == 422
        assert scheduled == []
        assert test_db.query(ScanSession).count() == 0


class TestStartDomainScan:

    @pytest.mark.parametrize("target", [
        "scanme.nmap.org", "127.0.0.1", "localhost", "my-host.lan.", "xn--bcher-kva.example",
    ])
    def test_ipv4_and_hostnames_are_accepted(self, client: TestClient, scheduled, target):
        assert client.post("/scan/domain", json={"target": target, **CONFIRMED}).status_code == 200

    def test_valid_target_is_accepted(self, client: TestClient, test_db: Session, scheduled):
        response = client.post("/scan/domain", json={"target": "  scanme.nmap.org  ", **CONFIRMED})

        assert response.status_code == 200
        scan_id = response.json()["scan_id"]

        scan = test_db.query(ScanSession).filter(ScanSession.id == scan_id).one()
        assert scan.type == "domain"
        assert scan.target == "scanme.nmap.org"   # surrounding whitespace stripped
        assert scheduled == [("domain", scan_id, "scanme.nmap.org")]

    def test_empty_target_is_rejected(self, client: TestClient, scheduled):
        response = client.post("/scan/domain", json={"target": "   ", **CONFIRMED})

        assert response.status_code == 422
        assert scheduled == []

    def test_too_long_target_is_rejected(self, client: TestClient, scheduled):
        response = client.post("/scan/domain", json={"target": "a" * 254, **CONFIRMED})

        assert response.status_code == 422
        assert scheduled == []

    @pytest.mark.parametrize("target", [
        # nmap option injection (python-nmap splits the host string on spaces)
        "nothing.invalid -oN pwned.txt",
        "-iL /etc/passwd",
        "--script=http-shellshock example.com",
        "example.com	-oX out.xml",
        # shell metacharacters
        "example.com; rm -rf /",
        "example.com | id",
        "$(whoami).example.com",
        "`id`.example.com",
        # malformed hostnames / unsupported targets
        "-leading-hyphen.com",
        "trailing-hyphen-.com",
        "under_score.com",
        "a" * 64 + ".com",          # label longer than 63 characters
        "10.0.0.0/24",              # CIDR ranges are for the network scan
        "::1",                      # IPv6 is not supported
    ])
    def test_invalid_targets_are_rejected(self, client: TestClient, test_db: Session, scheduled, target):
        response = client.post("/scan/domain", json={"target": target, **CONFIRMED})

        assert response.status_code == 422
        assert scheduled == []
        assert test_db.query(ScanSession).count() == 0


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


class TestScanAuthorization:
    """No active scan without an explicit, recorded authorization confirmation."""

    @pytest.mark.parametrize("payload", [
        {"target": "scanme.nmap.org"},                                    # missing
        {"target": "scanme.nmap.org", "authorization_confirmed": False},
        {"target": "scanme.nmap.org", "authorization_confirmed": None},
        {"target": "scanme.nmap.org", "authorization_confirmed": "maybe"},
        {"target": "scanme.nmap.org", "authorization_confirmed": "yes"},        # not a JSON true
        {"target": "scanme.nmap.org", "authorization_confirmed": 1},
    ])
    def test_domain_scan_without_confirmation_is_refused(self, client: TestClient, test_db: Session, scheduled, payload):
        response = client.post("/scan/domain", json=payload)

        assert response.status_code == 422
        assert scheduled == []
        assert test_db.query(ScanSession).count() == 0

    def test_network_scan_without_confirmation_is_refused(self, client: TestClient, test_db: Session, scheduled):
        response = client.post("/scan/network", json={"interface": "eth0"})

        assert response.status_code == 422
        assert scheduled == []
        assert test_db.query(ScanSession).count() == 0

    def test_confirmation_is_recorded_on_the_scan(self, client: TestClient, test_db: Session, scheduled):
        from app.core.audit import AUTHORIZATION_STATEMENT

        scan_id = client.post("/scan/domain", json={"target": "scanme.nmap.org", **CONFIRMED}).json()["scan_id"]

        scan = test_db.query(ScanSession).filter(ScanSession.id == scan_id).one()
        assert scan.authorized_by == "analyst-user"           # the authenticated user, not a client field
        assert scan.authorized_at is not None
        assert scan.authorization_statement == AUTHORIZATION_STATEMENT

        exposed = client.get(f"/scan/status/{scan_id}").json()["authorization"]
        assert exposed["by"] == "analyst-user"
        assert exposed["at"].endswith("Z")

    def test_network_scan_records_the_real_subnet(self, client: TestClient, test_db: Session, scheduled):
        scan_id = client.post("/scan/network", json={"interface": "eth0", **CONFIRMED}).json()["scan_id"]

        scan = test_db.query(ScanSession).filter(ScanSession.id == scan_id).one()
        assert scan.target == "10.0.0.0/24"
        assert scan.authorized_by == "analyst-user"

    def test_confirmation_is_written_to_the_audit_log_file(self, client: TestClient, scheduled):
        from tests.conftest import AUDIT_LOG_FILE

        scan_id = client.post("/scan/domain", json={"target": "scanme.nmap.org", **CONFIRMED}).json()["scan_id"]

        with open(AUDIT_LOG_FILE, encoding="utf-8") as f:
            lines = [line for line in f if f"scan_id={scan_id}" in line]
        assert len(lines) == 1
        assert "viper.audit" in lines[0]
        assert "user=analyst-user" in lines[0]
        assert "target=scanme.nmap.org" in lines[0]
        assert "statement=" in lines[0]

    def test_statement_endpoint(self, client: TestClient):
        from app.core.audit import AUTHORIZATION_STATEMENT

        assert client.get("/scan/authorization").json() == {"statement": AUTHORIZATION_STATEMENT}
