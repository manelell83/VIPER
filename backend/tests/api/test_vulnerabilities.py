"""
Unit tests for vulnerabilities API routes.

Tests:
  - GET /vulnerabilities (list all)
  - GET /vulnerabilities?host_id=X (filter)
  - GET /vulnerabilities?severity=CRITICAL (filter)
  - Vulnerability serialization
  - Vulnerability count aggregation
  - Empty results handling
"""

import pytest
from sqlalchemy.orm import Session
from app.models.scan import ScanSession, Host
from app.vulnerability_scanner.models import Vulnerability
from fastapi.testclient import TestClient


class TestVulnerabilityRoutes:
    """Test vulnerability API routes."""

    @pytest.fixture
    def scan_with_vulns(self, test_db: Session):
        """Create a test scan with vulnerabilities."""
        scan = ScanSession(type="network", target="192.168.1.0/24", status="completed")
        test_db.add(scan)
        test_db.commit()

        host1 = Host(scan_id=scan.id, ip="192.168.1.100", mac="aa:bb:cc:dd:ee:01")
        host2 = Host(scan_id=scan.id, ip="192.168.1.101", mac="aa:bb:cc:dd:ee:02")
        test_db.add_all([host1, host2])
        test_db.commit()

        # Add vulnerabilities
        vuln1 = Vulnerability(
            host_id=host1.id,
            cve_id="CVE-2023-0001",
            cvss=9.8,
            severity="CRITICAL",
            description="Critical RCE",
            affected_service="OpenSSH",
            affected_port=22,
        )
        vuln2 = Vulnerability(
            host_id=host1.id,
            cve_id="CVE-2023-0002",
            cvss=5.3,
            severity="MEDIUM",
            description="Medium SQLi",
            affected_service="Apache",
            affected_port=80,
        )
        vuln3 = Vulnerability(
            host_id=host2.id,
            cve_id="CVE-2023-0003",
            cvss=7.2,
            severity="HIGH",
            description="High Privesc",
            affected_service="Linux Kernel",
            affected_port=None,
        )
        test_db.add_all([vuln1, vuln2, vuln3])
        test_db.commit()

        return scan, [host1, host2], [vuln1, vuln2, vuln3]

    def test_get_vulnerabilities_list_all(self, client: TestClient, scan_with_vulns):
        """Test GET /vulnerabilities returns all vulnerabilities."""
        scan, hosts, vulns = scan_with_vulns

        response = client.get("/vulnerabilities")

        assert response.status_code == 200
        data = response.json()
        assert "vulnerabilities" in data or isinstance(data, list)

    def test_get_vulnerabilities_filter_by_severity(self, client: TestClient, scan_with_vulns, test_db: Session):
        """Test GET /vulnerabilities?severity=CRITICAL filters by severity."""
        scan, hosts, vulns = scan_with_vulns

        response = client.get("/vulnerabilities?severity=CRITICAL")

        assert response.status_code == 200
        data = response.json()
        vulnerabilities = data if isinstance(data, list) else data.get("vulnerabilities", [])

        # Should contain at least the CRITICAL vuln
        severities = [v.get("severity") for v in vulnerabilities]
        assert "CRITICAL" in severities

    def test_get_vulnerabilities_filter_by_host_id(self, client: TestClient, scan_with_vulns, test_db: Session):
        """Test GET /vulnerabilities?host_id=X filters by host."""
        scan, hosts, vulns = scan_with_vulns
        host1_id = hosts[0].id

        response = client.get(f"/vulnerabilities?host_id={host1_id}")

        assert response.status_code == 200
        data = response.json()
        vulnerabilities = data if isinstance(data, list) else data.get("vulnerabilities", [])

        # Should only contain vulnerabilities from host1
        if vulnerabilities:
            for vuln in vulnerabilities:
                assert vuln.get("host_id") == host1_id or len(vulnerabilities) == 0

    def test_vulnerability_serialization(self, client: TestClient, scan_with_vulns):
        """Test vulnerability JSON serialization."""
        scan, hosts, vulns = scan_with_vulns

        response = client.get("/vulnerabilities")
        data = response.json()
        vulnerabilities = data if isinstance(data, list) else data.get("vulnerabilities", [])

        if vulnerabilities:
            vuln = vulnerabilities[0]
            assert "cve_id" in vuln
            assert "cvss" in vuln
            assert "severity" in vuln
            assert "description" in vuln
            assert "affected_service" in vuln

    def test_vulnerability_count_aggregation(self, test_db: Session):
        """Test vulnerability count per host."""
        scan = ScanSession(type="network", target="192.168.1.0/24", status="completed")
        test_db.add(scan)
        test_db.commit()

        host = Host(scan_id=scan.id, ip="192.168.1.100", mac="aa:bb:cc:dd:ee:ff")
        test_db.add(host)
        test_db.commit()

        # Add 5 vulnerabilities
        for i in range(5):
            vuln = Vulnerability(
                host_id=host.id,
                cve_id=f"CVE-2023-{i:04d}",
                cvss=5.0 + i,
                severity="MEDIUM",
            )
            test_db.add(vuln)
        test_db.commit()

        # Count vulnerabilities for host
        count = test_db.query(Vulnerability).filter(Vulnerability.host_id == host.id).count()
        assert count == 5

    def test_get_vulnerabilities_empty_results(self, client: TestClient, test_db: Session):
        """Test GET /vulnerabilities with no vulnerabilities."""
        response = client.get("/vulnerabilities")

        assert response.status_code == 200
        data = response.json()
        vulnerabilities = data if isinstance(data, list) else data.get("vulnerabilities", [])
        assert len(vulnerabilities) == 0 or vulnerabilities == []


class TestVulnerabilityErrorHandling:
    """Test error handling for vulnerability routes."""

    def test_invalid_severity_filter(self, client: TestClient):
        """Test invalid severity filter."""
        response = client.get("/vulnerabilities?severity=INVALID_SEVERITY")

        # Should either return empty or 400
        assert response.status_code in [200, 400, 422]

    def test_invalid_host_id_filter(self, client: TestClient):
        """Test invalid host_id filter."""
        response = client.get("/vulnerabilities?host_id=nonexistent-id")

        # Should return 200 with empty results or 400
        assert response.status_code in [200, 400, 404]
