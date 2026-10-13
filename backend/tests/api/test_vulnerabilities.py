"""
API tests for the vulnerability routes (/vulnerabilities/*).
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.scan import ScanSession, Host
from app.vulnerability_scanner.models import Vulnerability


@pytest.fixture
def scan_with_vulns(test_db: Session):
    """Two scans; the first has two hosts with three CVEs in total."""
    scan = ScanSession(type="network", target="192.168.1.0/24", status="completed")
    other_scan = ScanSession(type="domain", target="example.com", status="completed")
    test_db.add_all([scan, other_scan])
    test_db.commit()

    host1 = Host(scan_id=scan.id, ip="192.168.1.100")
    host1.ports = [{"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"}]
    host2 = Host(scan_id=scan.id, ip="192.168.1.101")
    other_host = Host(scan_id=other_scan.id, ip="93.184.216.34")
    test_db.add_all([host1, host2, other_host])
    test_db.commit()

    test_db.add_all([
        Vulnerability(host_id=host1.id, cve_id="CVE-2023-0001", cvss=9.8, severity="CRITICAL",
                      affected_service="OpenSSH 8.2", affected_port="22/tcp"),
        Vulnerability(host_id=host1.id, cve_id="CVE-2023-0002", cvss=5.3, severity="MEDIUM",
                      affected_service="OpenSSH 8.2", affected_port="22/tcp"),
        Vulnerability(host_id=host2.id, cve_id="CVE-2023-0003", cvss=7.2, severity="HIGH",
                      affected_service="Apache httpd 2.4.41", affected_port="80/tcp"),
        Vulnerability(host_id=other_host.id, cve_id="CVE-2023-0004", cvss=4.0, severity="MEDIUM"),
    ])
    test_db.commit()
    return scan, host1, host2


class TestListVulnerabilities:

    def test_lists_all_sorted_by_cvss_desc(self, client: TestClient, scan_with_vulns):
        body = client.get("/vulnerabilities").json()

        assert body["count"] == 4
        assert [v["cvss"] for v in body["vulnerabilities"]] == [9.8, 7.2, 5.3, 4.0]

    def test_filter_by_scan(self, client: TestClient, scan_with_vulns):
        scan, _, _ = scan_with_vulns

        body = client.get(f"/vulnerabilities?scan_id={scan.id}").json()

        assert {v["cve_id"] for v in body["vulnerabilities"]} == {
            "CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003",
        }

    def test_filter_by_severity_is_case_insensitive(self, client: TestClient, scan_with_vulns):
        body = client.get("/vulnerabilities?severity=critical").json()

        assert [v["cve_id"] for v in body["vulnerabilities"]] == ["CVE-2023-0001"]

    def test_filter_by_host(self, client: TestClient, scan_with_vulns):
        _, host1, _ = scan_with_vulns

        body = client.get(f"/vulnerabilities?host_id={host1.id}").json()

        assert body["count"] == 2
        assert all(v["host_id"] == host1.id for v in body["vulnerabilities"])

    def test_limit_above_maximum_is_rejected(self, client: TestClient):
        assert client.get("/vulnerabilities?limit=501").status_code == 422

    def test_empty_database_returns_empty_list(self, client: TestClient):
        body = client.get("/vulnerabilities").json()

        assert body == {"vulnerabilities": [], "count": 0}


class TestHostVulnerabilities:

    def test_returns_host_vulns_and_risk(self, client: TestClient, scan_with_vulns):
        _, host1, _ = scan_with_vulns

        body = client.get(f"/vulnerabilities/by-host/{host1.id}").json()

        assert body["host"]["ip"] == "192.168.1.100"
        assert len(body["vulnerabilities"]) == 2
        assert body["risk"]["vuln_count"] == 2
        assert body["risk"]["critical"] == 1

    def test_unknown_host_returns_404(self, client: TestClient):
        assert client.get("/vulnerabilities/by-host/does-not-exist").status_code == 404


class TestRiskSummary:

    def test_summary_for_scan_covers_each_host(self, client: TestClient, scan_with_vulns):
        scan, _, _ = scan_with_vulns

        body = client.get(f"/vulnerabilities/risk/summary?scan_id={scan.id}").json()

        assert {h["host_ip"] for h in body["hosts"]} == {"192.168.1.100", "192.168.1.101"}
        assert body["network"]["total_vulns"] == 3
