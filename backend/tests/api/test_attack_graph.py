"""
API tests for the attack graph routes (/attack-graph/*).
The graph-building logic itself is unit-tested in tests/attack_graph/.
"""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.scan import ScanSession, Host


def _scan_with_ssh_host(db: Session) -> ScanSession:
    scan = ScanSession(type="domain", target="10.0.0.5", status="completed")
    db.add(scan)
    db.commit()
    host = Host(scan_id=scan.id, ip="10.0.0.5")
    host.ports = [{"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"}]
    db.add(host)
    db.commit()
    return scan


class TestGetAttackGraph:

    def test_builds_graph_on_demand(self, client: TestClient, test_db: Session):
        scan = _scan_with_ssh_host(test_db)

        response = client.get(f"/attack-graph/{scan.id}")

        assert response.status_code == 200
        body = response.json()
        node_types = sorted(n["data"]["type"] for n in body["elements"]["nodes"])
        # SSH is a pivot service; with no CVEs the host is not "critical",
        # so it is classified PIVOT rather than ENTRY.
        assert node_types == ["ATTACKER", "PIVOT"]
        assert body["stats"]["nodes"] == 2
        assert body["stats"]["paths"] == 1
        assert body["paths"][0]["target_ip"] == "10.0.0.5"

    def test_unknown_scan_returns_404(self, client: TestClient):
        assert client.get("/attack-graph/does-not-exist").status_code == 404


class TestRegenerate:

    def test_regenerate_replaces_existing_graph(self, client: TestClient, test_db: Session):
        scan = _scan_with_ssh_host(test_db)
        first = client.get(f"/attack-graph/{scan.id}").json()["graph_id"]

        response = client.post(f"/attack-graph/{scan.id}/regenerate")

        assert response.status_code == 200
        second = client.get(f"/attack-graph/{scan.id}").json()["graph_id"]
        assert second != first

    def test_graphs_for_two_scans_coexist(self, client: TestClient, test_db: Session):
        """Regression test: the attacker node used a fixed primary key, so the
        second scan's graph failed with a UNIQUE constraint error."""
        scan_a = _scan_with_ssh_host(test_db)
        scan_b = _scan_with_ssh_host(test_db)

        assert client.get(f"/attack-graph/{scan_a.id}").status_code == 200
        assert client.get(f"/attack-graph/{scan_b.id}").status_code == 200
