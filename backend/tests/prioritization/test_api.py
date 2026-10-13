"""
Tests for the AI Prioritization API: ranked items with breakdown, narrative
caching (template), and human-in-the-loop overrides.
"""

import pytest
from sqlalchemy.orm import Session

from app.exploitability.models import ExploitabilityAssessment
from app.models.scan import Host, ScanSession
from app.vulnerability_scanner.models import Vulnerability


@pytest.fixture
def scan_with_findings(test_db: Session):
    s = ScanSession(type="network", target="192.168.56.0/24", status="completed")
    test_db.add(s)
    test_db.commit()
    h = Host(scan_id=s.id, ip="192.168.56.5")
    h.ports = [{"port": 21, "state": "open", "service": "ftp"}]
    test_db.add(h)
    test_db.commit()
    top = Vulnerability(host_id=h.id, cve_id="CVE-2011-2523", cvss=9.8, severity="CRITICAL",
                        epss=0.96, match_type="cpe", affected_service="vsftpd 2.3.4")
    low = Vulnerability(host_id=h.id, cve_id="CVE-2010-1635", cvss=5.0, severity="MEDIUM",
                        epss=0.01, match_type="keyword", affected_service=" x")
    test_db.add_all([top, low])
    test_db.commit()
    test_db.add(ExploitabilityAssessment(host_id=h.id, vuln_id=top.id, scan_id=s.id,
                                         cve_id=top.cve_id, exploit_maturity="WEAPONIZED",
                                         lateral_movement_potential="HIGH"))
    test_db.commit()
    return s, top, low


class TestGet:

    def test_returns_ranked_items_with_breakdown(self, client, scan_with_findings):
        scan, top, low = scan_with_findings
        body = client.get(f"/prioritization/{scan.id}").json()

        assert body["count"] == 2
        assert body["items"][0]["cve_id"] == "CVE-2011-2523"      # vsftpd first
        assert body["items"][0]["rank"] == 1
        assert {f["key"] for f in body["items"][0]["factors"]} >= {"exploitation", "epss", "cvss"}
        assert "llm_available" in body

    def test_404_for_unknown_scan(self, client):
        assert client.get("/prioritization/does-not-exist").status_code == 404

    def test_requires_auth(self, anon_client, scan_with_findings):
        scan, _, _ = scan_with_findings
        assert anon_client.get(f"/prioritization/{scan.id}").status_code == 401


class TestNarrative:

    def test_template_narrative_is_cached(self, client, scan_with_findings):
        scan, _, _ = scan_with_findings
        resp = client.post(f"/prioritization/{scan.id}/narrative", json={"use_llm": False}).json()

        assert resp["source"] == "template" and resp["model"] is None
        # now the GET carries the explanations
        body = client.get(f"/prioritization/{scan.id}").json()
        assert body["narrative"]["source"] == "template"
        assert body["items"][0]["explanation"]["text"]
        assert body["items"][0]["explanation"]["source"] == "template"

    def test_use_llm_without_key_falls_back_to_template(self, client, scan_with_findings):
        scan, _, _ = scan_with_findings
        resp = client.post(f"/prioritization/{scan.id}/narrative", json={"use_llm": True}).json()
        # no key configured in tests -> clean fallback
        assert resp["source"] == "template"
        assert resp["requested_llm"] is True


class TestOverrides:

    def test_dismiss_moves_a_finding_to_the_bottom(self, client, scan_with_findings):
        scan, top, low = scan_with_findings
        client.patch(f"/prioritization/{scan.id}/items/{top.id}", json={"dismissed": True})

        items = client.get(f"/prioritization/{scan.id}").json()["items"]
        assert items[-1]["cve_id"] == "CVE-2011-2523" and items[-1]["dismissed"] is True
        assert items[0]["cve_id"] == "CVE-2010-1635"

    def test_manual_rank_pins_order(self, client, scan_with_findings):
        scan, top, low = scan_with_findings
        # pin the low finding to rank 1
        client.patch(f"/prioritization/{scan.id}/items/{low.id}", json={"manual_rank": 1})

        items = client.get(f"/prioritization/{scan.id}").json()["items"]
        assert items[0]["cve_id"] == "CVE-2010-1635"
        assert items[0]["manual_rank"] == 1

    def test_override_persists_and_can_be_cleared(self, client, scan_with_findings):
        scan, top, low = scan_with_findings
        client.patch(f"/prioritization/{scan.id}/items/{top.id}", json={"dismissed": True})
        client.patch(f"/prioritization/{scan.id}/items/{top.id}", json={"dismissed": False})

        items = client.get(f"/prioritization/{scan.id}").json()["items"]
        assert items[0]["cve_id"] == "CVE-2011-2523" and items[0]["dismissed"] is False
