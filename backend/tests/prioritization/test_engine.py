"""
Tests for the deterministic prioritization engine: transparent scoring,
ranking, and that the vsftpd backdoor rises to the top.
"""

import pytest
from sqlalchemy.orm import Session

from app.exploitability.models import ExploitabilityAssessment
from app.models.scan import Host, ScanSession
from app.prioritization.engine import host_exposure, prioritize_scan, score_finding
from app.vulnerability_scanner.models import Vulnerability


@pytest.fixture
def scan(test_db: Session):
    s = ScanSession(type="network", target="192.168.56.0/24")
    test_db.add(s)
    test_db.commit()
    return s


def _host(db, scan, ip, ports):
    h = Host(scan_id=scan.id, ip=ip)
    h.ports = ports
    db.add(h)
    db.commit()
    return h


def _vuln(db, host, cve, cvss, severity, kev=False, epss=None, match="cpe", service="svc", port="21/tcp"):
    v = Vulnerability(host_id=host.id, cve_id=cve, cvss=cvss, severity=severity,
                      kev=kev, epss=epss, match_type=match, affected_service=service, affected_port=port)
    db.add(v)
    db.commit()
    return v


def _assess(db, scan, host, vuln, maturity, lateral="LOW"):
    a = ExploitabilityAssessment(host_id=host.id, vuln_id=vuln.id, scan_id=scan.id,
                                 cve_id=vuln.cve_id, exploit_maturity=maturity,
                                 lateral_movement_potential=lateral)
    db.add(a)
    db.commit()
    return a


class TestScoring:

    def test_factors_sum_to_score_and_are_transparent(self, test_db, scan):
        host = _host(test_db, scan, "10.0.0.5", [{"port": 21, "state": "open", "service": "ftp"}])
        vuln = _vuln(test_db, host, "CVE-2011-2523", 9.8, "CRITICAL", kev=False, epss=0.96, match="cpe")
        a = _assess(test_db, scan, host, vuln, "WEAPONIZED", lateral="HIGH")

        scored = score_finding(vuln, a, host_exposure(host))

        keys = {f["key"] for f in scored["factors"]}
        assert keys == {"exploitation", "epss", "cvss", "confidence", "exposure", "lateral"}
        assert scored["score"] == round(min(100.0, sum(f["points"] for f in scored["factors"])), 1)
        assert scored["score"] >= 90.0   # weaponized + high EPSS + confirmed + exposure + lateral

    def test_kev_outweighs_a_plain_unknown(self, test_db, scan):
        host = _host(test_db, scan, "10.0.0.6", [{"port": 80, "state": "open", "service": "http"}])
        kev_v = _vuln(test_db, host, "CVE-2024-0001", 7.5, "HIGH", kev=True, epss=0.2)
        unk_v = _vuln(test_db, host, "CVE-2024-0002", 7.5, "HIGH", kev=False, epss=0.2)
        exp = host_exposure(host)

        kev_score = score_finding(kev_v, None, exp)["score"]
        unk_score = score_finding(unk_v, None, exp)["score"]
        assert kev_score > unk_score   # exploitation evidence dominates

    def test_weak_match_scores_below_confirmed(self, test_db, scan):
        host = _host(test_db, scan, "10.0.0.7", [{"port": 445, "state": "open", "service": "smb"}])
        conf = _vuln(test_db, host, "CVE-2024-0003", 8.0, "HIGH", match="cpe")
        weak = _vuln(test_db, host, "CVE-2024-0004", 8.0, "HIGH", match="keyword")
        exp = host_exposure(host)
        assert score_finding(conf, None, exp)["score"] > score_finding(weak, None, exp)["score"]

    def test_host_exposure_scales_with_open_ports(self, test_db, scan):
        bare = _host(test_db, scan, "10.0.0.8", [{"port": 80, "state": "open", "service": "http"}])
        busy = _host(test_db, scan, "10.0.0.9",
                     [{"port": p, "state": "open", "service": "ftp"} for p in range(1, 13)])
        assert host_exposure(busy)["points"] > host_exposure(bare)["points"]


class TestRanking:

    def test_vsftpd_backdoor_ranks_first(self, test_db, scan):
        host = _host(test_db, scan, "192.168.56.5",
                     [{"port": p, "state": "open", "service": s}
                      for p, s in [(21, "ftp"), (22, "ssh"), (80, "http"), (445, "smb")]])
        # The weaponized, high-EPSS, CPE-confirmed backdoor...
        vsftpd = _vuln(test_db, host, "CVE-2011-2523", 9.8, "CRITICAL", kev=False, epss=0.96, match="cpe")
        _assess(test_db, scan, host, vsftpd, "WEAPONIZED", lateral="HIGH")
        # ...vs a weak-match info-disclosure with no exploit evidence
        info = _vuln(test_db, host, "CVE-2010-1635", 5.0, "MEDIUM", kev=False, epss=0.01, match="keyword")
        _assess(test_db, scan, host, info, "UNKNOWN", lateral="LOW")

        ranked = prioritize_scan(scan.id, test_db)

        assert ranked[0]["cve_id"] == "CVE-2011-2523"
        assert ranked[0]["rank"] == 1
        assert ranked[0]["score"] > ranked[-1]["score"]

    def test_empty_scan_returns_nothing(self, test_db, scan):
        assert prioritize_scan(scan.id, test_db) == []
