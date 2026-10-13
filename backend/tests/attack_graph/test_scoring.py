"""
Tests for the evidence-based hop/path scoring: reachability, exploitability
(driven by Phase-4 evidence, not CVSS alone), impact, and the transparent
aggregation.
"""

from app.attack_graph import scoring


class _Vuln:
    def __init__(self, cve_id, cvss=0.0, kev=False, epss=None, match_type="cpe"):
        self.id = cve_id
        self.cve_id = cve_id
        self.cvss = cvss
        self.kev = kev
        self.epss = epss
        self.match_type = match_type


class _Assess:
    def __init__(self, maturity, attack_type="RCE"):
        self.exploit_maturity = maturity
        self.attack_type = attack_type


class TestReachability:
    def test_entry_is_fully_reachable(self):
        assert scoring.reachability(True, "0.0.0.0", "10.0.0.5", 21)["score"] == 100.0

    def test_same_subnet_lateral_is_high(self):
        assert scoring.reachability(False, "10.0.0.1", "10.0.0.9", 445)["score"] == 90.0

    def test_cross_subnet_is_lower(self):
        assert scoring.reachability(False, "10.0.0.1", "10.9.9.9", 445)["score"] == 55.0


class TestExploitability:
    def test_no_cve_is_service_exposure_only(self):
        r = scoring.exploitability({}, has_cve=False)
        assert r["score"] == 35.0 and "service-exposure" in r["detail"]

    def test_kev_is_highest(self):
        ev = {"kev": True, "epss": 0.9, "confirmed": True, "cvss": 9.8, "maturity": "WEAPONIZED", "cve_id": "CVE-X"}
        assert scoring.exploitability(ev, True)["score"] >= 95.0

    def test_weaponized_beats_unknown_at_same_cvss(self):
        strong = {"kev": False, "epss": None, "confirmed": True, "cvss": 9.8, "maturity": "WEAPONIZED", "cve_id": "A"}
        weak = {"kev": False, "epss": None, "confirmed": True, "cvss": 9.8, "maturity": "UNKNOWN", "cve_id": "B"}
        assert scoring.exploitability(strong, True)["score"] > scoring.exploitability(weak, True)["score"]

    def test_unknown_evidence_uses_cvss_and_penalises_weak_match(self):
        confirmed = {"kev": False, "epss": None, "confirmed": True, "cvss": 8.0, "maturity": "UNKNOWN", "cve_id": "A"}
        weak = {"kev": False, "epss": None, "confirmed": False, "cvss": 8.0, "maturity": "UNKNOWN", "cve_id": "B"}
        # a weak keyword match is worth half - evidence matters, not just CVSS
        assert scoring.exploitability(weak, True)["score"] < scoring.exploitability(confirmed, True)["score"]


class TestImpact:
    def test_rce_is_high(self):
        assert scoring.impact("REMOTE_ACCESS", "RCE", False, False)["score"] == 95.0

    def test_pivot_and_critical_add_gain(self):
        base = scoring.impact("REMOTE_ACCESS", "RCE", False, False)["score"]
        more = scoring.impact("REMOTE_ACCESS", "RCE", True, True)["score"]
        assert more > base


class TestScoreHop:
    def test_weighted_sum_and_justification(self):
        vulns = [_Vuln("CVE-2011-2523", cvss=9.8, kev=False, epss=0.96, match_type="cpe")]
        assessments = {"CVE-2011-2523": _Assess("WEAPONIZED", "RCE")}
        hop = scoring.score_hop(
            is_entry=True, is_pivot=False, attack_type="REMOTE_ACCESS",
            source_ip="0.0.0.0", source_label="ATTACKER", target_ip="192.168.56.5",
            port=21, service="ftp", vulns=vulns, assessments_by_vuln=assessments, target_critical=True,
        )
        assert hop["score"] == round(0.20 * hop["reachability"] + 0.50 * hop["exploitability"]
                                     + 0.30 * hop["impact"], 1)
        assert hop["exploitability"] >= 90.0        # weaponized + EPSS
        assert "CVE-2011-2523" in hop["justification"]
        assert "CPE-confirmed" in hop["justification"] and "EPSS 96%" in hop["justification"]
        assert {f["key"] for f in hop["factors"]} == {"reachability", "exploitability", "impact"}
        assert any(t["id"] == "T1190" for t in hop["mitre"])   # MITRE reference present

    def test_evidence_backed_hop_outranks_bare_service(self):
        backed = scoring.score_hop(True, False, "REMOTE_ACCESS", "0.0.0.0", "ATTACKER", "10.0.0.5",
                                   21, "ftp", [_Vuln("CVE-X", 9.8, kev=True, epss=0.9)],
                                   {"CVE-X": _Assess("WEAPONIZED")}, False)
        bare = scoring.score_hop(True, False, "REMOTE_ACCESS", "0.0.0.0", "ATTACKER", "10.0.0.6",
                                 21, "ftp", [], {}, False)
        assert backed["score"] > bare["score"]


class TestAggregatePath:
    def test_weakest_link_and_best_gain(self):
        hops = [{"reachability": 100.0, "exploitability": 95.0, "impact": 60.0},
                {"reachability": 90.0, "exploitability": 40.0, "impact": 95.0}]
        agg = scoring.aggregate_path(hops, hop_count=2)
        assert agg["reachability"] == 90.0     # weakest hop
        assert agg["exploitability"] == 40.0   # weakest hop
        assert agg["impact"] == 95.0           # best gain
        assert agg["score"] < 0.20 * 90 + 0.50 * 40 + 0.30 * 95   # length penalty applied

    def test_single_hop_has_no_penalty(self):
        hops = [{"reachability": 100.0, "exploitability": 90.0, "impact": 95.0}]
        agg = scoring.aggregate_path(hops, hop_count=1)
        assert agg["score"] == round(0.20 * 100 + 0.50 * 90 + 0.30 * 95, 1)
