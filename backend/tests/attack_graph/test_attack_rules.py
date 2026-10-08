"""
Unit tests for the attack rule matching (attack_rules.py).

A rule matches a host if one of its ports is open or one of its service
keywords appears in a service name. If CVEs are linked to the rule, the score
is boosted:  score = base × (1 + cvss/10 × (cvss_multiplier − 1)), capped at 100.
CVE-only rules (privilege escalation) match on CVSS alone.
"""

from types import SimpleNamespace

from app.attack_graph.attack_rules import evaluate_host_rules


def _vuln(cve_id, cvss, port="", service=""):
    return SimpleNamespace(cve_id=cve_id, cvss=cvss, affected_port=port, affected_service=service)


def _matched(results):
    return {rule.id: (score, cves) for rule, score, cves in results}


class TestPortAndServiceMatching:

    def test_no_ports_and_no_cves_matches_nothing(self):
        assert evaluate_host_rules([], [], []) == []

    def test_matches_on_open_port(self):
        matched = _matched(evaluate_host_rules([22], [""], []))

        assert matched["ssh_remote"] == (65.0, [])      # base score, no CVE boost

    def test_matches_on_service_keyword(self):
        # Non-standard port, but nmap identified the service as ssh
        matched = _matched(evaluate_host_rules([2222], ["ssh"], []))

        assert "ssh_remote" in matched

    def test_unrelated_port_matches_nothing(self):
        assert evaluate_host_rules([12345], ["unknown"], []) == []


class TestCveBoost:

    def test_linked_cve_boosts_score(self):
        vulns = [_vuln("CVE-A", 10.0, port="22/tcp", service="OpenSSH 8.2")]

        score, cves = _matched(evaluate_host_rules([22], ["ssh"], vulns))["ssh_remote"]

        # 65 × (1 + 10/10 × (1.4 − 1)) = 65 × 1.4 = 91.0
        assert score == 91.0
        assert cves == ["CVE-A"]

    def test_score_is_capped_at_100(self):
        vulns = [_vuln("CVE-A", 10.0, port="6379/tcp", service="Redis")]

        for _, score, _ in evaluate_host_rules([6379], ["redis"], vulns):
            assert score <= 100.0


class TestPrivilegeEscalationRules:

    def test_critical_cve_triggers_both_privesc_rules(self):
        matched = _matched(evaluate_host_rules([], [], [_vuln("CVE-A", 9.8)]))

        assert {"priv_esc_critical", "priv_esc_high"} <= matched.keys()
        assert matched["priv_esc_critical"][1] == ["CVE-A"]

    def test_high_cve_triggers_only_high_rule(self):
        matched = _matched(evaluate_host_rules([], [], [_vuln("CVE-A", 8.9)]))

        assert "priv_esc_high" in matched
        assert "priv_esc_critical" not in matched

    def test_medium_cve_triggers_no_privesc(self):
        assert evaluate_host_rules([], [], [_vuln("CVE-A", 6.9)]) == []
