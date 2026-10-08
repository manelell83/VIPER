"""
Unit tests for attack graph construction (graph_builder.py) and
attack path enumeration with NetworkX (path_engine.py).

Scenario used by most tests (no CVEs, so scores are the rules' base scores):

    10.0.0.1  port 22 (ssh)    → ssh_remote: entry point + pivot, base 65
    10.0.0.2  port 5985 (winrm)→ winrm_lateral: pivot only (not an entry point), base 72
    10.0.0.3  port 12345       → no rule matches → unreachable

Expected graph:
    ATTACKER ──65.0──▶ 10.0.0.1 ──61.2──▶ 10.0.0.2       (61.2 = 72 × 0.85 lateral penalty)

Expected paths (score = mean edge score − 3 × (hops − 1)):
    ATTACKER → .1        65.0           → HIGH
    ATTACKER → .1 → .2   63.1 − 3 = 60.1 → HIGH
"""

import pytest
from sqlalchemy.orm import Session

from app.attack_graph.graph_builder import build_attack_graph
from app.attack_graph.models import AttackEdge, AttackNode
from app.attack_graph.path_engine import generate_attack_paths, _score_to_severity
from app.models.scan import Host, ScanSession
from app.vulnerability_scanner.models import Vulnerability


def _add_host(db, scan_id, ip, port, service):
    host = Host(scan_id=scan_id, ip=ip)
    host.ports = [{"port": port, "protocol": "tcp", "state": "open", "service": service}]
    db.add(host)
    db.commit()
    return host


@pytest.fixture
def scan(test_db: Session):
    scan = ScanSession(type="network", target="10.0.0.0/24", status="completed")
    test_db.add(scan)
    test_db.commit()
    _add_host(test_db, scan.id, "10.0.0.1", 22, "ssh")
    _add_host(test_db, scan.id, "10.0.0.2", 5985, "wsman")
    _add_host(test_db, scan.id, "10.0.0.3", 12345, "unknown")
    return scan


def _nodes_by_ip(db, graph):
    return {n.ip: n for n in db.query(AttackNode).filter(AttackNode.graph_id == graph.id)}


class TestBuildAttackGraph:

    def test_scan_without_hosts_returns_none(self, test_db: Session):
        empty = ScanSession(type="network", target="10.0.0.0/24")
        test_db.add(empty)
        test_db.commit()

        assert build_attack_graph(empty.id, test_db) is None

    def test_creates_one_attacker_node_plus_one_node_per_host(self, test_db, scan):
        graph = build_attack_graph(scan.id, test_db)

        nodes = _nodes_by_ip(test_db, graph)
        assert graph.node_count == 4
        assert nodes["0.0.0.0"].node_type == "ATTACKER"
        assert nodes["10.0.0.1"].node_type == "PIVOT"     # entry + pivot, but no critical CVE
        assert nodes["10.0.0.2"].node_type == "PIVOT"
        assert nodes["10.0.0.3"].node_type == "INTERNAL"
        assert graph.entry_point_count == 1

    def test_entry_and_lateral_edges(self, test_db, scan):
        graph = build_attack_graph(scan.id, test_db)
        nodes = _nodes_by_ip(test_db, graph)
        ip_of = {n.id: ip for ip, n in nodes.items()}

        edges = {
            (ip_of[e.source_node_id], ip_of[e.target_node_id]): e
            for e in test_db.query(AttackEdge).filter(AttackEdge.graph_id == graph.id)
        }

        assert set(edges) == {("0.0.0.0", "10.0.0.1"), ("10.0.0.1", "10.0.0.2")}
        assert edges[("0.0.0.0", "10.0.0.1")].attack_type == "REMOTE_ACCESS"
        assert edges[("0.0.0.0", "10.0.0.1")].score == 65.0
        assert edges[("10.0.0.1", "10.0.0.2")].attack_type == "LATERAL_MOVEMENT"
        assert edges[("10.0.0.1", "10.0.0.2")].score == 61.2

    def test_critical_cve_makes_entry_host_an_entry_node(self, test_db, scan):
        host = test_db.query(Host).filter(Host.ip == "10.0.0.1").one()
        test_db.add(Vulnerability(host_id=host.id, cve_id="CVE-A", cvss=9.8,
                                  severity="CRITICAL", affected_port="22/tcp"))
        test_db.commit()

        graph = build_attack_graph(scan.id, test_db)

        node = _nodes_by_ip(test_db, graph)["10.0.0.1"]
        assert node.node_type == "ENTRY"
        assert node.is_critical

    def test_rebuilding_replaces_the_previous_graph(self, test_db, scan):
        first = build_attack_graph(scan.id, test_db)
        first_id = first.id

        second = build_attack_graph(scan.id, test_db)

        assert second.id != first_id
        assert test_db.query(AttackNode).filter(AttackNode.graph_id == first_id).count() == 0

    def test_graphs_of_different_scans_coexist(self, test_db, scan):
        other = ScanSession(type="domain", target="10.0.0.9")
        test_db.add(other)
        test_db.commit()
        _add_host(test_db, other.id, "10.0.0.9", 22, "ssh")

        assert build_attack_graph(scan.id, test_db) is not None
        assert build_attack_graph(other.id, test_db) is not None


class TestGenerateAttackPaths:

    def test_paths_and_scores(self, test_db, scan):
        graph = build_attack_graph(scan.id, test_db)

        paths = generate_attack_paths(graph, test_db)

        by_target = {p.target_ip: p for p in paths}
        assert set(by_target) == {"10.0.0.1", "10.0.0.2"}    # 10.0.0.3 is unreachable

        direct = by_target["10.0.0.1"]
        assert direct.hop_count == 1
        assert direct.total_score == 65.0
        assert direct.severity == "HIGH"

        lateral = by_target["10.0.0.2"]
        assert lateral.hop_count == 2
        assert lateral.entry_ip == "10.0.0.1"
        assert lateral.total_score == 60.1     # (65 + 61.2) / 2 − 3
        assert lateral.severity == "HIGH"

    def test_graph_summary_is_updated(self, test_db, scan):
        graph = build_attack_graph(scan.id, test_db)

        generate_attack_paths(graph, test_db)

        assert graph.path_count == 2
        assert graph.network_risk_level == "HIGH"   # from the best path score (65.0)

    def test_regenerating_paths_does_not_duplicate_them(self, test_db, scan):
        graph = build_attack_graph(scan.id, test_db)

        generate_attack_paths(graph, test_db)
        paths = generate_attack_paths(graph, test_db)

        assert len(paths) == 2
        assert graph.path_count == 2


class TestPathSeverity:

    @pytest.mark.parametrize("score, severity", [
        (80, "CRITICAL"), (79.9, "HIGH"), (60, "HIGH"),
        (59.9, "MEDIUM"), (40, "MEDIUM"), (39.9, "LOW"), (0, "LOW"),
    ])
    def test_thresholds(self, score, severity):
        assert _score_to_severity(score) == severity
