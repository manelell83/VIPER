"""
Unit tests for attack graph routes.

Tests:
  - GET /attack-graph/{scan_id}
  - Graph node/edge counts
  - AttackNode types
  - AttackNode risk_score range
  - AttackEdge validation
  - Path scoring
  - Network risk level
"""

import pytest
import json
from sqlalchemy.orm import Session
from fastapi.testclient import TestClient

from app.models.scan import ScanSession, Host
from app.attack_graph.models import AttackGraph, AttackNode, AttackEdge, AttackPath
from app.vulnerability_scanner.models import Vulnerability


class TestAttackGraphRoutes:
    """Test attack graph API routes."""

    @pytest.fixture
    def scan_with_attack_graph(self, test_db: Session):
        """Create a test scan with attack graph."""
        scan = ScanSession(type="network", target="192.168.1.0/24", status="completed")
        test_db.add(scan)
        test_db.commit()

        graph = AttackGraph(
            scan_id=scan.id,
            node_count=5,
            edge_count=8,
            path_count=3,
            entry_point_count=2,
            network_risk_level="HIGH",
        )
        test_db.add(graph)
        test_db.commit()

        # Create nodes
        attacker = AttackNode(
            graph_id=graph.id,
            node_type="ATTACKER",
            label="Attacker",
            ip="0.0.0.0",
            risk_score=100.0,
        )
        entry = AttackNode(
            graph_id=graph.id,
            node_type="ENTRY",
            label="192.168.1.100",
            ip="192.168.1.100",
            risk_score=85.0,
            is_entry_point=True,
        )
        pivot = AttackNode(
            graph_id=graph.id,
            node_type="PIVOT",
            label="192.168.1.101",
            ip="192.168.1.101",
            risk_score=72.0,
        )
        target = AttackNode(
            graph_id=graph.id,
            node_type="TARGET",
            label="192.168.1.102",
            ip="192.168.1.102",
            risk_score=95.0,
        )
        test_db.add_all([attacker, entry, pivot, target])
        test_db.commit()

        # Create edges
        edge1 = AttackEdge(
            graph_id=graph.id,
            source_node_id=attacker.id,
            target_node_id=entry.id,
            attack_type="REMOTE_ACCESS",
            port=22,
            service="ssh",
            cvss=7.5,
            cve_ids_json='["CVE-2023-0001"]',
            score=75.0,
        )
        edge2 = AttackEdge(
            graph_id=graph.id,
            source_node_id=entry.id,
            target_node_id=pivot.id,
            attack_type="LATERAL_MOVEMENT",
            port=445,
            service="smb",
            cvss=8.0,
            cve_ids_json='["CVE-2023-0002"]',
            score=80.0,
        )
        test_db.add_all([edge1, edge2])
        test_db.commit()

        return scan, graph, [attacker, entry, pivot, target], [edge1, edge2]

    def test_get_attack_graph_success(self, client: TestClient, scan_with_attack_graph):
        """Test GET /attack-graph/{scan_id} returns graph data."""
        scan, graph, nodes, edges = scan_with_attack_graph

        response = client.get(f"/attack-graph/{scan.id}")

        assert response.status_code == 200
        data = response.json()
        assert "id" in data or "nodes" in data

    def test_get_attack_graph_not_found(self, client: TestClient):
        """Test GET /attack-graph/{scan_id} returns 404 for nonexistent scan."""
        response = client.get("/attack-graph/nonexistent-scan-id")

        assert response.status_code == 404

    def test_attack_node_types(self, test_db: Session):
        """Test all AttackNode types are valid."""
        valid_types = ["ATTACKER", "ENTRY", "PIVOT", "TARGET", "INTERNAL"]

        scan = ScanSession(type="network", target="192.168.1.0/24", status="completed")
        test_db.add(scan)
        test_db.commit()

        graph = AttackGraph(scan_id=scan.id)
        test_db.add(graph)
        test_db.commit()

        for node_type in valid_types:
            node = AttackNode(
                graph_id=graph.id,
                node_type=node_type,
                label=f"node-{node_type}",
                ip="192.168.1.1",
            )
            test_db.add(node)
        test_db.commit()

        # Verify all nodes were created
        nodes = test_db.query(AttackNode).filter(AttackNode.graph_id == graph.id).all()
        assert len(nodes) == len(valid_types)

    def test_attack_node_risk_score_range(self, test_db: Session):
        """Test AttackNode risk_score is in valid range [0, 100]."""
        scan = ScanSession(type="network", target="192.168.1.0/24", status="completed")
        test_db.add(scan)
        test_db.commit()

        graph = AttackGraph(scan_id=scan.id)
        test_db.add(graph)
        test_db.commit()

        # Test boundary values
        node1 = AttackNode(
            graph_id=graph.id,
            node_type="ENTRY",
            label="node-0",
            ip="192.168.1.1",
            risk_score=0.0,
        )
        node2 = AttackNode(
            graph_id=graph.id,
            node_type="ENTRY",
            label="node-100",
            ip="192.168.1.2",
            risk_score=100.0,
        )
        node3 = AttackNode(
            graph_id=graph.id,
            node_type="ENTRY",
            label="node-50",
            ip="192.168.1.3",
            risk_score=50.0,
        )
        test_db.add_all([node1, node2, node3])
        test_db.commit()

        nodes = test_db.query(AttackNode).filter(AttackNode.graph_id == graph.id).all()
        for node in nodes:
            assert 0 <= node.risk_score <= 100

    def test_attack_edge_attack_types(self, test_db: Session):
        """Test AttackEdge attack_type values."""
        valid_types = ["REMOTE_ACCESS", "LATERAL_MOVEMENT", "PRIVILEGE_ESCALATION", "DATA_ACCESS"]

        scan = ScanSession(type="network", target="192.168.1.0/24", status="completed")
        test_db.add(scan)
        test_db.commit()

        graph = AttackGraph(scan_id=scan.id)
        test_db.add(graph)
        test_db.commit()

        node1 = AttackNode(graph_id=graph.id, node_type="ENTRY", label="n1", ip="192.168.1.1")
        node2 = AttackNode(graph_id=graph.id, node_type="ENTRY", label="n2", ip="192.168.1.2")
        test_db.add_all([node1, node2])
        test_db.commit()

        for attack_type in valid_types:
            edge = AttackEdge(
                graph_id=graph.id,
                source_node_id=node1.id,
                target_node_id=node2.id,
                attack_type=attack_type,
                score=50.0,
            )
            test_db.add(edge)
        test_db.commit()

        edges = test_db.query(AttackEdge).filter(AttackEdge.graph_id == graph.id).all()
        assert len(edges) == len(valid_types)

    def test_attack_edge_cve_ids_json_field(self, test_db: Session):
        """Test AttackEdge cve_ids_json field contains valid JSON."""
        scan = ScanSession(type="network", target="192.168.1.0/24", status="completed")
        test_db.add(scan)
        test_db.commit()

        graph = AttackGraph(scan_id=scan.id)
        test_db.add(graph)
        test_db.commit()

        node1 = AttackNode(graph_id=graph.id, node_type="ENTRY", label="n1", ip="192.168.1.1")
        node2 = AttackNode(graph_id=graph.id, node_type="ENTRY", label="n2", ip="192.168.1.2")
        test_db.add_all([node1, node2])
        test_db.commit()

        cve_ids_json = '["CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003"]'
        edge = AttackEdge(
            graph_id=graph.id,
            source_node_id=node1.id,
            target_node_id=node2.id,
            attack_type="REMOTE_ACCESS",
            cve_ids_json=cve_ids_json,
            score=75.0,
        )
        test_db.add(edge)
        test_db.commit()

        retrieved = test_db.query(AttackEdge).filter(AttackEdge.graph_id == graph.id).first()
        assert retrieved.cve_ids_json == cve_ids_json

        # Verify JSON is valid
        parsed = json.loads(retrieved.cve_ids_json)
        assert len(parsed) == 3
        assert "CVE-2023-0001" in parsed

    def test_attack_path_scoring(self, test_db: Session):
        """Test AttackPath scoring."""
        scan = ScanSession(type="network", target="192.168.1.0/24", status="completed")
        test_db.add(scan)
        test_db.commit()

        graph = AttackGraph(scan_id=scan.id)
        test_db.add(graph)
        test_db.commit()

        path = AttackPath(
            graph_id=graph.id,
            path_node_ids_json='["node1", "node2", "node3"]',
            path_ips_json='["0.0.0.0", "192.168.1.100", "192.168.1.101"]',
            total_score=85.5,
            hop_count=2,
            severity="HIGH",
        )
        test_db.add(path)
        test_db.commit()

        retrieved = test_db.query(AttackPath).first()
        assert retrieved.total_score == 85.5
        assert retrieved.hop_count == 2
        assert retrieved.severity == "HIGH"

    def test_network_risk_level_classification(self, test_db: Session):
        """Test network risk level classification."""
        valid_levels = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

        scan = ScanSession(type="network", target="192.168.1.0/24", status="completed")
        test_db.add(scan)
        test_db.commit()

        for level in valid_levels:
            graph = AttackGraph(
                scan_id=scan.id,
                network_risk_level=level,
            )
            test_db.add(graph)
        test_db.commit()

        graphs = test_db.query(AttackGraph).filter(AttackGraph.scan_id == scan.id).all()
        for graph in graphs:
            assert graph.network_risk_level in valid_levels
