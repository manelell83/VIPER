"""
Unit tests for database models.

Tests:
  - ScanSession model creation
  - Host model relationships
  - Vulnerability model cascade
  - AttackGraph serialization
  - UUID primary key generation
  - JSON field deserialization
  - Model validation
  - Default values
"""

import pytest
from uuid import uuid4
from datetime import datetime
from sqlalchemy.orm import Session

from app.models.scan import ScanSession, Host
from app.vulnerability_scanner.models import Vulnerability
from app.attack_graph.models import AttackGraph, AttackNode, AttackEdge, AttackPath


class TestScanSessionModel:
    """Test ScanSession model."""

    def test_scan_session_creation(self, test_db: Session):
        """Test creating a ScanSession."""
        scan = ScanSession(
            id="test-scan-001",
            type="network",
            target="192.168.1.0/24",
            status="pending",
            started_at=datetime.utcnow(),
        )
        test_db.add(scan)
        test_db.commit()

        retrieved = test_db.query(ScanSession).filter(ScanSession.id == "test-scan-001").first()
        assert retrieved is not None
        assert retrieved.type == "network"
        assert retrieved.status == "pending"

    def test_scan_session_uuid_primary_key(self, test_db: Session):
        """Test that scan_id is UUID."""
        scan = ScanSession(
            type="network",
            target="192.168.1.0/24",
            status="pending",
        )
        test_db.add(scan)
        test_db.commit()

        assert scan.id is not None
        assert isinstance(scan.id, str)
        assert len(scan.id) == 36  # UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx


class TestHostModel:
    """Test Host model."""

    @pytest.fixture
    def scan_session(self, test_db: Session):
        """Create a test scan session."""
        scan = ScanSession(
            type="network",
            target="192.168.1.0/24",
            status="pending",
        )
        test_db.add(scan)
        test_db.commit()
        return scan

    def test_host_creation(self, test_db: Session, scan_session: ScanSession):
        """Test creating a Host."""
        host = Host(
            scan_id=scan_session.id,
            ip="192.168.1.100",
            mac="aa:bb:cc:dd:ee:ff",
            hostname="test-host",
            os="Linux",
        )
        test_db.add(host)
        test_db.commit()

        retrieved = test_db.query(Host).filter(Host.ip == "192.168.1.100").first()
        assert retrieved is not None
        assert retrieved.hostname == "test-host"
        assert retrieved.os == "Linux"

    def test_host_cascade_delete(self, test_db: Session, scan_session: ScanSession):
        """Test that deleting scan deletes hosts."""
        host = Host(
            scan_id=scan_session.id,
            ip="192.168.1.100",
            mac="aa:bb:cc:dd:ee:ff",
            hostname="test-host",
        )
        test_db.add(host)
        test_db.commit()

        # Delete scan
        test_db.delete(scan_session)
        test_db.commit()

        # Host should be deleted
        retrieved = test_db.query(Host).filter(Host.ip == "192.168.1.100").first()
        assert retrieved is None

    def test_host_ports_json_field(self, test_db: Session, scan_session: ScanSession):
        """Test Host ports JSON field."""
        ports = [
            {"port": 22, "service": "ssh", "state": "open"},
            {"port": 80, "service": "http", "state": "open"},
        ]
        host = Host(
            scan_id=scan_session.id,
            ip="192.168.1.100",
            mac="aa:bb:cc:dd:ee:ff",
            ports=ports,
        )
        test_db.add(host)
        test_db.commit()

        retrieved = test_db.query(Host).filter(Host.ip == "192.168.1.100").first()
        assert retrieved.ports == ports
        assert len(retrieved.ports) == 2


class TestVulnerabilityModel:
    """Test Vulnerability model."""

    @pytest.fixture
    def host_with_scan(self, test_db: Session):
        """Create a test host within a scan."""
        scan = ScanSession(type="network", target="192.168.1.0/24", status="pending")
        test_db.add(scan)
        test_db.commit()

        host = Host(scan_id=scan.id, ip="192.168.1.100", mac="aa:bb:cc:dd:ee:ff")
        test_db.add(host)
        test_db.commit()
        return host

    def test_vulnerability_creation(self, test_db: Session, host_with_scan: Host):
        """Test creating a Vulnerability."""
        vuln = Vulnerability(
            host_id=host_with_scan.id,
            cve_id="CVE-2023-0001",
            cvss=7.5,
            severity="HIGH",
            description="Test vulnerability",
            affected_service="OpenSSH",
            affected_port=22,
        )
        test_db.add(vuln)
        test_db.commit()

        retrieved = test_db.query(Vulnerability).filter(
            Vulnerability.cve_id == "CVE-2023-0001"
        ).first()
        assert retrieved is not None
        assert retrieved.severity == "HIGH"
        assert retrieved.cvss == 7.5

    def test_vulnerability_cascade_delete(self, test_db: Session, host_with_scan: Host):
        """Test that deleting host deletes vulnerabilities."""
        vuln = Vulnerability(
            host_id=host_with_scan.id,
            cve_id="CVE-2023-0001",
            cvss=7.5,
            severity="HIGH",
        )
        test_db.add(vuln)
        test_db.commit()

        # Delete host
        test_db.delete(host_with_scan)
        test_db.commit()

        # Vulnerability should be deleted
        retrieved = test_db.query(Vulnerability).filter(
            Vulnerability.cve_id == "CVE-2023-0001"
        ).first()
        assert retrieved is None


class TestAttackGraphModel:
    """Test AttackGraph model."""

    @pytest.fixture
    def scan_with_graph(self, test_db: Session):
        """Create a test scan with attack graph."""
        scan = ScanSession(type="network", target="192.168.1.0/24", status="completed")
        test_db.add(scan)
        test_db.commit()

        graph = AttackGraph(
            scan_id=scan.id,
            node_count=5,
            edge_count=8,
            path_count=3,
            network_risk_level="HIGH",
        )
        test_db.add(graph)
        test_db.commit()
        return scan, graph

    def test_attack_graph_serialization(self, test_db: Session, scan_with_graph):
        """Test AttackGraph .to_dict() serialization."""
        scan, graph = scan_with_graph
        graph_dict = graph.to_dict()

        assert graph_dict["id"] == graph.id
        assert graph_dict["scan_id"] == scan.id
        assert graph_dict["node_count"] == 5
        assert graph_dict["edge_count"] == 8
        assert graph_dict["network_risk_level"] == "HIGH"

    def test_attack_node_creation(self, test_db: Session, scan_with_graph):
        """Test creating AttackNode."""
        scan, graph = scan_with_graph

        node = AttackNode(
            graph_id=graph.id,
            node_type="ENTRY",
            label="192.168.1.100",
            ip="192.168.1.100",
            risk_score=85.0,
            is_entry_point=True,
        )
        test_db.add(node)
        test_db.commit()

        retrieved = test_db.query(AttackNode).filter(AttackNode.ip == "192.168.1.100").first()
        assert retrieved is not None
        assert retrieved.risk_score == 85.0
        assert retrieved.is_entry_point is True

    def test_attack_edge_creation(self, test_db: Session, scan_with_graph):
        """Test creating AttackEdge with cve_ids_json."""
        scan, graph = scan_with_graph

        # Create nodes first
        node1 = AttackNode(
            graph_id=graph.id,
            node_type="ATTACKER",
            label="Attacker",
            ip="0.0.0.0",
            risk_score=100.0,
        )
        node2 = AttackNode(
            graph_id=graph.id,
            node_type="ENTRY",
            label="192.168.1.100",
            ip="192.168.1.100",
            risk_score=85.0,
        )
        test_db.add_all([node1, node2])
        test_db.commit()

        # Create edge with cve_ids_json
        edge = AttackEdge(
            graph_id=graph.id,
            source_node_id=node1.id,
            target_node_id=node2.id,
            attack_type="REMOTE_ACCESS",
            port=22,
            service="ssh",
            cvss=7.5,
            cve_ids_json='["CVE-2023-0001", "CVE-2023-0002"]',
            score=75.0,
        )
        test_db.add(edge)
        test_db.commit()

        retrieved = test_db.query(AttackEdge).filter(
            AttackEdge.source_node_id == node1.id
        ).first()
        assert retrieved is not None
        assert retrieved.cve_ids_json == '["CVE-2023-0001", "CVE-2023-0002"]'
        assert retrieved.attack_type == "REMOTE_ACCESS"

    def test_attack_path_cve_ids_json(self, test_db: Session, scan_with_graph):
        """Test AttackPath with cve_ids_json field."""
        scan, graph = scan_with_graph

        path = AttackPath(
            graph_id=graph.id,
            path_node_ids_json='["node1", "node2", "node3"]',
            path_ips_json='["0.0.0.0", "192.168.1.100", "192.168.1.101"]',
            total_score=75.5,
            hop_count=2,
            severity="HIGH",
            cve_ids_json='["CVE-2023-0001", "CVE-2023-0002"]',
        )
        test_db.add(path)
        test_db.commit()

        retrieved = test_db.query(AttackPath).first()
        assert retrieved is not None
        assert retrieved.cve_ids_json == '["CVE-2023-0001", "CVE-2023-0002"]'

        # Test .to_dict() includes proper deserialization
        path_dict = retrieved.to_dict()
        assert path_dict["cve_ids"] == ["CVE-2023-0001", "CVE-2023-0002"]
