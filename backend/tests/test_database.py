"""
Unit tests for database configuration.

Tests:
  - Database connection
  - Session management (get_db fixture)
  - CASCADE DELETE behavior
  - Foreign key constraints
  - Transaction rollback
  - Connection functionality
"""

import pytest
from sqlalchemy.orm import Session
from app.models.scan import ScanSession, Host
from app.vulnerability_scanner.models import Vulnerability
from app.core.database import engine, Base


class TestDatabaseConnection:
    """Test database connection and setup."""

    def test_database_engine_creation(self):
        """Test that database engine is created."""
        assert engine is not None

    def test_base_metadata_created(self):
        """Test that Base metadata is created."""
        assert Base.metadata is not None
        assert len(Base.metadata.tables) > 0


class TestSessionManagement:
    """Test session management."""

    def test_get_db_fixture(self, test_db: Session):
        """Test get_db fixture creates a session."""
        assert test_db is not None

    def test_session_add_and_commit(self, test_db: Session):
        """Test adding and committing to session."""
        scan = ScanSession(
            type="network",
            target="192.168.1.0/24",
            status="pending",
        )
        test_db.add(scan)
        test_db.commit()

        retrieved = test_db.query(ScanSession).filter(ScanSession.id == scan.id).first()
        assert retrieved is not None
        assert retrieved.id == scan.id

    def test_session_rollback(self, test_db: Session):
        """Test session rollback."""
        scan = ScanSession(
            type="network",
            target="192.168.1.0/24",
            status="pending",
        )
        test_db.add(scan)
        scan_id = scan.id
        test_db.rollback()

        # Should not be in database after rollback
        retrieved = test_db.query(ScanSession).filter(ScanSession.id == scan_id).first()
        assert retrieved is None


class TestCascadeDelete:
    """Test CASCADE DELETE behavior."""

    def test_scan_delete_cascades_to_hosts(self, test_db: Session):
        """Test that deleting scan cascades to hosts."""
        scan = ScanSession(type="network", target="192.168.1.0/24", status="pending")
        test_db.add(scan)
        test_db.commit()

        host = Host(
            scan_id=scan.id,
            ip="192.168.1.100",
            mac="aa:bb:cc:dd:ee:ff",
        )
        test_db.add(host)
        test_db.commit()
        host_id = host.id

        # Delete scan
        test_db.delete(scan)
        test_db.commit()

        # Host should be deleted
        retrieved = test_db.query(Host).filter(Host.id == host_id).first()
        assert retrieved is None

    def test_host_delete_cascades_to_vulnerabilities(self, test_db: Session):
        """Test that deleting host cascades to vulnerabilities."""
        scan = ScanSession(type="network", target="192.168.1.0/24", status="pending")
        test_db.add(scan)
        test_db.commit()

        host = Host(
            scan_id=scan.id,
            ip="192.168.1.100",
            mac="aa:bb:cc:dd:ee:ff",
        )
        test_db.add(host)
        test_db.commit()

        vuln = Vulnerability(
            host_id=host.id,
            cve_id="CVE-2023-0001",
            cvss=7.5,
            severity="HIGH",
        )
        test_db.add(vuln)
        test_db.commit()
        vuln_id = vuln.id

        # Delete host
        test_db.delete(host)
        test_db.commit()

        # Vulnerability should be deleted
        retrieved = test_db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
        assert retrieved is None


class TestForeignKeyConstraints:
    """Test foreign key constraints."""

    def test_host_requires_valid_scan_id(self, test_db: Session):
        """Test that host requires valid scan_id."""
        host = Host(
            scan_id="invalid-scan-id-that-doesnt-exist",
            ip="192.168.1.100",
            mac="aa:bb:cc:dd:ee:ff",
        )
        test_db.add(host)

        # This should fail on commit due to foreign key constraint
        with pytest.raises(Exception):
            test_db.commit()

    def test_vulnerability_requires_valid_host_id(self, test_db: Session):
        """Test that vulnerability requires valid host_id."""
        vuln = Vulnerability(
            host_id="invalid-host-id",
            cve_id="CVE-2023-0001",
            cvss=7.5,
            severity="HIGH",
        )
        test_db.add(vuln)

        # This should fail on commit due to foreign key constraint
        with pytest.raises(Exception):
            test_db.commit()


class TestDatabaseIntegrity:
    """Test overall database integrity."""

    def test_multiple_scans_isolation(self, test_db: Session):
        """Test that multiple scans are isolated."""
        scan1 = ScanSession(type="network", target="192.168.1.0/24", status="pending")
        scan2 = ScanSession(type="domain", target="example.com", status="pending")
        test_db.add_all([scan1, scan2])
        test_db.commit()

        host1 = Host(scan_id=scan1.id, ip="192.168.1.100", mac="aa:bb:cc:dd:ee:01")
        host2 = Host(scan_id=scan2.id, ip="10.0.0.1", mac="aa:bb:cc:dd:ee:02")
        test_db.add_all([host1, host2])
        test_db.commit()

        # Verify isolation
        hosts_scan1 = test_db.query(Host).filter(Host.scan_id == scan1.id).all()
        hosts_scan2 = test_db.query(Host).filter(Host.scan_id == scan2.id).all()

        assert len(hosts_scan1) == 1
        assert len(hosts_scan2) == 1
        assert hosts_scan1[0].ip == "192.168.1.100"
        assert hosts_scan2[0].ip == "10.0.0.1"
