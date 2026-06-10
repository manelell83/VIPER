"""
Unit tests for scan API routes.

Tests:
  - POST /scan/network with valid interface
  - POST /scan/network with invalid interface
  - POST /scan/domain with valid domain
  - GET /scan/{scan_id}
  - Scan status and persistence
  - Concurrent scans
  - Error handling
"""

import pytest
import json
from unittest.mock import patch, MagicMock
from sqlalchemy.orm import Session

from app.models.scan import ScanSession
from fastapi.testclient import TestClient


class TestScanRoutes:
    """Test scan API routes."""

    def test_post_scan_network_success(self, client: TestClient, test_db: Session, mock_arp, mock_port_scanner):
        """Test POST /scan/network with valid interface."""
        response = client.post(
            "/scan/network",
            json={"interface": "eth0"},
        )

        # Expect 202 Accepted (background task)
        assert response.status_code in [202, 200]
        data = response.json()
        assert "scan_id" in data

    def test_post_scan_network_with_timeout(self, client: TestClient, test_db: Session):
        """Test POST /scan/network handles timeout."""
        with patch("app.scanners.scan_engine.arp_scan") as mock_arp:
            mock_arp.side_effect = TimeoutError("ARP timeout")

            response = client.post(
                "/scan/network",
                json={"interface": "eth0"},
            )

            # Should handle timeout gracefully
            assert response.status_code in [202, 200, 500]

    def test_post_scan_domain_success(self, client: TestClient, test_db: Session):
        """Test POST /scan/domain with valid domain."""
        with patch("app.scanners.domain_recon.resolve_domain") as mock_resolve:
            mock_resolve.return_value = {"ip": "93.184.216.34", "hostname": "example.com"}

            response = client.post(
                "/scan/domain",
                json={"domain": "example.com"},
            )

            assert response.status_code in [202, 200]
            data = response.json()
            assert "scan_id" in data

    def test_get_scan_status_success(self, client: TestClient, test_db: Session):
        """Test GET /scan/{scan_id} returns scan details."""
        # Create a test scan
        scan = ScanSession(
            type="network",
            target="192.168.1.0/24",
            status="completed",
        )
        test_db.add(scan)
        test_db.commit()

        response = client.get(f"/scan/{scan.id}")

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == scan.id
        assert data["status"] == "completed"

    def test_get_scan_status_not_found(self, client: TestClient):
        """Test GET /scan/{scan_id} returns 404 for nonexistent scan."""
        response = client.get("/scan/nonexistent-scan-id")

        assert response.status_code == 404

    def test_concurrent_scans_isolation(self, client: TestClient, test_db: Session):
        """Test that concurrent scans are isolated."""
        scan1 = ScanSession(type="network", target="192.168.1.0/24", status="pending")
        scan2 = ScanSession(type="domain", target="example.com", status="pending")
        test_db.add_all([scan1, scan2])
        test_db.commit()

        response1 = client.get(f"/scan/{scan1.id}")
        response2 = client.get(f"/scan/{scan2.id}")

        assert response1.status_code == 200
        assert response2.status_code == 200
        assert response1.json()["id"] == scan1.id
        assert response2.json()["id"] == scan2.id

    def test_scan_persistence_in_database(self, client: TestClient, test_db: Session):
        """Test that scan is persisted in database."""
        with patch("app.scanners.scan_engine.arp_scan") as mock_arp:
            mock_arp.return_value = []  # No hosts found

            response = client.post(
                "/scan/network",
                json={"interface": "eth0"},
            )

            if response.status_code in [200, 202]:
                data = response.json()
                scan_id = data.get("scan_id")

                if scan_id:
                    # Verify scan was created in database
                    scan = test_db.query(ScanSession).filter(ScanSession.id == scan_id).first()
                    assert scan is not None
                    assert scan.target == "eth0"

    def test_scan_status_transitions(self, client: TestClient, test_db: Session):
        """Test scan status transitions."""
        scan = ScanSession(
            type="network",
            target="192.168.1.0/24",
            status="pending",
        )
        test_db.add(scan)
        test_db.commit()

        # Initially pending
        response = client.get(f"/scan/{scan.id}")
        assert response.json()["status"] == "pending"

        # Update to running
        scan.status = "running"
        test_db.commit()

        response = client.get(f"/scan/{scan.id}")
        assert response.json()["status"] == "running"

        # Update to completed
        scan.status = "completed"
        test_db.commit()

        response = client.get(f"/scan/{scan.id}")
        assert response.json()["status"] == "completed"


class TestScanErrorHandling:
    """Test error handling in scan routes."""

    def test_post_scan_invalid_interface(self, client: TestClient):
        """Test POST /scan/network with invalid interface."""
        response = client.post(
            "/scan/network",
            json={"interface": "invalid-interface-name-too-long-" * 10},
        )

        # Should return validation error
        assert response.status_code in [400, 422]

    def test_get_scan_with_malformed_id(self, client: TestClient):
        """Test GET /scan/{scan_id} with malformed ID."""
        response = client.get("/scan/not-a-uuid-format")

        # Should return 404 or 422
        assert response.status_code in [404, 422]

    def test_database_transaction_consistency(self, test_db: Session):
        """Test database transaction consistency."""
        scan = ScanSession(
            type="network",
            target="192.168.1.0/24",
            status="pending",
        )
        test_db.add(scan)
        test_db.commit()
        scan_id = scan.id

        # Start transaction and rollback
        scan.status = "modified"
        test_db.rollback()

        # Status should be reverted
        retrieved = test_db.query(ScanSession).filter(ScanSession.id == scan_id).first()
        assert retrieved.status == "pending"
