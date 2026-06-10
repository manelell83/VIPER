"""
Pytest configuration and shared fixtures.

Fixtures:
  - test_db: In-memory SQLite database for isolated tests
  - client: FastAPI TestClient connected to test_db
  - mock_nvd: Mock NVD API responses
  - mock_arp: Mock ARP scanner
  - event_loop: Async event loop for asyncio tests
"""

import pytest
import asyncio
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch, MagicMock

from app.main import app
from app.core.database import Base, get_db


# In-memory SQLite database
@pytest.fixture(scope="function")
def test_db() -> Session:
    """Create an in-memory SQLite database for each test."""
    engine = create_engine("sqlite:///:memory:")

    # Enable foreign keys for SQLite
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()

    yield db

    db.close()


# FastAPI TestClient
@pytest.fixture(scope="function")
def client(test_db: Session):
    """Create a FastAPI TestClient with test database."""
    def override_get_db():
        try:
            yield test_db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


# Event loop for async tests
@pytest.fixture(scope="function")
def event_loop():
    """Create an event loop for asyncio tests."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


# Mock NVD API
@pytest.fixture
def mock_nvd():
    """Mock NVD API responses."""
    mock_response = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-0001",
                    "description": {
                        "description_data": [
                            {"value": "Test vulnerability description"}
                        ]
                    }
                },
                "metrics": {
                    "cvssV31": {
                        "baseScore": 7.5,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                    }
                },
                "published": "2023-01-01T00:00:00Z"
            }
        ]
    }

    with patch("app.vulnerability_scanner.cve_lookup.requests.get") as mock_get:
        mock_get.return_value = Mock(json=lambda: mock_response, status_code=200)
        yield mock_get


# Mock ARP Scanner
@pytest.fixture
def mock_arp():
    """Mock ARP scanner."""
    mock_hosts = [
        {"ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:01", "hostname": "host1"},
        {"ip": "192.168.1.101", "mac": "aa:bb:cc:dd:ee:02", "hostname": "host2"},
    ]

    with patch("app.scanners.arp_scanner.arp_scan") as mock_scan:
        mock_scan.return_value = mock_hosts
        yield mock_scan


# Mock port scanner
@pytest.fixture
def mock_port_scanner():
    """Mock port scanner."""
    mock_ports = [
        {"port": 22, "service": "ssh", "state": "open", "version": "OpenSSH 8.0"},
        {"port": 80, "service": "http", "state": "open", "version": "Apache 2.4.41"},
    ]

    with patch("app.scanners.port_scanner.port_scan") as mock_scan:
        mock_scan.return_value = mock_ports
        yield mock_scan


# Mock WebSocket Manager
@pytest.fixture
def mock_ws_manager():
    """Mock WebSocket manager for testing."""
    manager = MagicMock()
    manager.connections = {}
    manager.emit = MagicMock()
    yield manager
