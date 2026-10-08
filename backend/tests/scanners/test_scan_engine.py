"""
Tests for the domain-scan pipeline (scan_engine.run_domain_scan) with the
network-facing steps (DNS, nmap, NVD) replaced by fakes.
"""

import pytest
from sqlalchemy.orm import Session

from app.models.scan import ScanSession, Host
from app.scanners import scan_engine


@pytest.fixture
def events():
    """Collects every WebSocket event the pipeline emits."""
    received = []

    async def emit(event):
        received.append(event)

    emit.received = received
    return emit


@pytest.fixture
def domain_scan(test_db: Session):
    scan = ScanSession(type="domain", target="example.com")
    test_db.add(scan)
    test_db.commit()
    return scan


@pytest.fixture
def no_cve_lookup(monkeypatch):
    async def none_found(hosts, db, emit):
        return 0
    monkeypatch.setattr(scan_engine, "scan_all_hosts_vulnerabilities", none_found)


async def test_successful_scan_stores_host_and_completes(test_db, domain_scan, events, monkeypatch, no_cve_lookup):
    monkeypatch.setattr(scan_engine, "resolve_target", lambda target: "93.184.216.34")
    monkeypatch.setattr(scan_engine, "port_scan", lambda ip, ports: {
        "ports": [{"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"}],
        "os": "Linux 5.4", "os_accuracy": 96, "hostname": None,
    })

    await scan_engine.run_domain_scan(domain_scan.id, "example.com", test_db, events)

    test_db.refresh(domain_scan)
    assert domain_scan.status == "completed"
    host = test_db.query(Host).filter(Host.scan_id == domain_scan.id).one()
    assert (host.ip, host.hostname, host.open_ports_count) == ("93.184.216.34", "example.com", 1)

    types = [e["type"] for e in events.received]
    assert types[0] == "started"
    assert "attack_graph_generated" in types
    assert types[-1] == "completed"


async def test_unresolvable_target_fails_with_clear_message(test_db, domain_scan, events, monkeypatch):
    def cannot_resolve(target):
        raise ValueError(f"Could not resolve '{target}'")
    monkeypatch.setattr(scan_engine, "resolve_target", cannot_resolve)

    await scan_engine.run_domain_scan(domain_scan.id, "nothing.invalid", test_db, events)

    test_db.refresh(domain_scan)
    assert domain_scan.status == "failed"
    assert domain_scan.error == "Could not resolve 'nothing.invalid'"
    assert events.received[-1] == {"type": "error", "message": "Could not resolve 'nothing.invalid'"}


async def test_unexpected_error_details_are_not_sent_to_the_client(test_db, domain_scan, events, monkeypatch):
    monkeypatch.setattr(scan_engine, "resolve_target", lambda target: "10.0.0.5")

    def crash(ip, ports):
        raise RuntimeError("secret internal detail: /opt/app/config.py line 42")
    monkeypatch.setattr(scan_engine, "port_scan", crash)

    await scan_engine.run_domain_scan(domain_scan.id, "example.com", test_db, events)

    test_db.refresh(domain_scan)
    assert domain_scan.status == "failed"
    assert domain_scan.error == scan_engine.INTERNAL_ERROR_MESSAGE
    assert all("secret internal detail" not in str(e) for e in events.received)
