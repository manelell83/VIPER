"""
API tests for report export (/reports/export/*).
"""

import json

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.exploitability.models import RemediationItem
from app.models.scan import ScanSession, Host


def _scan_with_hostile_banner(db: Session) -> ScanSession:
    """A scanned host controls its own service banner. This one contains
    ReportLab markup that would break PDF generation if not escaped."""
    scan = ScanSession(type="domain", target="10.0.0.5", status="completed")
    db.add(scan)
    db.commit()
    host = Host(scan_id=scan.id, ip="10.0.0.5")
    host.ports = [{"port": 80, "protocol": "tcp", "state": "open",
                   "service": "http", "version": "EvilHTTPd <font name='x'>"}]
    db.add(host)
    db.commit()
    db.add(RemediationItem(
        host_id=host.id, scan_id=scan.id, priority="IMMEDIATE",
        title="Patch services on 10.0.0.5 <b>",
        description="Affected services: EvilHTTPd <font name='x'> & <unclosed",
        steps_json=json.dumps(["Upgrade <script>alert(1)</script>"]),
    ))
    db.commit()
    return scan


def test_pdf_export_with_markup_in_scanned_data(client: TestClient, test_db: Session):
    scan = _scan_with_hostile_banner(test_db)

    response = client.get(f"/reports/export/{scan.id}/pdf")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF")


def test_json_export(client: TestClient, test_db: Session):
    scan = _scan_with_hostile_banner(test_db)

    response = client.get(f"/reports/export/{scan.id}/json")

    assert response.status_code == 200
    assert response.json()["hosts"][0]["ip"] == "10.0.0.5"


def test_export_of_unknown_scan_returns_404(client: TestClient):
    assert client.get("/reports/export/does-not-exist/pdf").status_code == 404
