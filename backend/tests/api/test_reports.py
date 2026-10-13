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


def _rich_scan(db: Session) -> ScanSession:
    """A completed scan with the Phase 2-7 signals the professional report uses."""
    from app.vulnerability_scanner.models import Vulnerability
    from app.exploitability.models import ExploitabilityAssessment
    from app.attack_graph.graph_builder import build_attack_graph
    from app.attack_graph.path_engine import generate_attack_paths

    scan = ScanSession(type="network", target="192.168.56.0/24", status="completed")
    db.add(scan)
    db.commit()
    host = Host(scan_id=scan.id, ip="192.168.56.5", hostname="metasploitable", os="Linux 2.6")
    host.ports = [
        {"port": 21, "protocol": "tcp", "state": "open", "service": "ftp", "version": "vsftpd 2.3.4"},
        {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 4.7"},
        {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "Apache 2.2.8"},
        {"port": 445, "protocol": "tcp", "state": "open", "service": "netbios-ssn", "version": "Samba 3.x"},
    ]
    db.add(host)
    db.commit()
    confirmed = Vulnerability(host_id=host.id, cve_id="CVE-2011-2523", cvss=9.8, severity="CRITICAL",
                              epss=0.96, kev=True, match_type="cpe", affected_service="vsftpd 2.3.4",
                              affected_port="21/tcp", description="Backdoor command execution in vsftpd 2.3.4.")
    weak = Vulnerability(host_id=host.id, cve_id="CVE-2003-0352", cvss=7.5, severity="HIGH",
                         epss=0.98, kev=False, match_type="keyword", affected_service="Windows RPC",
                         affected_port="135/tcp")
    db.add_all([confirmed, weak])
    db.commit()
    db.add(ExploitabilityAssessment(host_id=host.id, vuln_id=confirmed.id, scan_id=scan.id,
                                    cve_id=confirmed.cve_id, exploit_maturity="WEAPONIZED",
                                    attack_type="RCE", lateral_movement_potential="HIGH",
                                    patch_priority="IMMEDIATE", exploitability_score=95.0))
    db.commit()
    ag = build_attack_graph(scan.id, db)
    generate_attack_paths(ag, db)
    return scan


def test_professional_report_generates_from_real_signals(client: TestClient, test_db: Session):
    scan = _rich_scan(test_db)

    response = client.get(f"/reports/export/{scan.id}/pdf")

    assert response.status_code == 200
    assert response.content.startswith(b"%PDF")
    # A full multi-section audit report is substantially larger than a stub
    assert len(response.content) > 10000


def _pdf_text(pdf: bytes) -> str:
    """Rough text extraction: ReportLab writes content streams as ASCII85 +
    Flate, so decode both, then collect the parenthesised strings it emits for
    the Tj/TJ text operators."""
    import base64
    import re
    import zlib

    body = b""
    for m in re.finditer(rb">>\s*stream\r?\n(.*?)endstream", pdf, re.DOTALL):
        raw = m.group(1).strip()
        for cand in (raw, raw[:-2] if raw.endswith(b"~>") else raw):
            try:
                body += zlib.decompress(base64.a85decode(cand, adobe=False))
                break
            except Exception:
                try:
                    body += zlib.decompress(cand)
                    break
                except Exception:
                    pass
    parts = re.findall(rb"\(((?:[^()\\]|\\.)*)\)", body)
    return b" ".join(parts).decode("latin-1", "replace")


def test_report_has_all_sections_and_honesty_notes(test_db: Session):
    from app.api.routes import reports
    scan = _rich_scan(test_db)

    text = _pdf_text(reports._generate_advanced_pdf(scan.id, scan, test_db))

    # Professional audit structure
    for section in ["AUTHORIZED USE ONLY", "Executive summary", "Methodology",
                    "Prioritised findings", "Attack paths", "host roles", "Technical appendix"]:
        assert section in text, f"missing section: {section}"
    # Real Phase 2-7 signals surfaced
    assert "CVE-2011-2523" in text            # the weaponized, KEV finding
    assert "Confirmed" in text and "Weak" in text   # CPE vs weak match distinction
    assert "EPSS" in text and "KEV" in text
    # Honesty mentions kept
    assert "MulVAL" in text                   # attack graph is heuristic, not formal
    assert "inferred from observed services" in text
    assert "decision aid" in text
