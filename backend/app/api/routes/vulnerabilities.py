from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional

from app.core.database import get_db
from app.models.scan import Host, ScanSession
from app.vulnerability_scanner.models import Vulnerability
from app.vulnerability_scanner.risk_engine import compute_host_risk, compute_network_risk

router = APIRouter()


@router.get("")
async def list_vulnerabilities(
    scan_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    host_id: Optional[str] = Query(None),
    limit: int = Query(200, le=500),
    db: Session = Depends(get_db),
):
    """Return all vulnerabilities, optionally filtered by scan/severity/host."""
    q = db.query(Vulnerability)

    if host_id:
        q = q.filter(Vulnerability.host_id == host_id)

    if scan_id:
        # Join through host to filter by scan
        q = q.join(Host, Vulnerability.host_id == Host.id).filter(Host.scan_id == scan_id)

    if severity:
        q = q.filter(Vulnerability.severity == severity.upper())

    vulns = q.order_by(Vulnerability.cvss.desc()).limit(limit).all()
    return {
        "vulnerabilities": [v.to_dict() for v in vulns],
        "count": len(vulns),
    }


@router.get("/by-host/{host_id}")
async def get_host_vulnerabilities(host_id: str, db: Session = Depends(get_db)):
    """Return all vulnerabilities for a specific host, with risk score."""
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    vulns = db.query(Vulnerability).filter(Vulnerability.host_id == host_id)\
        .order_by(Vulnerability.cvss.desc()).all()

    vuln_dicts = [v.to_dict() for v in vulns]
    risk = compute_host_risk(host.to_dict(), vuln_dicts)

    return {
        "host": host.to_dict(),
        "vulnerabilities": vuln_dicts,
        "risk": risk,
    }


@router.get("/risk/summary")
async def get_risk_summary(scan_id: Optional[str] = Query(None), db: Session = Depends(get_db)):
    """Network-wide risk summary, optionally for a specific scan."""
    if scan_id:
        hosts = db.query(Host).filter(Host.scan_id == scan_id).all()
    else:
        # Use most recent completed scan
        scan = db.query(ScanSession)\
            .filter(ScanSession.status == "completed")\
            .order_by(ScanSession.completed_at.desc())\
            .first()
        hosts = db.query(Host).filter(Host.scan_id == scan.id).all() if scan else []

    host_risks = []
    for host in hosts:
        vulns = db.query(Vulnerability).filter(Vulnerability.host_id == host.id).all()
        vuln_dicts = [v.to_dict() for v in vulns]
        risk = compute_host_risk(host.to_dict(), vuln_dicts)
        risk["host_ip"] = host.ip
        risk["host_id"] = host.id
        host_risks.append(risk)

    network = compute_network_risk(host_risks)
    return {
        "scan_id": scan_id,
        "network": network,
        "hosts": host_risks,
    }


@router.get("/risk/top-hosts")
async def get_top_risky_hosts(
    scan_id: Optional[str] = Query(None),
    limit: int = Query(10, le=50),
    db: Session = Depends(get_db),
):
    """Return top N riskiest hosts."""
    if scan_id:
        hosts = db.query(Host).filter(Host.scan_id == scan_id).all()
    else:
        scan = db.query(ScanSession)\
            .filter(ScanSession.status == "completed")\
            .order_by(ScanSession.completed_at.desc())\
            .first()
        hosts = db.query(Host).filter(Host.scan_id == scan.id).all() if scan else []

    host_risks = []
    for host in hosts:
        vulns = db.query(Vulnerability).filter(Vulnerability.host_id == host.id).all()
        vuln_dicts = [v.to_dict() for v in vulns]
        risk = compute_host_risk(host.to_dict(), vuln_dicts)
        risk["host_ip"] = host.ip
        risk["host_id"] = host.id
        risk["hostname"] = host.hostname
        host_risks.append(risk)

    top = sorted(host_risks, key=lambda h: -h.get("score", 0))[:limit]
    return {"top_hosts": top, "count": len(top)}


@router.get("/stats")
async def get_vuln_stats(db: Session = Depends(get_db)):
    """Global vulnerability statistics across all scans."""
    total = db.query(Vulnerability).count()
    by_severity = {}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]:
        by_severity[sev.lower()] = db.query(Vulnerability).filter(
            Vulnerability.severity == sev
        ).count()

    return {
        "total": total,
        "by_severity": by_severity,
    }
