"""
Deterministic prioritization engine (the core - no API key needed).

Ranks a scan's vulnerabilities from most to least urgent using only real,
computed signals: exploitation evidence (CISA KEV / exploit maturity), EPSS,
CVSS, match confidence (CPE-confirmed vs weak keyword match), host exposure
and lateral-movement context.

The score is fully transparent: every finding carries the list of factors that
produced it, each with its points and a short explanation. Nothing here calls
an LLM - the optional AI layer only rephrases this output (see narrative.py).
"""

from typing import Dict, List

from sqlalchemy.orm import Session

from app.models.scan import Host
from app.vulnerability_scanner.models import Vulnerability
from app.exploitability.models import ExploitabilityAssessment
from app.vulnerability_scanner.risk_engine import HIGH_RISK_SERVICES

# Maximum points per factor. The total is capped at 100.
MAX_SCORE = 100.0

_MATURITY_POINTS = {"WEAPONIZED": 25.0, "FUNCTIONAL": 18.0, "POC": 10.0, "UNKNOWN": 0.0}


def _exploitation_factor(kev: bool, maturity: str) -> dict:
    if kev:
        return {"key": "exploitation", "label": "Exploited in the wild (CISA KEV)",
                "points": 30.0, "detail": "Listed in the CISA KEV catalogue"}
    points = _MATURITY_POINTS.get(maturity or "UNKNOWN", 0.0)
    detail = {
        "WEAPONIZED": "A reliable/weaponized public exploit exists",
        "FUNCTIONAL": "A working public exploit/PoC is referenced",
        "POC": "A proof-of-concept is referenced",
        "UNKNOWN": "No public-exploit evidence found",
    }.get(maturity or "UNKNOWN", "No public-exploit evidence found")
    return {"key": "exploitation", "label": f"Exploit maturity: {maturity or 'UNKNOWN'}",
            "points": points, "detail": detail}


def host_exposure(host: Host) -> dict:
    """Host-level exposure (0-10): how reachable/attack-surface-heavy the host is."""
    open_ports = [p for p in (host.ports or []) if p.get("state") == "open"]
    risky = [p for p in open_ports
             if (p.get("service") or "").lower() in HIGH_RISK_SERVICES]
    points = min(8.0, len(open_ports) * 1.0) + (2.0 if risky else 0.0)
    points = min(10.0, points)
    detail = f"{len(open_ports)} open port(s)" + (f", {len(risky)} high-risk service(s)" if risky else "")
    return {"key": "exposure", "label": "Host exposure", "points": round(points, 1), "detail": detail}


def score_finding(vuln: Vulnerability, assessment: ExploitabilityAssessment, exposure_factor: dict) -> dict:
    """Score one vulnerability and return {score, factors:[...]} - fully transparent."""
    maturity = assessment.exploit_maturity if assessment else None
    lateral = (assessment.lateral_movement_potential if assessment else None) or "LOW"
    confirmed = (vuln.match_type or "cpe") == "cpe"
    epss = vuln.epss
    cvss = vuln.cvss or 0.0

    factors = [_exploitation_factor(bool(vuln.kev), maturity)]

    factors.append({"key": "epss", "label": "Exploitation probability (EPSS)",
                    "points": round((epss or 0.0) * 20.0, 1),
                    "detail": f"EPSS {epss * 100:.1f}%" if epss is not None else "No EPSS data"})

    factors.append({"key": "cvss", "label": "Severity (CVSS)",
                    "points": round(cvss / 10.0 * 25.0, 1), "detail": f"CVSS {cvss}"})

    factors.append({"key": "confidence",
                    "label": "Match confidence (CPE-confirmed)" if confirmed else "Match confidence (weak)",
                    "points": 15.0 if confirmed else 5.0,
                    "detail": "Confirmed by CPE (product + version)" if confirmed
                              else "Keyword match only - may be a false positive"})

    factors.append(exposure_factor)

    lat_points = {"HIGH": 10.0, "MEDIUM": 5.0}.get(lateral, 0.0)
    factors.append({"key": "lateral", "label": "Lateral-movement potential",
                    "points": lat_points, "detail": f"{lateral} lateral-movement potential"})

    score = round(min(MAX_SCORE, sum(f["points"] for f in factors)), 1)
    return {"score": score, "factors": factors}


def prioritize_scan(scan_id: str, db: Session) -> List[dict]:
    """Rank every vulnerability in a scan, most urgent first.

    Returns a list of finding dicts with the transparent score breakdown. The
    deterministic order is by score desc, then CVSS, then CVE id (stable).
    """
    hosts = {h.id: h for h in db.query(Host).filter(Host.scan_id == scan_id).all()}
    if not hosts:
        return []

    exposure_by_host = {hid: host_exposure(h) for hid, h in hosts.items()}
    assessments = {a.vuln_id: a for a in db.query(ExploitabilityAssessment)
                   .filter(ExploitabilityAssessment.scan_id == scan_id).all()}

    findings = []
    vulns = db.query(Vulnerability).filter(
        Vulnerability.host_id.in_(list(hosts.keys()))).all()
    for vuln in vulns:
        host = hosts[vuln.host_id]
        scored = score_finding(vuln, assessments.get(vuln.id), exposure_by_host[vuln.host_id])
        findings.append({
            "vuln_id": vuln.id,
            "cve_id": vuln.cve_id,
            "host_id": host.id,
            "host_ip": host.ip,
            "affected_service": vuln.affected_service,
            "affected_port": vuln.affected_port,
            "severity": vuln.severity,
            "cvss": vuln.cvss,
            "kev": bool(vuln.kev),
            "epss": vuln.epss,
            "confirmed": (vuln.match_type or "cpe") == "cpe",
            "maturity": assessments.get(vuln.id).exploit_maturity if assessments.get(vuln.id) else None,
            "score": scored["score"],
            "factors": scored["factors"],
        })

    findings.sort(key=lambda f: (-f["score"], -(f["cvss"] or 0.0), f["cve_id"]))
    for i, f in enumerate(findings, start=1):
        f["rank"] = i
    return findings
