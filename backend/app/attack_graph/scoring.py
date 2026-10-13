"""
Evidence-based hop scoring for the attack graph.

Every hop (edge) is scored on three documented components, each 0-100:

  1. Reachability  - can the source actually reach the target's service, given
     the hosts, subnets and open ports really discovered?
  2. Exploitability - is the hop *backed by evidence*? Reuses the Phase-4
     signals: CISA KEV, EPSS, CPE-confirmed match, exploit maturity, CVSS. A
     hop is only "easy" when the evidence supports it.
  3. Impact / gain - what the attacker obtains: code execution, privilege
     escalation, a pivot, or data access.

The hop score is a transparent weighted sum: 0.20·R + 0.50·E + 0.30·I
(exploitability weighted highest, by design). Every hop also carries the
factor breakdown, a plain-language justification, and optional MITRE ATT&CK
technique references.

This is a heuristic, evidence-based model - NOT a formal attack graph (e.g.
MulVAL). It does not prove reachability or chain preconditions; it ranks
plausible paths from the real scan evidence so an analyst can review them.
"""

import ipaddress
from typing import List, Optional

# Component weights (documented and surfaced in the UI).
W_REACHABILITY = 0.20
W_EXPLOITABILITY = 0.50
W_IMPACT = 0.30

# MITRE ATT&CK technique references by attack type (links, not execution).
MITRE_BY_ATTACK_TYPE = {
    "REMOTE_ACCESS": [{"id": "T1190", "name": "Exploit Public-Facing Application"},
                      {"id": "T1133", "name": "External Remote Services"}],
    "LATERAL_MOVEMENT": [{"id": "T1021", "name": "Remote Services"},
                         {"id": "T1210", "name": "Exploitation of Remote Services"}],
    "DATA_ACCESS": [{"id": "T1190", "name": "Exploit Public-Facing Application"},
                    {"id": "T1005", "name": "Data from Local System"}],
    "PRIVILEGE_ESCALATION": [{"id": "T1068", "name": "Exploitation for Privilege Escalation"}],
    "PERSISTENCE": [{"id": "T1133", "name": "External Remote Services"}],
}

# Impact by the exploit's attack type (what the attacker gains).
_IMPACT = {
    "RCE": (95.0, "Remote code execution → shell"),
    "PRIVESC": (95.0, "Privilege escalation → root/SYSTEM"),
    "PRIVILEGE_ESCALATION": (95.0, "Privilege escalation → root/SYSTEM"),
    "AUTH_BYPASS": (85.0, "Authentication bypass"),
    "SQL_INJECTION": (78.0, "Database/data access"),
    "DATA_ACCESS": (75.0, "Data access"),
    "INFO_DISC": (60.0, "Information disclosure"),
    "SSRF": (65.0, "Server-side request forgery"),
    "XSS": (45.0, "Client-side code execution"),
    "DOS": (30.0, "Denial of service"),
    "REMOTE_ACCESS": (60.0, "Remote foothold"),
    "LATERAL_MOVEMENT": (70.0, "Pivot to other hosts"),
    "PERSISTENCE": (50.0, "Persistence / C2 channel"),
}


def _same_subnet(ip_a: str, ip_b: str, prefix: int = 24) -> bool:
    try:
        net = ipaddress.ip_network(f"{ip_a}/{prefix}", strict=False)
        return ipaddress.ip_address(ip_b) in net
    except ValueError:
        return False


def reachability(is_entry: bool, source_ip: Optional[str], target_ip: Optional[str],
                 port: Optional[int]) -> dict:
    """Can the source reach the target's service? From real IPs/subnets/ports."""
    port_part = f"port {port}" if port else "the service"
    if is_entry:
        return {"score": 100.0,
                "detail": f"{port_part} open and reachable from the attacker's vantage point"}
    if source_ip and target_ip and _same_subnet(source_ip, target_ip):
        return {"score": 90.0, "detail": f"Same subnet as {source_ip}; {port_part} open on the target"}
    return {"score": 55.0, "detail": f"{port_part} open; cross-subnet reachability assumed"}


def hop_evidence(vulns: list, assessments_by_vuln: dict) -> dict:
    """Summarise the strongest Phase-4 evidence among a hop's vulnerabilities."""
    best = {"kev": False, "epss": None, "confirmed": False, "cvss": 0.0,
            "maturity": None, "cve_id": None, "attack_type": None}
    for v in vulns:
        if v.kev:
            best["kev"] = True
        if v.epss is not None and (best["epss"] is None or v.epss > best["epss"]):
            best["epss"] = v.epss
        if (v.match_type or "cpe") == "cpe":
            best["confirmed"] = True
        if (v.cvss or 0.0) >= best["cvss"]:
            best["cvss"] = v.cvss or 0.0
            best["cve_id"] = v.cve_id
            a = assessments_by_vuln.get(v.id)
            if a:
                best["maturity"] = a.exploit_maturity
                best["attack_type"] = a.attack_type
    return best


def exploitability(evidence: dict, has_cve: bool) -> dict:
    """Evidence-based: a hop is 'easy' only when real evidence supports it."""
    if not has_cve:
        return {"score": 35.0, "detail": "No CVE on this service - service-exposure risk only "
                                         "(e.g. weak/default credentials, cleartext)"}
    if evidence["kev"]:
        base, why = 95.0, "CISA KEV (exploited in the wild)"
    elif evidence["maturity"] == "WEAPONIZED":
        base, why = 90.0, "weaponized public exploit"
    elif evidence["maturity"] == "FUNCTIONAL":
        base, why = 75.0, "working public exploit/PoC"
    elif evidence["maturity"] == "POC":
        base, why = 55.0, "proof-of-concept"
    else:
        # No public-exploit evidence: scale by CVSS, halved for a weak match.
        base = (evidence["cvss"] / 10.0) * 50.0 * (1.0 if evidence["confirmed"] else 0.5)
        why = "no public-exploit evidence (from CVSS" + ("" if evidence["confirmed"] else ", weak match") + ")"
    if evidence["epss"] is not None:
        base = min(100.0, base + evidence["epss"] * 10.0)
    conf = "CPE-confirmed" if evidence["confirmed"] else "weak match"
    epss_txt = f", EPSS {evidence['epss'] * 100:.0f}%" if evidence["epss"] is not None else ""
    cve = evidence["cve_id"] or "service CVEs"
    return {"score": round(min(100.0, base), 1), "detail": f"{cve}: {why} ({conf}{epss_txt})"}


def impact(attack_type: str, evidence_attack_type: Optional[str], is_pivot: bool,
           target_critical: bool) -> dict:
    """What the attacker gains on the target."""
    key = evidence_attack_type or attack_type
    score, label = _IMPACT.get(key, _IMPACT.get(attack_type, (55.0, "Foothold on the host")))
    notes = [label]
    if is_pivot:
        score = min(100.0, score + 8.0)
        notes.append("can pivot further")
    if target_critical:
        score = min(100.0, score + 5.0)
        notes.append("high-value host")
    return {"score": round(score, 1), "detail": "; ".join(notes)}


def score_hop(is_entry: bool, is_pivot: bool, attack_type: str, source_ip: Optional[str],
              source_label: str, target_ip: Optional[str], port: Optional[int],
              service: Optional[str], vulns: list, assessments_by_vuln: dict,
              target_critical: bool) -> dict:
    """Score one hop on the three components and build its justification + MITRE tags."""
    evidence = hop_evidence(vulns, assessments_by_vuln)
    r = reachability(is_entry, source_ip, target_ip, port)
    e = exploitability(evidence, has_cve=bool(vulns))
    i = impact(attack_type, evidence["attack_type"], is_pivot, target_critical)

    score = round(W_REACHABILITY * r["score"] + W_EXPLOITABILITY * e["score"] + W_IMPACT * i["score"], 1)

    factors = [
        {"key": "reachability", "label": "Reachability", "weight": W_REACHABILITY,
         "value": r["score"], "detail": r["detail"]},
        {"key": "exploitability", "label": "Hop exploitability (evidence)", "weight": W_EXPLOITABILITY,
         "value": e["score"], "detail": e["detail"]},
        {"key": "impact", "label": "Impact / gain", "weight": W_IMPACT,
         "value": i["score"], "detail": i["detail"]},
    ]

    svc = service or (f"port {port}" if port else "service")
    cve = evidence["cve_id"]
    gain = i["detail"].split(";")[0]
    src = source_label or source_ip or "ATTACKER"
    evi_bits = []
    if evidence["confirmed"]:
        evi_bits.append("CPE-confirmed")
    if evidence["kev"]:
        evi_bits.append("KEV")
    if evidence["epss"] is not None:
        evi_bits.append(f"EPSS {evidence['epss'] * 100:.0f}%")
    evi = (", ".join(evi_bits)) if evi_bits else "no exploit evidence"
    via = f"{svc}" + (f" ({cve}, {evi})" if cve else f" ({evi})")
    justification = f"{src} → {target_ip}: {via} → {gain}"

    return {
        "score": score,
        "reachability": r["score"],
        "exploitability": e["score"],
        "impact": i["score"],
        "factors": factors,
        "justification": justification,
        "mitre": MITRE_BY_ATTACK_TYPE.get(attack_type, []),
        "evidence": evidence,
    }


def aggregate_path(hop_scores: List[dict], hop_count: int) -> dict:
    """Combine hop components into a transparent path score.

    Reachability and exploitability take the weakest hop (a chain is only as
    reachable/easy as its hardest step); impact takes the best gain achieved.
    A small per-extra-hop penalty reflects that longer chains are less likely.
    """
    if not hop_scores:
        return {"score": 0.0, "reachability": 0.0, "exploitability": 0.0, "impact": 0.0, "factors": []}

    r = min(h["reachability"] for h in hop_scores)
    e = min(h["exploitability"] for h in hop_scores)
    i = max(h["impact"] for h in hop_scores)
    penalty = max(0.0, (hop_count - 1) * 4.0)
    base = W_REACHABILITY * r + W_EXPLOITABILITY * e + W_IMPACT * i
    score = round(max(0.0, min(100.0, base - penalty)), 1)

    factors = [
        {"key": "reachability", "label": "Reachability (weakest hop)", "weight": W_REACHABILITY,
         "value": round(r, 1), "detail": "The chain is only as reachable as its hardest step"},
        {"key": "exploitability", "label": "Exploitability (weakest hop, evidence-based)",
         "weight": W_EXPLOITABILITY, "value": round(e, 1), "detail": "The chain is only as easy as its hardest step"},
        {"key": "impact", "label": "Impact / gain (best on the path)", "weight": W_IMPACT,
         "value": round(i, 1), "detail": "The strongest gain the attacker reaches"},
        {"key": "hop_penalty", "label": f"Length penalty ({hop_count} hop(s))", "weight": 1.0,
         "value": round(-penalty, 1), "detail": "Longer chains are less likely to fully succeed"},
    ]
    return {"score": score, "reachability": round(r, 1), "exploitability": round(e, 1),
            "impact": round(i, 1), "factors": factors}
