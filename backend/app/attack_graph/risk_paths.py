"""
Risk path analysis — produces intelligent, prioritized security insights
from the generated attack graph.
"""

import json
import logging
from collections import Counter

from sqlalchemy.orm import Session

from app.attack_graph.models import AttackGraph, AttackNode, AttackEdge, AttackPath

log = logging.getLogger(__name__)


def analyze_risk(ag: AttackGraph, db: Session) -> dict:
    """
    Derive prioritized risk insights from the attack graph.
    Returns a structured analysis dict consumed by the API and frontend.
    """
    paths = db.query(AttackPath).filter(AttackPath.graph_id == ag.id).order_by(
        AttackPath.total_score.desc()
    ).all()
    nodes = db.query(AttackNode).filter(AttackNode.graph_id == ag.id).all()
    edges = db.query(AttackEdge).filter(AttackEdge.graph_id == ag.id).all()

    node_map = {n.id: n for n in nodes}
    attacker_ids = {n.id for n in nodes if n.node_type == "ATTACKER"}

    if not paths:
        return {
            "most_dangerous_host": None,
            "weakest_entry": None,
            "critical_paths": [],
            "attack_surface": [],
            "recommendations": [],
            "stats": {
                "total_paths": 0,
                "critical_paths": 0,
                "high_paths": 0,
                "entry_points": sum(1 for n in nodes if n.is_entry_point),
            },
        }

    # ── Most dangerous host ──────────────────────────────────────────────────
    # Host appearing most frequently in the highest-scoring paths
    host_score_sum: dict[str, float] = Counter()
    host_appearances: dict[str, int] = Counter()

    for path in paths:
        node_ids = json.loads(path.path_node_ids_json or "[]")
        for nid in node_ids:
            if nid in attacker_ids:
                continue
            host_appearances[nid] += 1
            host_score_sum[nid] += path.total_score

    most_dangerous = None
    if host_appearances:
        # Rank by (appearances × avg_score)
        danger_id = max(
            host_appearances,
            key=lambda k: host_appearances[k] * (host_score_sum[k] / host_appearances[k]),
        )
        n = node_map.get(danger_id)
        if n:
            most_dangerous = {
                "ip": n.ip,
                "label": n.label,
                "appearances_in_paths": host_appearances[danger_id],
                "risk_score": round(n.risk_score, 1),
                "node_type": n.node_type,
            }

    # ── Weakest entry point ──────────────────────────────────────────────────
    entry_edges = [e for e in edges if e.source_node_id in attacker_ids]
    weakest_entry = None
    if entry_edges:
        easiest = max(entry_edges, key=lambda e: e.score)
        target = node_map.get(easiest.target_node_id)
        if target:
            weakest_entry = {
                "ip": target.ip,
                "label": target.label,
                "attack_vector": easiest.attack_vector,
                "score": round(easiest.score, 1),
                "description": easiest.description,
                "cve_ids": json.loads(easiest.cve_ids_json or "[]"),
            }

    # ── Top critical paths ───────────────────────────────────────────────────
    critical_paths = []
    for p in paths[:5]:
        ips = json.loads(p.path_ips_json or "[]")
        vectors = json.loads(p.attack_vectors_json or "[]")
        cves = json.loads(p.cve_ids_json or "[]")
        critical_paths.append({
            "id": p.id,
            "path": " → ".join(ips),
            "path_ips": ips,
            "attack_vectors": vectors,
            "total_score": p.total_score,
            "severity": p.severity,
            "hop_count": p.hop_count,
            "entry_ip": p.entry_ip,
            "target_ip": p.target_ip,
            "cve_ids": cves,
        })

    # ── Attack surface (all entry points) ────────────────────────────────────
    entry_nodes = sorted(
        [n for n in nodes if n.is_entry_point],
        key=lambda n: n.risk_score,
        reverse=True,
    )
    attack_surface = [
        {
            "ip": n.ip,
            "label": n.label,
            "risk_score": round(n.risk_score, 1),
            "node_type": n.node_type,
            "is_critical": n.is_critical,
            "metadata": json.loads(n.metadata_json or "{}"),
        }
        for n in entry_nodes
    ]

    # ── Recommendations ──────────────────────────────────────────────────────
    recommendations = _generate_recommendations(nodes, edges, paths)

    # Persist summary back to the graph
    summary = {
        "most_dangerous_host": most_dangerous,
        "weakest_entry": weakest_entry,
        "attack_surface_count": len(attack_surface),
        "critical_path_count": sum(1 for p in paths if p.severity == "CRITICAL"),
        "high_path_count": sum(1 for p in paths if p.severity == "HIGH"),
    }
    ag.summary_json = json.dumps(summary)
    db.commit()

    return {
        "most_dangerous_host": most_dangerous,
        "weakest_entry": weakest_entry,
        "critical_paths": critical_paths,
        "attack_surface": attack_surface,
        "recommendations": recommendations,
        "stats": {
            "total_paths": len(paths),
            "critical_paths": sum(1 for p in paths if p.severity == "CRITICAL"),
            "high_paths": sum(1 for p in paths if p.severity == "HIGH"),
            "entry_points": len(entry_nodes),
        },
    }


def _generate_recommendations(nodes, edges, paths) -> list:
    recs = []

    critical_count = sum(1 for p in paths if p.severity == "CRITICAL")
    if critical_count:
        recs.append({
            "priority": "CRITICAL",
            "title": "Critical Attack Paths Detected",
            "detail": (
                f"{critical_count} critical attack path(s) identified. "
                "These represent the most direct routes to compromise."
            ),
            "action": "Patch all CRITICAL/HIGH CVEs. Restrict directly exposed services with firewall rules.",
        })

    smb_edges = [
        e for e in edges
        if "smb" in (e.service or "").lower() or "SMB" in (e.attack_vector or "")
    ]
    if smb_edges:
        recs.append({
            "priority": "HIGH",
            "title": "SMB Lateral Movement Risk",
            "detail": (
                f"{len(smb_edges)} SMB-based attack vector(s) detected. "
                "SMB enables EternalBlue, relay, and pass-the-hash attacks."
            ),
            "action": "Disable SMBv1, enforce SMB signing, restrict port 445 between hosts.",
        })

    db_edges = [e for e in edges if e.attack_type == "DATA_ACCESS"]
    if db_edges:
        recs.append({
            "priority": "HIGH",
            "title": "Database Services Exposed",
            "detail": (
                f"{len(db_edges)} database service attack vector(s) found. "
                "Databases should never be directly accessible from untrusted networks."
            ),
            "action": "Place databases behind application layer. Enforce auth, disable remote root.",
        })

    rdp_edges = [e for e in edges if "rdp" in (e.service or "").lower() or "RDP" in (e.attack_vector or "")]
    if rdp_edges:
        recs.append({
            "priority": "HIGH",
            "title": "RDP Exposed",
            "detail": "RDP is a primary ransomware delivery vector. Unpatched hosts risk BlueKeep-class RCE.",
            "action": "Restrict RDP to VPN only. Apply all Windows patches. Enable NLA.",
        })

    entry_count = sum(1 for n in nodes if n.is_entry_point)
    if entry_count > 4:
        recs.append({
            "priority": "MEDIUM",
            "title": f"Large Attack Surface ({entry_count} Entry Points)",
            "detail": (
                f"{entry_count} hosts are directly reachable by an external attacker. "
                "Each exposed service is a potential initial access point."
            ),
            "action": "Implement network segmentation. Use firewall to minimize internet-facing services.",
        })

    telnet_edges = [e for e in edges if "telnet" in (e.service or "").lower()]
    if telnet_edges:
        recs.append({
            "priority": "MEDIUM",
            "title": "Telnet Detected",
            "detail": "Telnet transmits all data including credentials in cleartext.",
            "action": "Replace Telnet with SSH immediately.",
        })

    if not recs:
        recs.append({
            "priority": "LOW",
            "title": "No Critical Issues Found",
            "detail": "No critical attack paths detected. Continue monitoring and patching.",
            "action": "Maintain patch cadence. Review firewall rules periodically.",
        })

    return recs
