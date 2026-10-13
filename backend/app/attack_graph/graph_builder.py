"""
Attack graph builder.
Analyzes scan data (hosts, services, CVEs) and constructs attack node/edge records.
All relationships are derived from real scan data — nothing is hardcoded.
"""

import json
import logging
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models.scan import Host
from app.vulnerability_scanner.models import Vulnerability
from app.exploitability.models import ExploitabilityAssessment
from app.attack_graph.models import AttackGraph, AttackNode, AttackEdge
from app.attack_graph.attack_rules import evaluate_host_rules
from app.attack_graph import scoring
from app.core.timeutil import utcnow

log = logging.getLogger(__name__)

def build_attack_graph(scan_id: str, db: Session) -> "AttackGraph | None":
    """
    Build (or rebuild) the attack graph for a completed scan.
    Returns the AttackGraph record, or None if the scan has no hosts.
    """
    hosts = db.query(Host).filter(Host.scan_id == scan_id).all()
    if not hosts:
        return None

    # Remove existing graph for this scan (regenerate from scratch)
    existing = db.query(AttackGraph).filter(AttackGraph.scan_id == scan_id).first()
    if existing:
        db.delete(existing)
        db.flush()

    ag = AttackGraph(
        id=str(uuid4()),
        scan_id=scan_id,
        generated_at=utcnow(),
    )
    db.add(ag)
    db.flush()

    # ── Virtual attacker node ────────────────────────────────────────────────
    # Each graph gets its own attacker node with a unique id (the id is the
    # table's primary key, so a fixed id would collide across scans).
    # Other modules find it by node_type == "ATTACKER".
    attacker = AttackNode(
        id=str(uuid4()),
        graph_id=ag.id,
        host_id=None,
        node_type="ATTACKER",
        label="External\nAttacker",
        ip="0.0.0.0",
        risk_score=100.0,
        is_entry_point=False,
        is_critical=True,
        metadata_json=json.dumps({}),
    )
    db.add(attacker)

    # Phase-4 exploitability evidence for every vuln in the scan (for hop scoring)
    assessments_by_vuln = {a.vuln_id: a for a in db.query(ExploitabilityAssessment)
                           .filter(ExploitabilityAssessment.scan_id == scan_id).all()}

    # ── Build host nodes ─────────────────────────────────────────────────────
    host_nodes: dict[str, AttackNode] = {}
    host_vulns: dict[str, list] = {}
    host_rules: dict[str, list] = {}

    for host in hosts:
        vulns = db.query(Vulnerability).filter(Vulnerability.host_id == host.id).all()
        open_ports = [p["port"] for p in host.ports if p.get("state") == "open"]
        services = [p.get("service", "") for p in host.ports if p.get("state") == "open"]

        matched = evaluate_host_rules(open_ports, services, vulns)
        host_vulns[host.id] = vulns
        host_rules[host.id] = matched

        max_sev = host.max_severity()
        is_critical = max_sev in ("CRITICAL", "HIGH")
        has_entry = any(r.is_entry_point for r, _, _ in matched)
        has_pivot = any(r.is_pivot for r, _, _ in matched)

        rule_scores = [s for _, s, _ in matched]
        risk_score = max(rule_scores) if rule_scores else min(50.0, len(open_ports) * 5)
        risk_score = min(100.0, risk_score)

        if has_entry and is_critical:
            node_type = "ENTRY"
        elif has_pivot:
            node_type = "PIVOT"
        elif len(open_ports) > 5:
            node_type = "TARGET"
        else:
            node_type = "INTERNAL"

        node = AttackNode(
            id=str(uuid4()),
            graph_id=ag.id,
            host_id=host.id,
            node_type=node_type,
            label=host.hostname or host.ip,
            ip=host.ip,
            risk_score=risk_score,
            is_entry_point=has_entry,
            is_critical=is_critical,
            metadata_json=json.dumps({
                "open_ports": open_ports,
                "services": services,
                "vuln_count": len(vulns),
                "max_severity": max_sev,
                "os": host.os or "Unknown",
            }),
        )
        db.add(node)
        host_nodes[host.id] = node

    db.flush()

    # ── Build edges ──────────────────────────────────────────────────────────
    entry_host_ids: set[str] = set()  # hosts directly reachable from ATTACKER

    for host in hosts:
        matched = host_rules[host.id]
        vulns = host_vulns[host.id]
        target_node = host_nodes[host.id]

        for rule, score, cve_ids in matched:
            if not rule.is_entry_point:
                continue
            hop_vulns = [v for v in vulns if v.cve_id in cve_ids]
            best_cvss = max((v.cvss or 0) for v in hop_vulns) if hop_vulns else 0.0
            port = rule.ports[0] if rule.ports else None
            svc = ", ".join(rule.services[:3]) if rule.services else None
            hop = scoring.score_hop(
                is_entry=True, is_pivot=rule.is_pivot, attack_type=rule.attack_type,
                source_ip="0.0.0.0", source_label="ATTACKER", target_ip=host.ip,
                port=port, service=svc, vulns=hop_vulns,
                assessments_by_vuln=assessments_by_vuln, target_critical=target_node.is_critical,
            )
            edge = AttackEdge(
                id=str(uuid4()), graph_id=ag.id,
                source_node_id=attacker.id, target_node_id=target_node.id,
                attack_type=rule.attack_type, attack_vector=rule.attack_vector,
                port=port, service=svc, cvss=best_cvss,
                cve_ids_json=json.dumps(cve_ids), score=hop["score"], description=rule.description,
                reachability=hop["reachability"], exploitability=hop["exploitability"], impact=hop["impact"],
                factors_json=json.dumps(hop["factors"]), mitre_json=json.dumps(hop["mitre"]),
                justification=hop["justification"],
            )
            db.add(edge)
            entry_host_ids.add(host.id)

    # Lateral movement: only from entry-reachable hosts that have pivot capability
    for src_host_id in entry_host_ids:
        src_host = next(h for h in hosts if h.id == src_host_id)
        src_rules = host_rules[src_host_id]
        pivot_rules = [(r, s, c) for r, s, c in src_rules if r.is_pivot]

        if not pivot_rules:
            continue

        for dst_host in hosts:
            if dst_host.id == src_host_id:
                continue

            dst_rules = host_rules[dst_host.id]
            dst_pivot = [(r, s, c) for r, s, c in dst_rules if r.is_pivot]

            if not dst_pivot:
                continue

            # Match pivot rules between source and destination (same attack type)
            src_types = {r.attack_type for r, _, _ in pivot_rules}
            dst_matches = [(r, s, c) for r, s, c in dst_pivot if r.attack_type in src_types]

            if not dst_matches:
                # Fallback: if target has any pivot service, allow lateral movement
                dst_matches = dst_pivot[:1]

            best_rule, best_score, best_cves = max(dst_matches, key=lambda x: x[1])
            dst_vulns = host_vulns[dst_host.id]
            hop_vulns = [v for v in dst_vulns if v.cve_id in best_cves]
            best_cvss = max((v.cvss or 0) for v in hop_vulns) if hop_vulns else 0.0
            port = best_rule.ports[0] if best_rule.ports else None
            svc = ", ".join(best_rule.services[:3]) if best_rule.services else None
            hop = scoring.score_hop(
                is_entry=False, is_pivot=best_rule.is_pivot, attack_type="LATERAL_MOVEMENT",
                source_ip=src_host.ip, source_label=src_host.hostname or src_host.ip,
                target_ip=dst_host.ip, port=port, service=svc, vulns=hop_vulns,
                assessments_by_vuln=assessments_by_vuln,
                target_critical=host_nodes[dst_host.id].is_critical,
            )
            edge = AttackEdge(
                id=str(uuid4()), graph_id=ag.id,
                source_node_id=host_nodes[src_host_id].id, target_node_id=host_nodes[dst_host.id].id,
                attack_type="LATERAL_MOVEMENT", attack_vector=f"Pivot → {best_rule.attack_vector}",
                port=port, service=svc, cvss=best_cvss,
                cve_ids_json=json.dumps(best_cves), score=hop["score"],
                description=f"Compromised {src_host.ip} can pivot to {dst_host.ip} via {best_rule.name}.",
                reachability=hop["reachability"], exploitability=hop["exploitability"], impact=hop["impact"],
                factors_json=json.dumps(hop["factors"]), mitre_json=json.dumps(hop["mitre"]),
                justification=hop["justification"],
            )
            db.add(edge)

    db.flush()

    # ── Finalize metadata ────────────────────────────────────────────────────
    node_count = db.query(AttackNode).filter(AttackNode.graph_id == ag.id).count()
    edge_count = db.query(AttackEdge).filter(AttackEdge.graph_id == ag.id).count()
    entry_count = db.query(AttackNode).filter(
        AttackNode.graph_id == ag.id,
        AttackNode.is_entry_point == True,
    ).count()

    ag.node_count = node_count
    ag.edge_count = edge_count
    ag.entry_point_count = entry_count
    db.commit()

    log.info(f"Attack graph built for scan {scan_id}: {node_count} nodes, {edge_count} edges")
    return ag
