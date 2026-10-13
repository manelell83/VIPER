"""
Attack path engine.
Uses NetworkX to find attack paths through the graph,
then scores and persists them as AttackPath records.
"""

import json
import logging
from uuid import uuid4

import networkx as nx
from sqlalchemy.orm import Session

from app.attack_graph.models import AttackGraph, AttackNode, AttackEdge, AttackPath
from app.attack_graph import scoring
from app.core.config import settings

log = logging.getLogger(__name__)

MAX_PATHS = settings.MAX_ATTACK_PATHS
MAX_HOPS  = settings.MAX_ATTACK_HOPS


def generate_attack_paths(ag: AttackGraph, db: Session) -> list:
    """
    Enumerate attack paths from ATTACKER to reachable targets, score and persist
    the top MAX_PATHS. Each distinct entry service is its own path; multi-hop
    (lateral) chains use the strongest edge between any two hosts.
    """
    db.query(AttackPath).filter(AttackPath.graph_id == ag.id).delete()
    db.flush()

    nodes = db.query(AttackNode).filter(AttackNode.graph_id == ag.id).all()
    edges = db.query(AttackEdge).filter(AttackEdge.graph_id == ag.id).all()
    node_map = {n.id: n for n in nodes}

    attacker = next((n for n in nodes if n.node_type == "ATTACKER"), None)
    if attacker is None:
        db.commit()
        return []

    # Best edge per (source, target) pair - several services can connect the
    # same two hosts; the graph keeps the strongest for multi-hop enumeration.
    best_edge: dict[tuple, AttackEdge] = {}
    for e in edges:
        pair = (e.source_node_id, e.target_node_id)
        if pair not in best_edge or e.score > best_edge[pair].score:
            best_edge[pair] = e

    G = nx.DiGraph()
    G.add_nodes_from(n.id for n in nodes)
    for pair, e in best_edge.items():
        G.add_edge(pair[0], pair[1], weight=max(1.0, 100.0 - e.score))

    paths_created: list[AttackPath] = []
    seen: set[str] = set()

    def materialize(edge_chain: list[AttackEdge]):
        """Build and persist one AttackPath from an ordered list of edges."""
        node_ids = [edge_chain[0].source_node_id] + [e.target_node_id for e in edge_chain]
        # Key by the edges themselves: several services can link the same hosts,
        # and each is a distinct path (e.g. ftp-backdoor vs ssh to the same host).
        key = "→".join(e.id for e in edge_chain)
        if key in seen or len(paths_created) >= MAX_PATHS:
            return
        seen.add(key)

        hop_scores, hops, path_cves, path_vectors, path_ips = [], [], [], [], []
        mitre: dict[str, dict] = {}
        for e in edge_chain:
            src, tgt = node_map.get(e.source_node_id), node_map.get(e.target_node_id)
            path_ips.append(src.ip if src else e.source_node_id)
            path_vectors.append(e.attack_vector or e.attack_type)
            path_cves.extend(json.loads(e.cve_ids_json or "[]"))
            hop_scores.append({"reachability": e.reachability or 0.0,
                               "exploitability": e.exploitability or 0.0, "impact": e.impact or 0.0})
            hop_mitre = json.loads(e.mitre_json or "[]")
            for t in hop_mitre:
                mitre[t["id"]] = t
            hops.append({
                "source_ip": src.ip if src else None,
                "source_label": "ATTACKER" if (src and src.node_type == "ATTACKER") else (src.label if src else None),
                "target_ip": tgt.ip if tgt else None,
                "attack_vector": e.attack_vector, "attack_type": e.attack_type,
                "justification": e.justification, "score": e.score,
                "reachability": e.reachability, "exploitability": e.exploitability, "impact": e.impact,
                "cve_ids": json.loads(e.cve_ids_json or "[]"), "mitre": hop_mitre,
            })
        last = node_map.get(edge_chain[-1].target_node_id)
        path_ips.append(last.ip if last else edge_chain[-1].target_node_id)

        agg = scoring.aggregate_path(hop_scores, hop_count=len(edge_chain))
        ap = AttackPath(
            id=str(uuid4()), graph_id=ag.id,
            path_node_ids_json=json.dumps(node_ids), path_ips_json=json.dumps(path_ips),
            attack_vectors_json=json.dumps(path_vectors), total_score=agg["score"],
            hop_count=len(edge_chain), entry_ip=path_ips[1] if len(path_ips) > 1 else None,
            target_ip=path_ips[-1] if path_ips else None, severity=_score_to_severity(agg["score"]),
            cve_ids_json=json.dumps(list(set(path_cves))),
            reachability_score=agg["reachability"], exploitability_score=agg["exploitability"],
            impact_score=agg["impact"], factors_json=json.dumps(agg["factors"]),
            mitre_json=json.dumps(list(mitre.values())),
            justification=" ; then ".join(h["justification"] for h in hops if h["justification"]),
            hops_json=json.dumps(hops),
        )
        db.add(ap)
        paths_created.append(ap)

    # 1) One path per distinct entry service (ATTACKER → host), strongest first.
    entry_edges = sorted((e for e in edges if e.source_node_id == attacker.id),
                         key=lambda e: -e.score)
    for e in entry_edges:
        materialize([e])

    # 2) Multi-hop (lateral) chains, using the strongest edge between hosts.
    targets = [n for n in nodes if n.id != attacker.id]
    for target in targets:
        if len(paths_created) >= MAX_PATHS or not nx.has_path(G, attacker.id, target.id):
            continue
        try:
            multi = [p for p in nx.all_simple_paths(G, attacker.id, target.id, cutoff=MAX_HOPS)
                     if len(p) > 2]
        except Exception:
            continue
        multi.sort(key=lambda p: (_path_cost(p, G), len(p)))
        for path_nodes in multi[:3]:
            chain = [best_edge[(path_nodes[i], path_nodes[i + 1])] for i in range(len(path_nodes) - 1)]
            materialize(chain)

    db.flush()

    # Update graph summary
    if paths_created:
        max_score = max(p.total_score for p in paths_created)
        ag.network_risk_level = _score_to_severity(max_score)
    ag.path_count = len(paths_created)

    db.commit()
    log.info(f"Generated {len(paths_created)} attack paths for graph {ag.id}")
    return paths_created


def _path_cost(path: list[str], G: nx.DiGraph) -> float:
    """Sum of edge weights along a path (lower = easier to exploit)."""
    total = 0.0
    for i in range(len(path) - 1):
        data = G.edges.get((path[i], path[i + 1]))
        total += data.get("weight", 50.0) if data else 50.0
    return total


def _score_to_severity(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"
