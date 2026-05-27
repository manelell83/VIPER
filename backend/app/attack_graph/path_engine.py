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

log = logging.getLogger(__name__)

ATTACKER_NODE_ID = "ATTACKER"
MAX_PATHS = 30
MAX_HOPS = 6


def generate_attack_paths(ag: AttackGraph, db: Session) -> list:
    """
    Enumerate attack paths from ATTACKER to all reachable target nodes.
    Scores each path and persists the top MAX_PATHS results.
    Returns the list of AttackPath objects created.
    """
    db.query(AttackPath).filter(AttackPath.graph_id == ag.id).delete()
    db.flush()

    nodes = db.query(AttackNode).filter(AttackNode.graph_id == ag.id).all()
    edges = db.query(AttackEdge).filter(AttackEdge.graph_id == ag.id).all()

    node_map = {n.id: n for n in nodes}
    edge_map: dict[tuple, AttackEdge] = {}

    G = nx.DiGraph()

    for node in nodes:
        G.add_node(node.id)

    for edge in edges:
        cost = max(1.0, 100.0 - edge.score)  # lower score → easier attack
        G.add_edge(edge.source_node_id, edge.target_node_id, weight=cost, score=edge.score, edge=edge)
        edge_map[(edge.source_node_id, edge.target_node_id)] = edge

    if ATTACKER_NODE_ID not in G:
        db.commit()
        return []

    # Target nodes: all non-attacker nodes reachable from ATTACKER
    targets = [n for n in nodes if n.id != ATTACKER_NODE_ID]

    paths_created: list[AttackPath] = []
    seen_paths: set[str] = set()

    for target in targets:
        if not nx.has_path(G, ATTACKER_NODE_ID, target.id):
            continue

        try:
            all_paths = list(nx.all_simple_paths(G, ATTACKER_NODE_ID, target.id, cutoff=MAX_HOPS))
        except Exception:
            continue

        # Prioritize shorter, higher-scoring paths
        all_paths.sort(key=lambda p: (_path_cost(p, G), len(p)))

        for path_nodes in all_paths[:4]:  # max 4 paths per target
            path_key = "→".join(path_nodes)
            if path_key in seen_paths:
                continue
            seen_paths.add(path_key)

            path_ips: list[str] = []
            path_vectors: list[str] = []
            path_cves: list[str] = []
            edge_scores: list[float] = []

            for i in range(len(path_nodes) - 1):
                n = node_map.get(path_nodes[i])
                path_ips.append(n.ip if n else path_nodes[i])
                e = edge_map.get((path_nodes[i], path_nodes[i + 1]))
                if e:
                    path_vectors.append(e.attack_vector or e.attack_type)
                    path_cves.extend(json.loads(e.cve_ids_json or "[]"))
                    edge_scores.append(e.score)

            # Last node IP
            last_node = node_map.get(path_nodes[-1])
            path_ips.append(last_node.ip if last_node else path_nodes[-1])

            if not edge_scores:
                continue

            # Path score: average edge score, penalised by hop count
            avg_score = sum(edge_scores) / len(edge_scores)
            hop_penalty = max(0.0, (len(path_nodes) - 2) * 3.0)
            path_score = max(0.0, min(100.0, avg_score - hop_penalty))

            severity = _score_to_severity(path_score)

            ap = AttackPath(
                id=str(uuid4()),
                graph_id=ag.id,
                path_node_ids_json=json.dumps(path_nodes),
                path_ips_json=json.dumps(path_ips),
                attack_vectors_json=json.dumps(path_vectors),
                total_score=round(path_score, 1),
                hop_count=len(path_nodes) - 1,
                entry_ip=path_ips[1] if len(path_ips) > 1 else None,
                target_ip=path_ips[-1] if path_ips else None,
                severity=severity,
                cve_ids_json=json.dumps(list(set(path_cves))),
            )
            db.add(ap)
            paths_created.append(ap)

            if len(paths_created) >= MAX_PATHS:
                break

        if len(paths_created) >= MAX_PATHS:
            break

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
