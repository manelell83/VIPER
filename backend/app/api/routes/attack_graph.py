"""
Attack graph API routes.
Fixed routes (/paths, /paths/critical, /risk-summary) must be defined
before the parameterized /{scan_id} route so FastAPI resolves them correctly.
"""

import json
import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.attack_graph.models import AttackGraph, AttackNode, AttackEdge, AttackPath
from app.attack_graph.graph_builder import build_attack_graph
from app.attack_graph.path_engine import generate_attack_paths
from app.attack_graph.risk_paths import analyze_risk

log = logging.getLogger(__name__)
router = APIRouter()


# ── Fixed routes first (must precede /{scan_id}) ────────────────────────────

@router.get("/paths")
async def list_paths(scan_id: str = None, severity: str = None, db: Session = Depends(get_db)):
    """List attack paths, optionally filtered by scan_id and/or severity."""
    query = db.query(AttackPath)

    if scan_id:
        ag = db.query(AttackGraph).filter(AttackGraph.scan_id == scan_id).first()
        if ag:
            query = query.filter(AttackPath.graph_id == ag.id)
        else:
            return {"paths": []}

    if severity:
        query = query.filter(AttackPath.severity == severity.upper())

    paths = query.order_by(AttackPath.total_score.desc()).limit(50).all()
    return {"paths": [p.to_dict() for p in paths]}


@router.get("/paths/critical")
async def critical_paths(db: Session = Depends(get_db)):
    """Return all CRITICAL and HIGH severity attack paths across all scans."""
    paths = (
        db.query(AttackPath)
        .filter(AttackPath.severity.in_(["CRITICAL", "HIGH"]))
        .order_by(AttackPath.total_score.desc())
        .limit(25)
        .all()
    )
    return {"paths": [p.to_dict() for p in paths]}


@router.get("/risk-summary")
async def risk_summary(scan_id: str, db: Session = Depends(get_db)):
    """Full risk analysis for a specific scan."""
    ag = db.query(AttackGraph).filter(AttackGraph.scan_id == scan_id).first()
    if not ag:
        # Try generating on demand
        ag = build_attack_graph(scan_id, db)
        if not ag:
            raise HTTPException(404, "No scan or hosts found for this scan_id")
        generate_attack_paths(ag, db)

    risk = analyze_risk(ag, db)
    return {
        **risk,
        "graph_stats": ag.to_dict(),
    }


# ── Parameterized routes ─────────────────────────────────────────────────────

@router.get("/{scan_id}")
async def get_attack_graph(scan_id: str, db: Session = Depends(get_db)):
    """
    Get the attack graph for a scan.
    If not yet generated, builds it on demand.
    Returns Cytoscape-ready elements + path list + risk analysis.
    """
    ag = db.query(AttackGraph).filter(AttackGraph.scan_id == scan_id).first()

    if not ag:
        ag = build_attack_graph(scan_id, db)
        if not ag:
            raise HTTPException(404, "Scan not found or has no hosts")
        generate_attack_paths(ag, db)

    nodes = db.query(AttackNode).filter(AttackNode.graph_id == ag.id).all()
    edges = db.query(AttackEdge).filter(AttackEdge.graph_id == ag.id).all()
    paths = (
        db.query(AttackPath)
        .filter(AttackPath.graph_id == ag.id)
        .order_by(AttackPath.total_score.desc())
        .limit(20)
        .all()
    )

    # Format as Cytoscape elements
    cy_nodes = []
    for node in nodes:
        meta = json.loads(node.metadata_json or "{}")
        cy_nodes.append({
            "data": {
                "id": node.id,
                "label": node.label,
                "type": node.node_type,
                "ip": node.ip,
                "risk_score": node.risk_score,
                "is_entry": node.is_entry_point,
                "is_critical": node.is_critical,
                **meta,
            }
        })

    cy_edges = []
    for edge in edges:
        cy_edges.append({
            "data": {
                "id": edge.id,
                "source": edge.source_node_id,
                "target": edge.target_node_id,
                "attack_type": edge.attack_type,
                "attack_vector": edge.attack_vector,
                "score": edge.score,
                "port": edge.port,
                "service": edge.service,
                "description": edge.description,
                "cvss": edge.cvss,
                "cve_ids": json.loads(edge.cve_ids_json or "[]"),
            }
        })

    risk = analyze_risk(ag, db)

    return {
        "scan_id": scan_id,
        "graph_id": ag.id,
        "generated_at": ag.generated_at.isoformat() if ag.generated_at else None,
        "stats": {
            "nodes": ag.node_count,
            "edges": ag.edge_count,
            "paths": ag.path_count,
            "entry_points": ag.entry_point_count,
            "risk_level": ag.network_risk_level,
        },
        "elements": {
            "nodes": cy_nodes,
            "edges": cy_edges,
        },
        "paths": [p.to_dict() for p in paths],
        "risk_analysis": risk,
    }


@router.post("/{scan_id}/regenerate")
async def regenerate(scan_id: str, db: Session = Depends(get_db)):
    """Force-regenerate the attack graph for a scan."""
    ag = build_attack_graph(scan_id, db)
    if not ag:
        raise HTTPException(404, "Scan not found or has no hosts")
    paths = generate_attack_paths(ag, db)
    return {
        "message": "Attack graph regenerated",
        "scan_id": scan_id,
        "nodes": ag.node_count,
        "edges": ag.edge_count,
        "paths": len(paths),
    }
