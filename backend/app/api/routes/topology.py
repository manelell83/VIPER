from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.scan import ScanSession, Host
from app.scanners.host_role import classify_host, ROLE_LABELS

router = APIRouter()


@router.get("/{scan_id}")
async def get_topology(scan_id: str, db: Session = Depends(get_db)):
    """
    Return topology data formatted for Cytoscape.js.
    Nodes: gateway + hosts. Edges: gateway → host.
    """
    scan = db.query(ScanSession).filter(ScanSession.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    hosts = db.query(Host).filter(Host.scan_id == scan_id).all()

    nodes = []
    edges = []

    # Infer gateway from the subnet (first host address)
    gateway_ip = _infer_gateway(scan.target, hosts)

    if gateway_ip:
        nodes.append({
            "data": {
                "id": f"gw_{gateway_ip.replace('.', '_')}",
                "label": f"Gateway\n{gateway_ip}",
                "type": "gateway",
                "ip": gateway_ip,
                "mac": "",
                "hostname": "Gateway",
                "os": "",
                "open_ports": 0,
                "role": "gateway",
                "roles": ["gateway"],
            }
        })

    for host in hosts:
        node_id = f"host_{host.ip.replace('.', '_')}"
        # Role inferred from the services actually observed (not certified)
        role = classify_host(host.ports or [])
        nodes.append({
            "data": {
                "id": node_id,
                "label": host.hostname or host.ip,
                "type": "host",
                "ip": host.ip,
                "mac": host.mac or "",
                "hostname": host.hostname or "",
                "os": host.os or "Unknown",
                "open_ports": host.open_ports_count,
                "status": host.status,
                "vuln_count": host.vuln_count,
                "max_severity": host.max_severity(),
                "role": role["primary"],
                "roles": role["roles"],
            }
        })

        if gateway_ip:
            gw_id = f"gw_{gateway_ip.replace('.', '_')}"
            edges.append({
                "data": {
                    "id": f"edge_{gw_id}_{node_id}",
                    "source": gw_id,
                    "target": node_id,
                }
            })

    return {
        "scan_id": scan_id,
        "elements": {"nodes": nodes, "edges": edges},
        "role_labels": ROLE_LABELS,
        "role_note": "Roles are inferred from the services observed on each host, not certified "
                     "(e.g. an open port 53 does not prove an authoritative DNS server).",
        "stats": {
            "nodes": len(nodes),
            "edges": len(edges),
            "hosts": len(hosts),
        },
    }


def _infer_gateway(subnet: str, hosts: list) -> str | None:
    """Return the gateway IP from scan target or discover from host list."""
    import ipaddress

    # Try parsing subnet CIDR
    try:
        network = ipaddress.IPv4Network(subnet, strict=False)
        gw_candidate = str(network.network_address + 1)
        # Check if this gateway was actually discovered
        host_ips = {h.ip for h in hosts}
        if gw_candidate in host_ips:
            return gw_candidate
        # Still return candidate even if not in scan (common gateway)
        if network.num_addresses > 2:
            return gw_candidate
    except Exception:
        pass

    return None
