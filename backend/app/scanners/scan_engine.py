import asyncio
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Awaitable

from sqlalchemy.orm import Session

from app.models.scan import ScanSession, Host
from app.scanners.interface_detector import get_interface_by_name
from app.scanners.arp_scanner import arp_scan
from app.scanners.port_scanner import port_scan
from app.scanners.network_calculator import resolve_target
from app.vulnerability_scanner.vulnerability_engine import scan_all_hosts_vulnerabilities
from app.attack_graph.graph_builder import build_attack_graph
from app.attack_graph.path_engine import generate_attack_paths
from app.exploitability.exploitability_engine import run_exploitability_analysis

executor = ThreadPoolExecutor(max_workers=4)

Emitter = Callable[[dict], Awaitable[None]]


async def run_network_scan(scan_id: str, interface_name: str, db: Session, emit: Emitter):
    """Discover all hosts on a LAN by selecting an interface. Subnet is auto-calculated."""
    loop = asyncio.get_running_loop()

    scan = db.query(ScanSession).filter(ScanSession.id == scan_id).first()
    if not scan:
        return

    try:
        iface = get_interface_by_name(interface_name)
        if not iface:
            await _fail(scan, db, emit, f"Interface '{interface_name}' not found")
            return

        scan.status = "running"
        scan.target = iface["subnet"]
        db.commit()

        await emit({"type": "started", "data": {
            "scan_id": scan_id,
            "interface": interface_name,
            "subnet": iface["subnet"],
            "ip": iface["ip"],
        }})

        # --- ARP Discovery ---
        await emit({"type": "progress", "message": f"Running ARP discovery on {iface['subnet']}...", "percent": 10})
        raw_hosts = await loop.run_in_executor(executor, lambda: arp_scan(iface["subnet"]))

        if not raw_hosts:
            await emit({"type": "progress", "message": "No hosts responded to ARP. Trying ping sweep...", "percent": 20})

        await emit({
            "type": "arp_complete",
            "message": f"Discovered {len(raw_hosts)} host(s) via ARP",
            "data": {"count": len(raw_hosts)},
            "percent": 30,
        })

        total = len(raw_hosts)

        # --- Port Scan each host ---
        for idx, raw_host in enumerate(raw_hosts):
            ip = raw_host["ip"]
            pct = 30 + int(60 * (idx / max(total, 1)))

            await emit({
                "type": "host_discovered",
                "message": f"Scanning {ip} ({idx + 1}/{total})",
                "data": {"ip": ip, "mac": raw_host.get("mac"), "hostname": raw_host.get("hostname")},
                "percent": pct,
            })

            scan_result = await loop.run_in_executor(executor, lambda h=ip: port_scan(h))

            host = Host(
                scan_id=scan_id,
                ip=ip,
                mac=raw_host.get("mac"),
                hostname=scan_result.get("hostname") or raw_host.get("hostname"),
                os=scan_result.get("os"),
                os_accuracy=scan_result.get("os_accuracy"),
                status="up",
            )
            host.ports = scan_result.get("ports", [])
            db.add(host)
            db.commit()
            db.refresh(host)

            await emit({
                "type": "host_scanned",
                "message": f"Scanned {ip}: {host.open_ports_count} open ports",
                "data": host.to_dict(),
                "percent": pct + 2,
            })

        # --- Vulnerability Scanning ---
        await emit({"type": "progress", "message": "Starting CVE vulnerability lookup...", "percent": 92})
        db_hosts = db.query(Host).filter(Host.scan_id == scan_id).all()
        total_vulns = await scan_all_hosts_vulnerabilities(db_hosts, db, emit)

        # --- Exploitability Analysis ---
        await emit({"type": "progress", "message": "Analyzing exploitability...", "percent": 94})
        try:
            await run_exploitability_analysis(scan_id, db, emit)
        except Exception as exp_exc:
            await emit({"type": "progress", "message": f"Exploitability analysis skipped: {exp_exc}", "percent": 95})

        # --- Attack Graph Generation ---
        await emit({"type": "progress", "message": "Building attack graph...", "percent": 96})
        try:
            ag = await loop.run_in_executor(executor, lambda: build_attack_graph(scan_id, db))
            if ag:
                paths = await loop.run_in_executor(executor, lambda: generate_attack_paths(ag, db))
                await emit({
                    "type": "attack_graph_generated",
                    "message": f"Attack graph ready: {ag.node_count} nodes, {len(paths)} path(s), risk level {ag.network_risk_level}",
                    "data": {
                        "nodes": ag.node_count,
                        "edges": ag.edge_count,
                        "paths": len(paths),
                        "risk_level": ag.network_risk_level,
                    },
                    "percent": 99,
                })
        except Exception as ag_exc:
            await emit({"type": "progress", "message": f"Attack graph skipped: {ag_exc}", "percent": 99})

        _complete(scan, db)

        await emit({
            "type": "completed",
            "message": f"Scan complete. {total} host(s), {total_vulns} CVE(s) found.",
            "data": {"hosts_count": total, "vuln_count": total_vulns},
            "percent": 100,
        })

    except Exception as exc:
        await _fail(scan, db, emit, str(exc))


async def run_domain_scan(scan_id: str, target: str, db: Session, emit: Emitter):
    """Resolve a domain/IP and run a port scan against it."""
    loop = asyncio.get_running_loop()

    scan = db.query(ScanSession).filter(ScanSession.id == scan_id).first()
    if not scan:
        return

    try:
        scan.status = "running"
        db.commit()

        await emit({"type": "started", "data": {"scan_id": scan_id, "target": target}})

        # Resolve domain → IP
        await emit({"type": "progress", "message": f"Resolving {target}...", "percent": 10})
        ip = await loop.run_in_executor(executor, lambda: resolve_target(target))

        await emit({"type": "progress", "message": f"Resolved to {ip}. Scanning ports...", "percent": 20})

        # Port scan
        scan_result = await loop.run_in_executor(executor, lambda: port_scan(ip, "1-1024"))

        host = Host(
            scan_id=scan_id,
            ip=ip,
            mac=None,
            hostname=scan_result.get("hostname") or (target if target != ip else None),
            os=scan_result.get("os"),
            os_accuracy=scan_result.get("os_accuracy"),
            status="up",
        )
        host.ports = scan_result.get("ports", [])
        db.add(host)
        db.commit()
        db.refresh(host)

        # --- Vulnerability Scanning ---
        await emit({"type": "progress", "message": "Looking up CVEs...", "percent": 85})
        total_vulns = await scan_all_hosts_vulnerabilities([host], db, emit)
        db.refresh(host)

        # --- Exploitability Analysis ---
        await emit({"type": "progress", "message": "Analyzing exploitability...", "percent": 93})
        try:
            await run_exploitability_analysis(scan_id, db, emit)
        except Exception as exp_exc:
            await emit({"type": "progress", "message": f"Exploitability analysis skipped: {exp_exc}", "percent": 95})

        # --- Attack Graph Generation ---
        await emit({"type": "progress", "message": "Building attack graph...", "percent": 96})
        try:
            ag = await loop.run_in_executor(executor, lambda: build_attack_graph(scan_id, db))
            if ag:
                paths = await loop.run_in_executor(executor, lambda: generate_attack_paths(ag, db))
                await emit({
                    "type": "attack_graph_generated",
                    "message": f"Attack graph ready: {ag.node_count} nodes, {len(paths)} path(s)",
                    "data": {
                        "nodes": ag.node_count,
                        "edges": ag.edge_count,
                        "paths": len(paths),
                        "risk_level": ag.network_risk_level,
                    },
                    "percent": 99,
                })
        except Exception as ag_exc:
            await emit({"type": "progress", "message": f"Attack graph skipped: {ag_exc}", "percent": 99})

        _complete(scan, db)

        await emit({
            "type": "completed",
            "message": f"Scan complete. {host.open_ports_count} open port(s), {total_vulns} CVE(s) found.",
            "data": {"hosts_count": 1, "vuln_count": total_vulns, "host": host.to_dict()},
            "percent": 100,
        })

    except Exception as exc:
        await _fail(scan, db, emit, str(exc))


def _complete(scan: ScanSession, db: Session):
    scan.status = "completed"
    scan.completed_at = datetime.utcnow()
    db.commit()


async def _fail(scan: ScanSession, db: Session, emit: Emitter, error: str):
    scan.status = "failed"
    scan.error = error
    scan.completed_at = datetime.utcnow()
    db.commit()
    await emit({"type": "error", "message": error})
