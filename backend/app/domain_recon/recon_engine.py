"""
Orchestrates a passive domain recon and links the findings into a graph:

    domain ─┬─ subdomain ─── IP ─── service (HTTP fingerprint)
            └─ IP (apex)  ─── service

Everything is passive: DNS lookups, RDAP/whois, crt.sh (Certificate
Transparency) and a single page-like HTTP request per host. No port scanning.
Each step degrades gracefully - a source being down never fails the recon.
"""

import asyncio
import json
import logging
from typing import Awaitable, Callable, Dict, List

import httpx
from sqlalchemy.orm import Session

from app.core.timeutil import utcnow
from app.domain_recon.dns_recon import resolve_records, reverse_dns
from app.domain_recon.http_fingerprint import fingerprint
from app.domain_recon.models import ReconScan
from app.domain_recon.subdomain_recon import fetch_subdomains
from app.domain_recon.whois_recon import lookup_whois

log = logging.getLogger(__name__)

Emitter = Callable[[dict], Awaitable[None]]

# Keep the recon light and bounded, even for domains with hundreds of CT names.
MAX_SUBDOMAINS_RESOLVED = 25    # how many subdomains we resolve to IPs for the graph
MAX_FINGERPRINTS = 12           # how many hosts we fetch a page from

INTERNAL_ERROR_MESSAGE = "Recon failed due to an internal error (see server logs)"


async def run_recon(recon_id: str, target: str, db: Session, emit: Emitter) -> None:
    recon = db.query(ReconScan).filter(ReconScan.id == recon_id).first()
    if not recon:
        return

    loop = asyncio.get_running_loop()
    try:
        recon.status = "running"
        db.commit()
        await emit({"type": "started", "data": {"recon_id": recon_id, "target": target}})

        # ── DNS ────────────────────────────────────────────────────────────
        await emit({"type": "progress", "message": f"Resolving DNS records for {target}...", "percent": 10})
        dns = await loop.run_in_executor(None, resolve_records, target)
        await emit({"type": "dns_complete",
                    "message": f"DNS: {len(dns['A'])} A, {len(dns['AAAA'])} AAAA, {len(dns['MX'])} MX, "
                               f"{len(dns['NS'])} NS record(s)",
                    "data": dns, "percent": 25})

        async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
            # ── WHOIS / RDAP ──────────────────────────────────────────────
            await emit({"type": "progress", "message": "Looking up registration (RDAP/WHOIS)...", "percent": 35})
            whois = await lookup_whois(target, client)
            await emit({"type": "whois_complete",
                        "message": f"Registration via {whois.get('source') or 'none'}"
                                   + (f": {whois['registrar']}" if whois.get("registrar") else ""),
                        "data": whois, "percent": 45})

            # ── Subdomains (crt.sh) ───────────────────────────────────────
            await emit({"type": "progress", "message": "Querying crt.sh for subdomains...", "percent": 55})
            subs = await fetch_subdomains(target, client)
            if subs["available"]:
                await emit({"type": "subdomains_complete",
                            "message": f"Found {len(subs['subdomains'])} subdomain(s) via crt.sh",
                            "data": {"count": len(subs["subdomains"]), "available": True}, "percent": 65})
            else:
                await emit({"type": "subdomains_complete", "message": subs["error"],
                            "data": {"count": 0, "available": False}, "percent": 65})

            # ── Resolve apex + subdomains to IPs (passive) ────────────────
            await emit({"type": "progress", "message": "Resolving hosts to IP addresses...", "percent": 75})
            hosts = [target] + [s for s in subs["subdomains"] if s != target][:MAX_SUBDOMAINS_RESOLVED]
            host_ips = await _resolve_hosts(hosts, loop)

            # ── Reverse DNS for each IP ───────────────────────────────────
            all_ips = sorted({ip for ips in host_ips.values() for ip in ips})
            ptr = await _reverse_all(all_ips, loop)

            # ── Light HTTP fingerprint (page visit, not a port scan) ──────
            await emit({"type": "progress", "message": "Fingerprinting reachable web hosts...", "percent": 85})
            fp_hosts = [h for h in hosts if host_ips.get(h)][:MAX_FINGERPRINTS]
            fingerprints = await _fingerprint_all(fp_hosts, client)

        result = _build_result(target, dns, whois, subs, host_ips, ptr, fingerprints)
        recon.result_json = json.dumps(result)
        recon.status = "completed"
        recon.completed_at = utcnow()
        db.commit()

        reachable = sum(1 for f in fingerprints if f["reachable"])
        await emit({"type": "completed",
                    "message": f"Recon complete: {len(all_ips)} IP(s), {len(subs['subdomains'])} subdomain(s), "
                               f"{reachable} web host(s)",
                    "data": {"recon_id": recon_id}, "percent": 100})

    except Exception as exc:
        log.exception("Recon failed for %s", target)
        recon.status = "failed"
        recon.error = INTERNAL_ERROR_MESSAGE
        db.commit()
        await emit({"type": "error", "message": INTERNAL_ERROR_MESSAGE, "data": {"recon_id": recon_id}})
        _ = exc


async def _resolve_hosts(hosts: List[str], loop) -> Dict[str, List[str]]:
    """{host: [IPs]} from A/AAAA records, resolved concurrently."""
    async def one(host):
        records = await loop.run_in_executor(None, resolve_records, host)
        return host, sorted(set(records["A"]) | set(records["AAAA"]))

    return dict(await asyncio.gather(*(one(h) for h in hosts)))


async def _reverse_all(ips: List[str], loop) -> Dict[str, str]:
    async def one(ip):
        return ip, await loop.run_in_executor(None, reverse_dns, ip)

    return {ip: name for ip, name in await asyncio.gather(*(one(ip) for ip in ips))}


async def _fingerprint_all(hosts: List[str], client) -> List[dict]:
    return list(await asyncio.gather(*(fingerprint(h, client) for h in hosts)))


def _build_result(target, dns, whois, subs, host_ips, ptr, fingerprints) -> dict:
    """Assemble the recon document, including the linked entity graph."""
    fp_by_host = {f["host"]: f for f in fingerprints}

    ips = [{"ip": ip, "ptr": ptr.get(ip) or None} for ip in sorted({i for v in host_ips.values() for i in v})]

    nodes, edges = _build_graph(target, subs["subdomains"], host_ips, fp_by_host)

    return {
        "domain": target,
        "dns": dns,
        "whois": whois,
        "subdomains": {"available": subs["available"], "error": subs["error"], "list": subs["subdomains"]},
        "ips": ips,
        "fingerprints": fingerprints,
        "graph": {"nodes": nodes, "edges": edges},
        "generated_at": utcnow().isoformat() + "Z",
    }


def _build_graph(target, subdomains, host_ips, fp_by_host):
    """domain -> subdomains -> IPs -> services, as typed nodes and edges."""
    nodes = {}   # id -> node
    edges = []

    def node(node_id, ntype, label, **extra):
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "type": ntype, "label": label, **extra}

    def edge(src, dst):
        pair = {"source": src, "target": dst}
        if pair not in edges:
            edges.append(pair)

    node(f"domain:{target}", "domain", target)

    for host, ips in host_ips.items():
        host_node = f"domain:{target}" if host == target else f"subdomain:{host}"
        if host != target:
            node(host_node, "subdomain", host)
            edge(f"domain:{target}", host_node)

        fp = fp_by_host.get(host)
        for ip in ips:
            ip_node = f"ip:{ip}"
            node(ip_node, "ip", ip)
            edge(host_node, ip_node)
            if fp and fp["reachable"]:
                svc_label = fp.get("server") or f"HTTP {fp.get('status')}"
                svc_node = f"service:{ip}:{svc_label}"
                node(svc_node, "service", svc_label, title=fp.get("title"), status=fp.get("status"))
                edge(ip_node, svc_node)

    # Subdomains discovered but not resolved still appear, linked to the domain
    for sub in subdomains:
        if sub != target and f"subdomain:{sub}" not in nodes:
            node(f"subdomain:{sub}", "subdomain", sub, unresolved=True)
            edge(f"domain:{target}", f"subdomain:{sub}")

    return list(nodes.values()), edges
