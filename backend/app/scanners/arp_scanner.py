import logging
import socket
import subprocess
import platform
from typing import List, Dict, Any, Optional

from app.scanners.capabilities import get_capabilities

log = logging.getLogger(__name__)


def discover_hosts(subnet: str, interface_ip: str) -> Dict[str, Any]:
    """Find the live hosts of `subnet`, reached through the interface `interface_ip`.

    Returns {"hosts": [...], "method": "arp" | "ping", "note": str | None}.
    ARP needs admin rights (and Npcap on Windows). When it cannot run, a ping
    sweep of the same subnet is used and `note` says why: nothing is invented
    and the fallback is never silent.
    """
    caps = get_capabilities()
    if caps["discovery_method"] != "arp":
        reasons = "; ".join(p["message"] for p in caps["problems"] if p["id"] in ("admin", "npcap", "pcap"))
        return {"hosts": _fallback_arp_scan(subnet), "method": "ping",
                "note": f"ARP discovery unavailable ({reasons}) - ping sweep used instead."}
    try:
        return {"hosts": _scapy_arp_scan(subnet, interface_ip), "method": "arp", "note": None}
    except Exception as exc:
        log.warning("ARP discovery failed on %s: %s", subnet, exc)
        return {"hosts": _fallback_arp_scan(subnet), "method": "ping",
                "note": "ARP discovery failed on this interface - ping sweep used instead."}


def _scapy_interface(interface_ip: str) -> Optional[Any]:
    """The Scapy interface that owns `interface_ip`, or None."""
    from scapy.all import conf
    for iface in conf.ifaces.values():
        if getattr(iface, "ip", None) == interface_ip:
            return iface
    return None


def _scapy_arp_scan(subnet: str, interface_ip: str) -> List[Dict[str, Any]]:
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0

    # Send only on the interface the user chose. Without iface=, Scapy uses the
    # default route's interface, which can be a different (unauthorised) network.
    iface = _scapy_interface(interface_ip)
    if iface is None:
        raise RuntimeError(f"no capture interface owns {interface_ip}")

    arp_request = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, iface=iface, timeout=3, verbose=0)

    hosts = []
    for sent, received in answered:
        hostname = _resolve_hostname(received.psrc)
        hosts.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
            "hostname": hostname,
        })

    hosts.sort(key=lambda h: _ip_sort_key(h["ip"]))
    return hosts


def _fallback_arp_scan(subnet: str) -> List[Dict[str, Any]]:
    """
    Fallback: ping sweep + ARP cache read.
    Works without Scapy/Npcap — uses OS ping and arp commands.
    """
    import ipaddress
    import concurrent.futures

    network = ipaddress.IPv4Network(subnet, strict=False)
    hosts_ips = list(network.hosts())

    def ping(ip):
        ip_str = str(ip)
        if platform.system() == "Windows":
            result = subprocess.run(
                ["ping", "-n", "1", "-w", "500", ip_str],
                capture_output=True, timeout=3
            )
        else:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip_str],
                capture_output=True, timeout=3
            )
        return ip_str if result.returncode == 0 else None

    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(ping, hosts_ips)
        alive = [r for r in results if r is not None]

    # Read ARP cache
    arp_cache = _read_arp_cache()

    hosts = []
    for ip in alive:
        hostname = _resolve_hostname(ip)
        hosts.append({
            "ip": ip,
            "mac": arp_cache.get(ip, ""),
            "hostname": hostname,
        })

    hosts.sort(key=lambda h: _ip_sort_key(h["ip"]))
    return hosts


def _read_arp_cache() -> Dict[str, str]:
    """Read the OS ARP cache to get MAC addresses."""
    cache = {}
    try:
        if platform.system() == "Windows":
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0].strip()
                    mac = parts[1].strip()
                    if _is_valid_ip(ip) and "-" in mac:
                        cache[ip] = mac.replace("-", ":")
        else:
            result = subprocess.run(["arp", "-n"], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and _is_valid_ip(parts[0]):
                    cache[parts[0]] = parts[2] if parts[2] != "<incomplete>" else ""
    except Exception:
        pass
    return cache


def _resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _is_valid_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _ip_sort_key(ip: str):
    try:
        return tuple(int(x) for x in ip.split("."))
    except Exception:
        return (0, 0, 0, 0)
