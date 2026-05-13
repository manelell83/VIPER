import socket
import struct
import subprocess
import platform
from typing import List, Dict, Any


def arp_scan(subnet: str) -> List[Dict[str, Any]]:
    """
    Perform ARP scan on the given subnet.
    Uses Scapy when available (requires Npcap on Windows), falls back to
    OS-native ARP ping sweep via subprocess.
    """
    try:
        return _scapy_arp_scan(subnet)
    except Exception:
        return _fallback_arp_scan(subnet)


def _scapy_arp_scan(subnet: str) -> List[Dict[str, Any]]:
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0

    arp_request = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, timeout=3, verbose=0)

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
