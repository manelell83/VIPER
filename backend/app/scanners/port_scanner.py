import socket
import concurrent.futures
from typing import Dict, Any, List


def port_scan(ip: str, port_range: str = "1-1024") -> Dict[str, Any]:
    """
    Scan ports on the given IP using python-nmap.
    Falls back to a raw socket scan if nmap is unavailable.
    """
    try:
        return _nmap_scan(ip, port_range)
    except Exception as e:
        return _socket_scan(ip, port_range)


def _nmap_scan(ip: str, port_range: str = "1-1024") -> Dict[str, Any]:
    import nmap

    nm = nmap.PortScanner()
    arguments = f"-sV --host-timeout 60s -T4"

    # Try OS detection (requires admin/root — graceful degradation)
    try:
        nm.scan(ip, port_range, arguments=arguments + " -O")
    except nmap.PortScannerError:
        nm.scan(ip, port_range, arguments=arguments)

    if ip not in nm.all_hosts():
        return {"ports": [], "os": None, "os_accuracy": None, "hostname": None}

    return _parse_nmap_host(nm[ip])


def _parse_nmap_host(host) -> Dict[str, Any]:
    """Convert one python-nmap host result (PortScannerHostDict) into our format.

    Kept separate from _nmap_scan so it can be unit-tested without running nmap.
    """
    result: Dict[str, Any] = {
        "ports": [],
        "os": None,
        "os_accuracy": None,
        "hostname": None,
    }

    # Hostname
    if host.hostname():
        result["hostname"] = host.hostname()

    # OS detection
    if "osmatch" in host and host["osmatch"]:
        best = host["osmatch"][0]
        result["os"] = best.get("name", "Unknown")
        result["os_accuracy"] = int(best.get("accuracy", 0))

    # Ports
    ports = []
    for proto in host.all_protocols():
        for port_num in sorted(host[proto].keys()):
            port_data = host[proto][port_num]
            ports.append({
                "port": port_num,
                "protocol": proto,
                "state": port_data.get("state", "unknown"),
                "service": port_data.get("name", ""),
                "version": _build_version_string(port_data),
                "product": port_data.get("product", ""),
            })

    result["ports"] = ports
    return result


def _build_version_string(port_data: Dict) -> str:
    parts = [
        port_data.get("product", ""),
        port_data.get("version", ""),
        port_data.get("extrainfo", ""),
    ]
    return " ".join(p for p in parts if p).strip()


def _socket_scan(ip: str, port_range: str = "1-1024") -> Dict[str, Any]:
    """Raw socket fallback when nmap is not available."""
    start, end = (int(p) for p in port_range.split("-"))
    open_ports = []

    def check_port(port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    service = _get_service_name(port)
                    return {
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        "service": service,
                        "version": "",
                        "product": "",
                    }
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(check_port, range(start, end + 1))
        open_ports = [r for r in results if r is not None]

    hostname = ""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    return {
        "ports": sorted(open_ports, key=lambda p: p["port"]),
        "os": None,
        "os_accuracy": None,
        "hostname": hostname,
    }


def _get_service_name(port: int) -> str:
    COMMON = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 143: "imap", 443: "https",
        445: "smb", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
        5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
        27017: "mongodb", 9200: "elasticsearch",
    }
    return COMMON.get(port, "")
