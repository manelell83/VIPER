import psutil
import ipaddress
import socket
from typing import List, Dict, Any


def get_interfaces() -> List[Dict[str, Any]]:
    interfaces = []
    stats = psutil.net_if_stats()

    for name, addrs in psutil.net_if_addrs().items():
        iface_stats = stats.get(name)
        is_up = iface_stats.isup if iface_stats else False

        for addr in addrs:
            # AF_INET = 2 (IPv4)
            if addr.family == socket.AF_INET:
                ip = addr.address
                netmask = addr.netmask or "255.255.255.0"

                # Skip loopback
                if ip.startswith("127."):
                    continue

                try:
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    interfaces.append({
                        "name": name,
                        "ip": ip,
                        "netmask": netmask,
                        "subnet": str(network),
                        "prefix_len": network.prefixlen,
                        "gateway": str(network.network_address + 1),
                        "is_up": is_up,
                    })
                except Exception:
                    continue

    return interfaces


def get_interface_by_name(name: str) -> Dict[str, Any] | None:
    for iface in get_interfaces():
        if iface["name"] == name:
            return iface
    return None
