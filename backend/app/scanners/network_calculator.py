import ipaddress
from typing import Dict, Any


def calculate_subnet(ip: str, netmask: str) -> Dict[str, Any]:
    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    return {
        "network": str(network),
        "network_address": str(network.network_address),
        "broadcast_address": str(network.broadcast_address),
        "prefix_len": network.prefixlen,
        "num_hosts": network.num_addresses - 2,
        "host_range": f"{network.network_address + 1} - {network.broadcast_address - 1}",
    }


def resolve_target(target: str) -> str:
    """Resolve domain/hostname to IP address."""
    import socket
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False
