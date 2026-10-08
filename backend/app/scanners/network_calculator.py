import ipaddress
import re
import socket
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


# RFC 1123 hostname label: 1-63 letters/digits/hyphens, not starting or ending
# with a hyphen. This also rules out spaces and a leading "-", so a hostname
# can never be interpreted as an nmap command-line option.
_HOSTNAME_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def is_valid_hostname(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    labels = value[:-1].split(".") if value.endswith(".") else value.split(".")
    return all(_HOSTNAME_LABEL.match(label) for label in labels)


def is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def is_valid_scan_target(value: str) -> bool:
    """A scan target must be an IPv4 address or a valid hostname.
    (IPv6 is not supported: names are resolved to IPv4 and nmap runs without -6.)"""
    return is_ipv4(value) or is_valid_hostname(value)


def resolve_target(target: str) -> str:
    """Resolve a hostname to an IPv4 address (IP addresses are returned as-is).

    Raises ValueError if the name cannot be resolved: the unresolved input is
    never passed on to the scanner.
    """
    if is_ipv4(target):
        return target
    try:
        return socket.gethostbyname(target)
    except (socket.gaierror, UnicodeError) as exc:
        raise ValueError(f"Could not resolve '{target}'") from exc


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
