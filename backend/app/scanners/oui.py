"""MAC address -> vendor name, from the IEEE OUI list bundled with Scapy (offline)."""

from typing import Optional

LOCALLY_ADMINISTERED = "Locally administered (virtual or randomized MAC)"


def is_locally_administered(mac: str) -> bool:
    """Bit 1 of the first octet set = address not assigned by the IEEE to a vendor."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def mac_vendor(mac: Optional[str]) -> Optional[str]:
    """Vendor name for a MAC address, or None when it is unknown or not a MAC."""
    if not mac or mac.count(":") != 5:
        return None
    mac = mac.lower()
    if is_locally_administered(mac):
        return LOCALLY_ADMINISTERED
    try:
        from scapy.all import conf
        name = conf.manufdb._get_manuf(mac)
    except Exception:
        return None
    # Scapy returns the MAC itself when the prefix is not in its database
    return None if not name or name.lower() == mac else name
