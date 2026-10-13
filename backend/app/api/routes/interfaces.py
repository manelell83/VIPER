from fastapi import APIRouter
from app.core.config import settings
from app.scanners.capabilities import get_capabilities
from app.scanners.interface_detector import get_interfaces
from app.scanners.network_calculator import network_size

router = APIRouter()


@router.get("")
async def list_interfaces():
    """Return all available local network interfaces with subnet info."""
    interfaces = get_interfaces()
    for iface in interfaces:
        iface["host_count"] = network_size(iface["subnet"])
        iface["scannable"] = iface["host_count"] <= settings.MAX_NETWORK_HOSTS
    return {"interfaces": interfaces, "count": len(interfaces), "max_hosts": settings.MAX_NETWORK_HOSTS}


@router.get("/capabilities")
async def scanner_capabilities():
    """Admin rights, Npcap and Nmap availability, with how to fix what is missing."""
    return get_capabilities()
