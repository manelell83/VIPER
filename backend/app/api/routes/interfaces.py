from fastapi import APIRouter
from app.scanners.interface_detector import get_interfaces

router = APIRouter()


@router.get("")
async def list_interfaces():
    """Return all available local network interfaces with subnet info."""
    interfaces = get_interfaces()
    return {"interfaces": interfaces, "count": len(interfaces)}
