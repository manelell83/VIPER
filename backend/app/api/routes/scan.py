from uuid import uuid4
from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field, StrictBool, field_validator
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.audit import AUTHORIZATION_STATEMENT, record_scan_authorization
from app.core.database import get_db, SessionLocal
from app.models.scan import ScanSession
from app.models.user import User
from app.scanners.interface_detector import get_interface_by_name
from app.scanners.network_calculator import is_valid_scan_target, network_size
from app.core.config import settings
from app.scanners.scan_engine import run_network_scan, run_domain_scan
from app.api.websocket import manager

router = APIRouter()


class ScanAuthorization(BaseModel):
    # Must be explicitly true: the user confirms they own the target or are
    # authorised to scan it (AUTHORIZATION_STATEMENT). No confirmation, no scan.
    # Required on purpose: with a default value, Pydantic would not run the
    # validator when the field is missing, and the check could be skipped.
    # StrictBool: only a JSON true is accepted (not "yes", "on" or 1).
    authorization_confirmed: StrictBool

    @field_validator("authorization_confirmed")
    @classmethod
    def must_be_confirmed(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("you must confirm you own the target or are authorised to scan it")
        return value


class NetworkScanRequest(ScanAuthorization):
    interface: str = Field(min_length=1, max_length=64)


class DomainScanRequest(ScanAuthorization):
    target: str = Field(max_length=253)   # IPv4 address or hostname

    @field_validator("target")
    @classmethod
    def must_be_ip_or_hostname(cls, value: str) -> str:
        # Allow-list validation: only an IPv4 address or an RFC 1123 hostname
        # is accepted. This blocks nmap option injection such as
        # "example.com -oN /path/file" (spaces and a leading "-" are impossible).
        value = value.strip()
        if not is_valid_scan_target(value):
            raise ValueError("target must be an IPv4 address or a valid hostname")
        return value


async def _emit(scan_id: str, data: dict):
    await manager.emit(scan_id, data)


# Background tasks are async so FastAPI runs them on the main event loop —
# the same loop that owns the WebSocket connections, so emit() is safe.
# Blocking work (ARP, nmap, graph building) is offloaded to a thread pool
# inside scan_engine via run_in_executor.

async def _background_network_scan(scan_id: str, interface: str):
    db = SessionLocal()
    try:
        await run_network_scan(scan_id, interface, db, lambda d: _emit(scan_id, d))
    finally:
        db.close()


async def _background_domain_scan(scan_id: str, target: str):
    db = SessionLocal()
    try:
        await run_domain_scan(scan_id, target, db, lambda d: _emit(scan_id, d))
    finally:
        db.close()


@router.get("/authorization")
async def authorization_statement():
    """The statement a user must confirm before starting an active scan."""
    return {"statement": AUTHORIZATION_STATEMENT}


@router.post("/network")
async def start_network_scan(
    body: NetworkScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Start a dynamic LAN scan on the selected interface (authorization confirmed)."""
    # Only interfaces that actually exist on this machine are accepted
    iface = get_interface_by_name(body.interface)
    if iface is None:
        raise HTTPException(status_code=422, detail=f"Unknown network interface: {body.interface}")

    # Refuse oversized networks: every live host gets an nmap scan, so a /16
    # (65,534 addresses) would run for hours.
    size = network_size(iface["subnet"])
    if size > settings.MAX_NETWORK_HOSTS:
        raise HTTPException(
            status_code=422,
            detail=(f"{iface['subnet']} has {size} addresses; network scans are limited to "
                    f"{settings.MAX_NETWORK_HOSTS} (a /24). Use an interface on a smaller network."),
        )

    scan_id = str(uuid4())
    scan = ScanSession(id=scan_id, type="network", target=iface["subnet"], interface=body.interface)
    record_scan_authorization(scan, user.username)
    db.add(scan)
    db.commit()

    background_tasks.add_task(_background_network_scan, scan_id, body.interface)

    return {"scan_id": scan_id, "message": "Network scan started", "websocket": f"/ws/{scan_id}"}


@router.post("/domain")
async def start_domain_scan(
    body: DomainScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Start a port scan of an IPv4 address or hostname (validated by DomainScanRequest)."""
    target = body.target

    scan_id = str(uuid4())
    scan = ScanSession(id=scan_id, type="domain", target=target)
    record_scan_authorization(scan, user.username)
    db.add(scan)
    db.commit()

    background_tasks.add_task(_background_domain_scan, scan_id, target)

    return {"scan_id": scan_id, "message": "Domain scan started", "websocket": f"/ws/{scan_id}"}


@router.get("/status/{scan_id}")
async def get_scan_status(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(ScanSession).filter(ScanSession.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan.to_dict()
