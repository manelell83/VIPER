import asyncio
from uuid import uuid4
from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db, SessionLocal
from app.models.scan import ScanSession
from app.scanners.scan_engine import run_network_scan, run_domain_scan
from app.api.websocket import manager

router = APIRouter()


class NetworkScanRequest(BaseModel):
    interface: str


class DomainScanRequest(BaseModel):
    target: str   # domain name or IP address


async def _emit(scan_id: str, data: dict):
    await manager.emit(scan_id, data)


def _background_network_scan(scan_id: str, interface: str):
    db = SessionLocal()
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(
            run_network_scan(scan_id, interface, db, lambda d: _emit(scan_id, d))
        )
        loop.close()
    finally:
        db.close()


def _background_domain_scan(scan_id: str, target: str):
    db = SessionLocal()
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(
            run_domain_scan(scan_id, target, db, lambda d: _emit(scan_id, d))
        )
        loop.close()
    finally:
        db.close()


@router.post("/network")
async def start_network_scan(
    body: NetworkScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Start a dynamic LAN scan on the selected interface."""
    scan_id = str(uuid4())
    scan = ScanSession(id=scan_id, type="network", target="detecting...", interface=body.interface)
    db.add(scan)
    db.commit()

    background_tasks.add_task(_background_network_scan, scan_id, body.interface)

    return {"scan_id": scan_id, "message": "Network scan started", "websocket": f"/ws/{scan_id}"}


@router.post("/domain")
async def start_domain_scan(
    body: DomainScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Start a domain/IP port scan."""
    target = body.target.strip()
    if not target:
        raise HTTPException(status_code=422, detail="Target cannot be empty")
    if len(target) > 253:
        raise HTTPException(status_code=422, detail="Target too long")
    # Reject obviously invalid characters to prevent injection
    forbidden = {";", "&", "|", "`", "$", "(", ")", "\n", "\r"}
    if any(c in target for c in forbidden):
        raise HTTPException(status_code=422, detail="Invalid characters in target")

    scan_id = str(uuid4())
    scan = ScanSession(id=scan_id, type="domain", target=target)
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
