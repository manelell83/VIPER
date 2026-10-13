"""
Passive domain-recon routes. Recon uses only public data (DNS, RDAP/WHOIS,
Certificate Transparency) plus a single page-like HTTP request - it does not
actively scan, so it does not require the active-scan authorization that
/scan does. A valid login is still required.
"""

import ipaddress
import re
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.api.websocket import manager
from app.core.database import SessionLocal, get_db
from app.domain_recon.models import ReconScan
from app.domain_recon.recon_engine import run_recon
from app.models.user import User

router = APIRouter()

# An RFC 1123 hostname with at least one dot (a registrable domain), e.g.
# example.com. Not an IP: recon is about a domain's public footprint.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")


class ReconRequest(BaseModel):
    target: str = Field(max_length=253)

    @field_validator("target")
    @classmethod
    def must_be_a_domain(cls, value: str) -> str:
        value = value.strip().lower()
        if value.startswith(("http://", "https://")):
            value = value.split("://", 1)[1].split("/", 1)[0]
        value = value.rstrip(".")   # a trailing dot (FQDN root) is valid but we store without it
        try:
            ipaddress.ip_address(value)
            raise ValueError("enter a domain name, not an IP address")
        except ValueError as exc:
            if "domain name" in str(exc):
                raise
        if not _HOSTNAME_RE.match(value):
            raise ValueError("target must be a valid domain name (e.g. example.com)")
        return value


async def _emit(recon_id: str, data: dict):
    await manager.emit(recon_id, data)


async def _background_recon(recon_id: str, target: str):
    db = SessionLocal()
    try:
        await run_recon(recon_id, target, db, lambda d: _emit(recon_id, d))
    finally:
        db.close()


@router.post("")
async def start_recon(
    body: ReconRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Start passive recon on a domain. Returns the recon id and its WebSocket."""
    recon_id = str(uuid4())
    recon = ReconScan(id=recon_id, target=body.target, status="running", created_by=user.username)
    db.add(recon)
    db.commit()

    background_tasks.add_task(_background_recon, recon_id, body.target)
    return {"recon_id": recon_id, "message": "Domain recon started", "websocket": f"/ws/{recon_id}"}


@router.get("")
async def list_recon(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Recent recon sessions (without their full result)."""
    rows = db.query(ReconScan).order_by(ReconScan.created_at.desc()).limit(50).all()
    return {"recon": [r.to_dict(include_result=False) for r in rows]}


@router.get("/{recon_id}")
async def get_recon(recon_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """One recon session with its full structured result."""
    recon = db.query(ReconScan).filter(ReconScan.id == recon_id).first()
    if not recon:
        raise HTTPException(status_code=404, detail="Recon session not found")
    return recon.to_dict()
