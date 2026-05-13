from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.scan import ScanSession, Host

router = APIRouter()


@router.get("")
async def list_scans(db: Session = Depends(get_db)):
    """Return all scan sessions ordered by most recent."""
    scans = db.query(ScanSession).order_by(ScanSession.started_at.desc()).all()
    return {"scans": [s.to_dict() for s in scans], "count": len(scans)}


@router.get("/{scan_id}")
async def get_scan_results(scan_id: str, db: Session = Depends(get_db)):
    """Return full details of a scan session including all hosts."""
    scan = db.query(ScanSession).filter(ScanSession.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    hosts = db.query(Host).filter(Host.scan_id == scan_id).all()
    return {
        "scan": scan.to_dict(),
        "hosts": [h.to_dict() for h in hosts],
    }


@router.delete("/{scan_id}")
async def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    """Delete a scan session and all associated hosts."""
    scan = db.query(ScanSession).filter(ScanSession.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return {"message": "Scan deleted"}
