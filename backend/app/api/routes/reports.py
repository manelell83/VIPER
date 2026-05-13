import io
import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.scan import ScanSession, Host

router = APIRouter()


@router.get("/export/{scan_id}/json")
async def export_json(scan_id: str, db: Session = Depends(get_db)):
    """Export scan results as JSON."""
    scan = db.query(ScanSession).filter(ScanSession.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    hosts = db.query(Host).filter(Host.scan_id == scan_id).all()

    payload = {
        "report": {
            "generated_at": datetime.utcnow().isoformat(),
            "app": "ViperV2 Network Scanner",
            "version": "2.0.0",
        },
        "scan": scan.to_dict(),
        "hosts": [h.to_dict() for h in hosts],
        "summary": {
            "total_hosts": len(hosts),
            "total_open_ports": sum(h.open_ports_count for h in hosts),
            "os_distribution": _os_distribution(hosts),
        },
    }

    content = json.dumps(payload, indent=2, default=str)
    filename = f"viperv2_scan_{scan_id[:8]}_{datetime.utcnow().strftime('%Y%m%d')}.json"

    return StreamingResponse(
        iter([content]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/export/{scan_id}/pdf")
async def export_pdf(scan_id: str, db: Session = Depends(get_db)):
    """Export scan results as PDF using ReportLab."""
    scan = db.query(ScanSession).filter(ScanSession.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    hosts = db.query(Host).filter(Host.scan_id == scan_id).all()

    try:
        pdf_bytes = _generate_pdf(scan, hosts)
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="ReportLab not installed. Install with: pip install reportlab",
        )

    filename = f"viperv2_scan_{scan_id[:8]}_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def _generate_pdf(scan: ScanSession, hosts: list) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.units import cm

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=2 * cm, bottomMargin=2 * cm)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    title_style = ParagraphStyle("Title", parent=styles["Heading1"], fontSize=20, textColor=colors.HexColor("#0ea5e9"))
    elements.append(Paragraph("ViperV2 Network Scan Report", title_style))
    elements.append(Spacer(1, 0.5 * cm))

    # Meta
    meta = [
        ["Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
        ["Scan ID", scan.id[:8] + "..."],
        ["Type", scan.type.upper()],
        ["Target", scan.target],
        ["Status", scan.status.upper()],
        ["Hosts Found", str(len(hosts))],
        ["Total Open Ports", str(sum(h.open_ports_count for h in hosts))],
    ]
    meta_table = Table(meta, colWidths=[5 * cm, 12 * cm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#374151")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 1 * cm))

    # Hosts table
    elements.append(Paragraph("Discovered Hosts", styles["Heading2"]))
    elements.append(Spacer(1, 0.3 * cm))

    headers = ["IP Address", "MAC Address", "Hostname", "OS", "Open Ports"]
    rows = [headers]
    for h in hosts:
        open_ports = ", ".join(str(p["port"]) for p in h.ports if p.get("state") == "open")[:60]
        rows.append([
            h.ip or "",
            h.mac or "N/A",
            h.hostname or "N/A",
            (h.os or "Unknown")[:30],
            open_ports or "None",
        ])

    host_table = Table(rows, repeatRows=1)
    host_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0ea5e9")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(host_table)

    doc.build(elements)
    return buf.getvalue()


def _os_distribution(hosts: list) -> dict:
    dist: dict = {}
    for h in hosts:
        key = h.os or "Unknown"
        dist[key] = dist.get(key, 0) + 1
    return dist
