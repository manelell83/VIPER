import io
import json
from datetime import datetime
from xml.sax.saxutils import escape
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
    """Export full security assessment report as PDF."""
    scan = db.query(ScanSession).filter(ScanSession.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        pdf_bytes = _generate_advanced_pdf(scan_id, scan, db)
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="ReportLab not installed. Install with: pip install reportlab",
        )

    filename = f"viperv2_report_{scan_id[:8]}_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ─── PDF Generation ───────────────────────────────────────────────────────────

def _generate_advanced_pdf(scan_id: str, scan: ScanSession, db: Session) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,
        HRFlowable, PageBreak,
    )
    from reportlab.lib.units import cm
    from reportlab.lib.enums import TA_CENTER, TA_LEFT

    # Load all data
    hosts = db.query(Host).filter(Host.scan_id == scan_id).all()

    from app.vulnerability_scanner.models import Vulnerability
    from app.exploitability.models import ExploitabilityAssessment, RemediationItem
    from app.attack_graph.models import AttackGraph, AttackPath

    all_vulns = db.query(Vulnerability).filter(
        Vulnerability.host_id.in_([h.id for h in hosts])
    ).all() if hosts else []

    assessments = db.query(ExploitabilityAssessment).filter(
        ExploitabilityAssessment.scan_id == scan_id
    ).all()

    remediation_items = db.query(RemediationItem).filter(
        RemediationItem.scan_id == scan_id
    ).all()

    ag = db.query(AttackGraph).filter(AttackGraph.scan_id == scan_id).first()
    attack_paths = (
        db.query(AttackPath)
        .filter(AttackPath.graph_id == ag.id)
        .order_by(AttackPath.total_score.desc())
        .limit(10)
        .all()
        if ag else []
    )

    # Compute security score
    vuln_penalty = min(50, len(all_vulns) * 2)
    exploit_penalty = min(30, len([a for a in assessments if a.exploit_maturity in ("WEAPONIZED", "FUNCTIONAL")]) * 5)
    path_penalty = min(20, len([p for p in attack_paths if getattr(p, "severity", "") in ("CRITICAL", "HIGH")]) * 4)
    security_score = max(0, 100 - vuln_penalty - exploit_penalty - path_penalty)

    # Color palette
    C_DARK    = colors.HexColor("#0f172a")
    C_BLUE    = colors.HexColor("#0ea5e9")
    C_RED     = colors.HexColor("#ef4444")
    C_ORANGE  = colors.HexColor("#f97316")
    C_YELLOW  = colors.HexColor("#eab308")
    C_GREEN   = colors.HexColor("#22c55e")
    C_GRAY    = colors.HexColor("#64748b")
    C_LIGHT   = colors.HexColor("#f8fafc")
    C_BORDER  = colors.HexColor("#e2e8f0")
    C_ROW_ALT = colors.HexColor("#f1f5f9")

    SEV_COLORS = {
        "CRITICAL": C_RED,
        "HIGH":     C_ORANGE,
        "MEDIUM":   C_YELLOW,
        "LOW":      C_GREEN,
    }

    MATURITY_COLORS = {
        "WEAPONIZED":  C_RED,
        "FUNCTIONAL":  C_ORANGE,
        "POC":         C_YELLOW,
        "THEORETICAL": C_GRAY,
        "UNPROVEN":    C_GRAY,
    }

    PRIORITY_COLORS = {
        "IMMEDIATE": C_RED,
        "CRITICAL":  C_RED,
        "URGENT":    C_ORANGE,
        "HIGH":      C_ORANGE,
        "SCHEDULED": C_YELLOW,
        "MEDIUM":    C_YELLOW,
        "MONITOR":   C_GREEN,
        "LOW":       C_GREEN,
    }

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=1.5 * cm, bottomMargin=1.5 * cm,
        leftMargin=2 * cm, rightMargin=2 * cm,
    )
    styles = getSampleStyleSheet()
    W = A4[0] - 4 * cm  # usable width

    def _h1(text):
        s = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=18,
                           textColor=C_BLUE, spaceAfter=6)
        return Paragraph(text, s)

    def _h2(text):
        s = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=13,
                           textColor=C_DARK, spaceBefore=12, spaceAfter=4)
        return Paragraph(text, s)

    def _h3(text):
        s = ParagraphStyle("h3", parent=styles["Heading3"], fontSize=11,
                           textColor=C_DARK, spaceBefore=8, spaceAfter=3)
        return Paragraph(text, s)

    def _body(text):
        s = ParagraphStyle("body", parent=styles["Normal"], fontSize=9,
                           textColor=C_DARK, spaceAfter=3)
        return Paragraph(text, s)

    def _divider():
        return HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=6)

    def _score_color(score):
        if score >= 80:
            return C_GREEN
        if score >= 60:
            return C_YELLOW
        if score >= 40:
            return C_ORANGE
        return C_RED

    def _sev_style(rows_with_sev, header_len=1):
        cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), C_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]
        for i, sev in enumerate(rows_with_sev):
            row_i = i + header_len
            c = SEV_COLORS.get(sev, C_GRAY)
            cmds.append(("BACKGROUND", (0, row_i), (-1, row_i), colors.Color(c.red, c.green, c.blue, alpha=0.12)))
            if i % 2 == 1 and sev not in SEV_COLORS:
                cmds.append(("BACKGROUND", (0, row_i), (-1, row_i), C_ROW_ALT))
        return TableStyle(cmds)

    elems = []

    # ── COVER PAGE ────────────────────────────────────────────────────────────
    elems.append(Spacer(1, 2 * cm))
    cover_title = ParagraphStyle("ct", parent=styles["Title"], fontSize=28,
                                 textColor=C_BLUE, alignment=TA_CENTER)
    elems.append(Paragraph("ViperV2 Security Report", cover_title))
    elems.append(Spacer(1, 0.5 * cm))
    sub = ParagraphStyle("sub", parent=styles["Normal"], fontSize=12,
                         textColor=C_GRAY, alignment=TA_CENTER)
    elems.append(Paragraph("Intelligent Network Security Assessment Platform", sub))
    elems.append(Spacer(1, 1.5 * cm))

    # Score box
    score_label = "SECURE" if security_score >= 80 else ("MODERATE" if security_score >= 60 else ("AT RISK" if security_score >= 40 else "CRITICAL"))
    score_data = [[f"Security Score: {security_score}/100  [{score_label}]"]]
    score_tbl = Table(score_data, colWidths=[W])
    sc = _score_color(security_score)
    score_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), sc),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 16),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("PADDING", (0, 0), (-1, -1), 14),
    ]))
    elems.append(score_tbl)
    elems.append(Spacer(1, 1 * cm))

    # Cover metadata
    cover_meta = [
        ["Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
        ["Scan ID", scan.id[:16] + "..."],
        ["Target", scan.target or "N/A"],
        ["Scan Type", scan.type.upper()],
        ["Status", scan.status.upper()],
    ]
    cm_tbl = Table(cover_meta, colWidths=[4 * cm, W - 4 * cm])
    cm_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), C_DARK),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    elems.append(cm_tbl)
    elems.append(PageBreak())

    # ── SECTION 1: EXECUTIVE SUMMARY ─────────────────────────────────────────
    elems.append(_h1("1. Executive Summary"))
    elems.append(_divider())

    by_sev = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for v in all_vulns:
        if v.severity in by_sev:
            by_sev[v.severity] += 1

    weaponized = sum(1 for a in assessments if a.exploit_maturity == "WEAPONIZED")
    functional = sum(1 for a in assessments if a.exploit_maturity == "FUNCTIONAL")
    immediate_patch = sum(1 for r in remediation_items if r.priority in ("IMMEDIATE", "CRITICAL"))

    summary_rows = [
        ["Metric", "Value", "Risk"],
        ["Total Hosts Discovered", str(len(hosts)), "—"],
        ["Total Open Ports", str(sum(h.open_ports_count for h in hosts)), "—"],
        ["Total Vulnerabilities", str(len(all_vulns)), "HIGH" if len(all_vulns) > 20 else "MEDIUM" if len(all_vulns) > 5 else "LOW"],
        ["Critical CVEs", str(by_sev["CRITICAL"]), "CRITICAL" if by_sev["CRITICAL"] > 0 else "OK"],
        ["High CVEs", str(by_sev["HIGH"]), "HIGH" if by_sev["HIGH"] > 0 else "OK"],
        ["Weaponized Exploits", str(weaponized), "CRITICAL" if weaponized > 0 else "OK"],
        ["Functional Exploits", str(functional), "HIGH" if functional > 0 else "OK"],
        ["Attack Paths Found", str(ag.path_count if ag else 0), "HIGH" if (ag and ag.path_count > 0) else "OK"],
        ["Immediate Patch Actions", str(immediate_patch), "CRITICAL" if immediate_patch > 0 else "OK"],
        ["Network Risk Level", ag.network_risk_level if ag else "NONE", ag.network_risk_level if ag else "NONE"],
        ["Overall Security Score", f"{security_score}/100", score_label],
    ]
    sev_col = [r[2] for r in summary_rows[1:]]
    s_tbl = Table(summary_rows, colWidths=[7 * cm, 4 * cm, W - 11 * cm])
    cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), C_BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]
    for i, risk in enumerate(sev_col):
        rc = SEV_COLORS.get(risk, PRIORITY_COLORS.get(risk, C_GRAY))
        cmds.append(("BACKGROUND", (2, i + 1), (2, i + 1), colors.Color(rc.red, rc.green, rc.blue, alpha=0.25)))
        cmds.append(("TEXTCOLOR", (2, i + 1), (2, i + 1), rc))
        cmds.append(("FONTNAME", (2, i + 1), (2, i + 1), "Helvetica-Bold"))
    s_tbl.setStyle(TableStyle(cmds))
    elems.append(s_tbl)
    elems.append(Spacer(1, 0.5 * cm))

    # Key findings paragraph
    findings = []
    if weaponized:
        findings.append(f"<b>{weaponized} WEAPONIZED exploit(s)</b> detected — immediate action required.")
    if by_sev["CRITICAL"]:
        findings.append(f"{by_sev['CRITICAL']} CRITICAL CVE(s) require emergency patching.")
    if ag and ag.network_risk_level in ("CRITICAL", "HIGH"):
        findings.append(f"Network risk level is <b>{ag.network_risk_level}</b> — {ag.path_count} attack path(s) identified.")
    if immediate_patch:
        findings.append(f"{immediate_patch} remediation action(s) classified as IMMEDIATE priority.")
    if not findings:
        findings.append("No critical findings detected. Continue monitoring and apply scheduled patches.")

    for f in findings:
        elems.append(_body(f"• {f}"))
    elems.append(PageBreak())

    # ── SECTION 2: NETWORK OVERVIEW ───────────────────────────────────────────
    elems.append(_h1("2. Network Overview"))
    elems.append(_divider())

    os_dist = _os_distribution(hosts)
    if os_dist:
        elems.append(_h3("Operating System Distribution"))
        os_rows = [["OS / Platform", "Count"]] + [[k, str(v)] for k, v in os_dist.items()]
        os_tbl = Table(os_rows, colWidths=[W * 0.75, W * 0.25])
        os_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), C_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_ROW_ALT]),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        elems.append(os_tbl)
        elems.append(Spacer(1, 0.5 * cm))

    # ── SECTION 3: HOST INVENTORY ─────────────────────────────────────────────
    elems.append(_h1("3. Host Inventory"))
    elems.append(_divider())

    host_rows = [["IP Address", "Hostname", "OS", "Open Ports", "CVEs", "Max Severity"]]
    host_sevs = []
    for h in hosts:
        sev = h.max_severity()
        host_rows.append([
            h.ip or "",
            (h.hostname or "—")[:22],
            (h.os or "Unknown")[:25],
            str(h.open_ports_count),
            str(h.vuln_count),
            sev or "—",
        ])
        host_sevs.append(sev or "")
    h_tbl = Table(host_rows, colWidths=[3.5*cm, 4*cm, 4.5*cm, 2.5*cm, 1.5*cm, 3*cm])
    cmds2 = [
        ("BACKGROUND", (0, 0), (-1, 0), C_BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    for i, sev in enumerate(host_sevs):
        rc = SEV_COLORS.get(sev, C_GRAY)
        cmds2.append(("BACKGROUND", (5, i+1), (5, i+1), colors.Color(rc.red, rc.green, rc.blue, alpha=0.2)))
        cmds2.append(("TEXTCOLOR", (5, i+1), (5, i+1), rc))
        if i % 2 == 0:
            cmds2.append(("BACKGROUND", (0, i+1), (4, i+1), C_ROW_ALT))
    h_tbl.setStyle(TableStyle(cmds2))
    elems.append(h_tbl)
    elems.append(PageBreak())

    # ── SECTION 4: OPEN PORTS & SERVICES ─────────────────────────────────────
    elems.append(_h1("4. Open Ports & Services"))
    elems.append(_divider())

    port_rows = [["Host IP", "Port", "Protocol", "State", "Service", "Version"]]
    for h in hosts:
        open_ports = [p for p in (h.ports or []) if p.get("state") == "open"]
        for p in open_ports[:20]:
            port_rows.append([
                h.ip or "",
                str(p.get("port", "")),
                p.get("protocol", "tcp"),
                p.get("state", ""),
                (p.get("service") or p.get("name") or "—")[:18],
                (p.get("version") or "—")[:25],
            ])
    p_tbl = Table(port_rows, colWidths=[3*cm, 2*cm, 2.5*cm, 2*cm, 3.5*cm, W-13*cm], repeatRows=1)
    p_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), C_BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_ROW_ALT]),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    elems.append(p_tbl)
    elems.append(PageBreak())

    # ── SECTION 5: VULNERABILITY SUMMARY ──────────────────────────────────────
    elems.append(_h1("5. Vulnerability Summary"))
    elems.append(_divider())

    # Severity distribution bar
    sev_summary = [["Severity", "Count", "Percentage"]]
    total_v = max(len(all_vulns), 1)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        cnt = by_sev[sev]
        sev_summary.append([sev, str(cnt), f"{cnt*100//total_v}%"])
    sv_tbl = Table(sev_summary, colWidths=[4*cm, 3*cm, W-7*cm])
    sev_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), C_BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]
    for i, sev in enumerate(("CRITICAL", "HIGH", "MEDIUM", "LOW")):
        rc = SEV_COLORS[sev]
        sev_cmds.append(("BACKGROUND", (0, i+1), (0, i+1), colors.Color(rc.red, rc.green, rc.blue, alpha=0.25)))
        sev_cmds.append(("TEXTCOLOR", (0, i+1), (0, i+1), rc))
        sev_cmds.append(("FONTNAME", (0, i+1), (0, i+1), "Helvetica-Bold"))
    sv_tbl.setStyle(TableStyle(sev_cmds))
    elems.append(sv_tbl)
    elems.append(Spacer(1, 0.5 * cm))

    # ── SECTION 6: CRITICAL CVEs ───────────────────────────────────────────────
    elems.append(_h1("6. Critical CVE Details"))
    elems.append(_divider())

    crit_vulns = [v for v in all_vulns if v.severity in ("CRITICAL", "HIGH")][:25]
    if crit_vulns:
        vuln_rows = [["CVE ID", "Severity", "CVSS", "Service", "Port", "Host IP"]]
        vuln_sevs = []
        for v in crit_vulns:
            host_ip = next((h.ip for h in hosts if h.id == v.host_id), "—")
            vuln_rows.append([
                v.cve_id or "—",
                v.severity or "—",
                str(v.cvss or "—"),
                (v.affected_service or "—")[:20],
                v.affected_port or "—",
                host_ip,
            ])
            vuln_sevs.append(v.severity or "")
        v_tbl = Table(vuln_rows, colWidths=[3.5*cm, 2.5*cm, 1.8*cm, 4*cm, 1.8*cm, W-13.6*cm], repeatRows=1)
        vc = [
            ("BACKGROUND", (0, 0), (-1, 0), C_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]
        for i, sev in enumerate(vuln_sevs):
            rc = SEV_COLORS.get(sev, C_GRAY)
            vc.append(("BACKGROUND", (1, i+1), (1, i+1), colors.Color(rc.red, rc.green, rc.blue, alpha=0.25)))
            vc.append(("TEXTCOLOR", (1, i+1), (1, i+1), rc))
            vc.append(("FONTNAME", (1, i+1), (1, i+1), "Helvetica-Bold"))
            if i % 2 == 0:
                vc.append(("BACKGROUND", (0, i+1), (0, i+1), C_ROW_ALT))
        v_tbl.setStyle(TableStyle(vc))
        elems.append(v_tbl)
    else:
        elems.append(_body("No critical or high severity CVEs found."))
    elems.append(PageBreak())

    # ── SECTION 7: ATTACK PATH ANALYSIS ───────────────────────────────────────
    elems.append(_h1("7. Attack Path Analysis"))
    elems.append(_divider())

    if ag:
        elems.append(_body(f"Network Risk Level: <b>{ag.network_risk_level}</b>"))
        elems.append(_body(f"Graph: {ag.node_count} nodes · {ag.edge_count} edges · {ag.path_count} paths"))
        elems.append(Spacer(1, 0.3 * cm))

    if attack_paths:
        path_rows = [["#", "Entry Point", "Target", "Hops", "Score", "Severity"]]
        path_sevs = []
        for i, p in enumerate(attack_paths[:10]):
            path_rows.append([
                str(i + 1),
                p.entry_ip or "—",
                p.target_ip or "—",
                str(p.hop_count),
                f"{p.total_score:.1f}",
                p.severity or "—",
            ])
            path_sevs.append(p.severity or "")
        pt_tbl = Table(path_rows, colWidths=[1*cm, 4*cm, 4*cm, 2*cm, 2.5*cm, W-13.5*cm])
        ptc = [
            ("BACKGROUND", (0, 0), (-1, 0), C_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]
        for i, sev in enumerate(path_sevs):
            rc = SEV_COLORS.get(sev, C_GRAY)
            ptc.append(("BACKGROUND", (5, i+1), (5, i+1), colors.Color(rc.red, rc.green, rc.blue, alpha=0.25)))
            ptc.append(("TEXTCOLOR", (5, i+1), (5, i+1), rc))
            ptc.append(("FONTNAME", (5, i+1), (5, i+1), "Helvetica-Bold"))
        pt_tbl.setStyle(TableStyle(ptc))
        elems.append(pt_tbl)
    else:
        elems.append(_body("No attack paths detected for this scan."))
    elems.append(PageBreak())

    # ── SECTION 8: EXPLOITABILITY ASSESSMENT ──────────────────────────────────
    elems.append(_h1("8. Exploitability Assessment"))
    elems.append(_divider())

    if assessments:
        # Maturity distribution
        mat_counts = {}
        for a in assessments:
            mat_counts[a.exploit_maturity] = mat_counts.get(a.exploit_maturity, 0) + 1
        mat_rows = [["Exploit Maturity", "Count"]]
        for m in ("WEAPONIZED", "FUNCTIONAL", "POC", "THEORETICAL", "UNPROVEN"):
            if mat_counts.get(m, 0) > 0:
                mat_rows.append([m, str(mat_counts[m])])
        mat_tbl = Table(mat_rows, colWidths=[5*cm, 3*cm])
        mc = [
            ("BACKGROUND", (0, 0), (-1, 0), C_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]
        for i, m in enumerate([r[0] for r in mat_rows[1:]]):
            rc = MATURITY_COLORS.get(m, C_GRAY)
            mc.append(("BACKGROUND", (0, i+1), (0, i+1), colors.Color(rc.red, rc.green, rc.blue, alpha=0.2)))
            mc.append(("TEXTCOLOR", (0, i+1), (0, i+1), rc))
            mc.append(("FONTNAME", (0, i+1), (0, i+1), "Helvetica-Bold"))
        mat_tbl.setStyle(TableStyle(mc))
        elems.append(mat_tbl)
        elems.append(Spacer(1, 0.5 * cm))

        # Top dangerous
        elems.append(_h3("Top 10 Most Dangerous Vulnerabilities"))
        top10 = sorted(assessments, key=lambda a: a.exploitability_score, reverse=True)[:10]
        t10_rows = [["CVE ID", "Maturity", "Score", "Attack Type", "Lateral Mvmt", "Host"]]
        t10_mat = []
        for a in top10:
            host_ip = next((h.ip for h in hosts if h.id == a.host_id), "—")
            t10_rows.append([
                a.cve_id or "—",
                a.exploit_maturity or "—",
                f"{a.exploitability_score:.1f}",
                a.attack_type or "—",
                a.lateral_movement_potential or "—",
                host_ip,
            ])
            t10_mat.append(a.exploit_maturity or "")
        t10_tbl = Table(t10_rows, colWidths=[3.5*cm, 3*cm, 2*cm, 3*cm, 3*cm, W-14.5*cm], repeatRows=1)
        t10c = [
            ("BACKGROUND", (0, 0), (-1, 0), C_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]
        for i, mat in enumerate(t10_mat):
            rc = MATURITY_COLORS.get(mat, C_GRAY)
            t10c.append(("BACKGROUND", (1, i+1), (1, i+1), colors.Color(rc.red, rc.green, rc.blue, alpha=0.2)))
            t10c.append(("TEXTCOLOR", (1, i+1), (1, i+1), rc))
            t10c.append(("FONTNAME", (1, i+1), (1, i+1), "Helvetica-Bold"))
        t10_tbl.setStyle(TableStyle(t10c))
        elems.append(t10_tbl)
    else:
        elems.append(_body("No exploitability assessments available for this scan."))
    elems.append(PageBreak())

    # ── SECTION 9: RISK CLASSIFICATION ────────────────────────────────────────
    elems.append(_h1("9. Risk Classification"))
    elems.append(_divider())

    # Per-host risk table
    host_risk_rows = [["Host IP", "Hostname", "CVEs", "Max Severity", "Weaponized", "Patch Priority"]]
    for h in hosts:
        h_assessments = [a for a in assessments if a.host_id == h.id]
        h_weaponized = sum(1 for a in h_assessments if a.exploit_maturity == "WEAPONIZED")
        h_immediate = sum(1 for a in h_assessments if a.patch_priority == "IMMEDIATE")
        host_risk_rows.append([
            h.ip or "—",
            (h.hostname or "—")[:20],
            str(h.vuln_count),
            h.max_severity() or "—",
            str(h_weaponized),
            "IMMEDIATE" if h_immediate > 0 else ("URGENT" if h_assessments else "MONITOR"),
        ])
    hr_tbl = Table(host_risk_rows, colWidths=[3*cm, 4*cm, 2*cm, 3*cm, 3*cm, W-15*cm], repeatRows=1)
    hr_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), C_BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_ROW_ALT]),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    elems.append(hr_tbl)
    elems.append(PageBreak())

    # ── SECTION 10: REMEDIATION PLAN ──────────────────────────────────────────
    elems.append(_h1("10. Remediation Plan"))
    elems.append(_divider())

    priority_order = {"IMMEDIATE": 0, "CRITICAL": 0, "URGENT": 1, "HIGH": 1, "SCHEDULED": 2, "MEDIUM": 2, "MONITOR": 3, "LOW": 3}
    sorted_rem = sorted(remediation_items, key=lambda r: priority_order.get(r.priority or "", 9))

    if sorted_rem:
        rem_rows = [["Priority", "Title", "Category", "Effort", "Host"]]
        rem_pris = []
        for r in sorted_rem[:30]:
            host_ip = next((h.ip for h in hosts if h.id == r.host_id), "—")
            rem_rows.append([
                r.priority or "—",
                (r.title or "—")[:40],
                r.category or "—",
                r.effort or "—",
                host_ip,
            ])
            rem_pris.append(r.priority or "")
        r_tbl = Table(rem_rows, colWidths=[2.5*cm, 7*cm, 2.5*cm, 2*cm, W-14*cm], repeatRows=1)
        rc2 = [
            ("BACKGROUND", (0, 0), (-1, 0), C_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]
        for i, pri in enumerate(rem_pris):
            pc = PRIORITY_COLORS.get(pri, C_GRAY)
            rc2.append(("BACKGROUND", (0, i+1), (0, i+1), colors.Color(pc.red, pc.green, pc.blue, alpha=0.25)))
            rc2.append(("TEXTCOLOR", (0, i+1), (0, i+1), pc))
            rc2.append(("FONTNAME", (0, i+1), (0, i+1), "Helvetica-Bold"))
            if i % 2 == 1:
                rc2.append(("BACKGROUND", (1, i+1), (-1, i+1), C_ROW_ALT))
        r_tbl.setStyle(TableStyle(rc2))
        elems.append(r_tbl)

        # Detailed steps for top 5 IMMEDIATE items
        immediate_items = [r for r in sorted_rem if r.priority in ("IMMEDIATE", "CRITICAL")][:5]
        if immediate_items:
            elems.append(Spacer(1, 0.5 * cm))
            elems.append(_h3("Immediate Action Details"))
            for r in immediate_items:
                # title/description/steps contain scanned data (IPs, service
                # banners): escape it so ReportLab does not parse it as markup
                elems.append(_body(f"<b>{escape(r.title)}</b> — {escape(r.description or '')}"))
                try:
                    steps = json.loads(r.steps_json or "[]")
                    for s in steps[:5]:
                        elems.append(_body(f"  • {escape(str(s))}"))
                except Exception:
                    pass
                elems.append(Spacer(1, 0.2 * cm))
    else:
        elems.append(_body("No remediation items generated for this scan."))
    elems.append(PageBreak())

    # ── SECTION 11: FINAL RISK SCORE ──────────────────────────────────────────
    elems.append(_h1("11. Final Security Score"))
    elems.append(_divider())

    score_breakdown = [
        ["Component", "Deduction", "Detail"],
        ["Base Score", "100", "Starting security score"],
        ["Vulnerabilities", f"−{vuln_penalty}", f"{len(all_vulns)} CVE(s) × 2 pts each (max 50)"],
        ["Exploitable CVEs", f"−{exploit_penalty}", f"{weaponized + functional} weaponized/functional × 5 pts (max 30)"],
        ["Critical Attack Paths", f"−{path_penalty}", f"Critical/high paths × 4 pts (max 20)"],
        ["Final Score", str(security_score), score_label],
    ]
    sb_tbl = Table(score_breakdown, colWidths=[5*cm, 3*cm, W-8*cm])
    sbc = [
        ("BACKGROUND", (0, 0), (-1, 0), C_BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_ROW_ALT]),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("BACKGROUND", (0, 5), (-1, 5), _score_color(security_score)),
        ("TEXTCOLOR", (0, 5), (-1, 5), colors.white),
        ("FONTNAME", (0, 5), (-1, 5), "Helvetica-Bold"),
    ]
    sb_tbl.setStyle(TableStyle(sbc))
    elems.append(sb_tbl)
    elems.append(Spacer(1, 1 * cm))

    # Recommendation
    if security_score >= 80:
        rec = "Network security posture is GOOD. Maintain regular scanning cadence and apply scheduled patches."
    elif security_score >= 60:
        rec = "Security posture is MODERATE. Address high-severity CVEs and harden exposed services within 30 days."
    elif security_score >= 40:
        rec = "Security posture is AT RISK. Immediate patching of critical CVEs and network segmentation required."
    else:
        rec = "Security posture is CRITICAL. Emergency response required — weaponized exploits and/or critical attack paths exist."
    elems.append(_body(f"<b>Recommendation:</b> {rec}"))
    elems.append(Spacer(1, 1 * cm))

    footer_style = ParagraphStyle("foot", parent=styles["Normal"], fontSize=8,
                                  textColor=C_GRAY, alignment=TA_CENTER)
    elems.append(Paragraph(
        f"Generated by ViperV2 v2.0.0 · {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} · "
        "This report is for authorized security assessment purposes only.",
        footer_style,
    ))

    doc.build(elems)
    return buf.getvalue()


def _os_distribution(hosts: list) -> dict:
    dist: dict = {}
    for h in hosts:
        key = h.os or "Unknown"
        dist[key] = dist.get(key, 0) + 1
    return dist
