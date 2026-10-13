import io
import json
from xml.sax.saxutils import escape
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.scan import ScanSession, Host
from app.core.timeutil import utcnow, iso_utc

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
            "generated_at": iso_utc(utcnow()),
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
    filename = f"viperv2_scan_{scan_id[:8]}_{utcnow().strftime('%Y%m%d')}.json"

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

    filename = f"viperv2_report_{scan_id[:8]}_{utcnow().strftime('%Y%m%d')}.pdf"
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
        SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable, PageBreak,
    )
    from reportlab.lib.units import cm
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

    from app.vulnerability_scanner.models import Vulnerability
    from app.exploitability.models import ExploitabilityAssessment, RemediationItem
    from app.attack_graph.models import AttackGraph, AttackPath
    from app.prioritization.engine import prioritize_scan
    from app.scanners.host_role import classify_host, ROLE_LABELS

    # ── Load data ────────────────────────────────────────────────────────────
    hosts = db.query(Host).filter(Host.scan_id == scan_id).all()
    host_by_id = {h.id: h for h in hosts}
    all_vulns = db.query(Vulnerability).filter(
        Vulnerability.host_id.in_([h.id for h in hosts])).all() if hosts else []
    assessments = db.query(ExploitabilityAssessment).filter(
        ExploitabilityAssessment.scan_id == scan_id).all()
    assess_by_vuln = {a.vuln_id: a for a in assessments}
    remediation_items = db.query(RemediationItem).filter(
        RemediationItem.scan_id == scan_id).all()
    ag = db.query(AttackGraph).filter(AttackGraph.scan_id == scan_id).first()
    attack_paths = (db.query(AttackPath).filter(AttackPath.graph_id == ag.id)
                    .order_by(AttackPath.total_score.desc()).limit(10).all() if ag else [])
    findings = prioritize_scan(scan_id, db)   # evidence-based ranking (Phase 5)

    # ── Key figures ──────────────────────────────────────────────────────────
    by_sev = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for v in all_vulns:
        if v.severity in by_sev:
            by_sev[v.severity] += 1
    confirmed = sum(1 for v in all_vulns if (v.match_type or "cpe") == "cpe")
    weak = len(all_vulns) - confirmed
    kev_count = sum(1 for v in all_vulns if v.kev)
    weaponized = sum(1 for a in assessments if a.exploit_maturity == "WEAPONIZED")
    functional = sum(1 for a in assessments if a.exploit_maturity == "FUNCTIONAL")
    immediate = sum(1 for a in assessments if a.patch_priority == "IMMEDIATE")

    # Risk posture from real evidence
    if kev_count or weaponized or (ag and ag.network_risk_level == "CRITICAL"):
        posture, p_color_key = "CRITICAL", "CRITICAL"
    elif functional or by_sev["CRITICAL"] or (ag and ag.network_risk_level == "HIGH"):
        posture, p_color_key = "ELEVATED", "HIGH"
    elif by_sev["HIGH"] or all_vulns:
        posture, p_color_key = "MODERATE", "MEDIUM"
    else:
        posture, p_color_key = "LOW", "LOW"

    # ── Palette (VIPER identity: crimson accent, light report body) ──────────
    C_INK     = colors.HexColor("#1a1420")
    C_ACCENT  = colors.HexColor("#e4324f")   # VIPER crimson
    C_ACCENT2 = colors.HexColor("#b3122b")
    C_RED     = colors.HexColor("#e4324f")
    C_ORANGE  = colors.HexColor("#ea7a45")
    C_YELLOW  = colors.HexColor("#cfa22c")
    C_GREEN   = colors.HexColor("#3fbf6a")
    C_GRAY    = colors.HexColor("#6b6572")
    C_BORDER  = colors.HexColor("#e4e0e6")
    C_ROW_ALT = colors.HexColor("#faf7f9")
    C_SOFT    = colors.HexColor("#fcecef")   # soft crimson wash
    SEV_COLORS = {"CRITICAL": C_RED, "HIGH": C_ORANGE, "MEDIUM": C_YELLOW, "LOW": C_GREEN}
    MAT_COLORS = {"WEAPONIZED": C_RED, "FUNCTIONAL": C_ORANGE, "POC": C_YELLOW,
                  "UNKNOWN": C_GRAY, "THEORETICAL": C_GRAY, "UNPROVEN": C_GRAY}

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=1.6 * cm, bottomMargin=1.6 * cm,
                            leftMargin=2 * cm, rightMargin=2 * cm,
                            title=f"VIPER Security Assessment - {scan.target or scan_id[:8]}",
                            author="VIPER")
    styles = getSampleStyleSheet()
    W = A4[0] - 4 * cm

    def _style(name, **kw):
        return ParagraphStyle(name, parent=styles["Normal"], **kw)

    H1 = _style("h1", fontSize=16, leading=19, textColor=C_ACCENT, spaceBefore=4,
                spaceAfter=4, fontName="Helvetica-Bold")
    H2 = _style("h2", fontSize=11.5, leading=14, textColor=C_INK, spaceBefore=10,
                spaceAfter=3, fontName="Helvetica-Bold")
    BODY = _style("body", fontSize=9.3, leading=13.5, textColor=C_INK, spaceAfter=4,
                  alignment=TA_JUSTIFY)
    SMALL = _style("small", fontSize=8, leading=10.5, textColor=C_GRAY)
    NOTE = _style("note", fontSize=8, leading=11, textColor=C_GRAY, alignment=TA_JUSTIFY,
                  leftIndent=6, borderPadding=0)

    def h1(n, t):
        return Paragraph(f"{n}. &nbsp;{escape(t)}", H1)

    def body(t):
        return Paragraph(t, BODY)

    def note(t):
        return Paragraph(f"<i>Note — {t}</i>", NOTE)

    def divider():
        return HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceAfter=7, spaceBefore=1)

    def cell(t, bold=False, size=7.6, color=C_INK, align=TA_LEFT):
        st = _style("c", fontSize=size, leading=size + 2.5, textColor=color, alignment=align,
                    fontName="Helvetica-Bold" if bold else "Helvetica")
        return Paragraph(escape(str(t)) if not bold else f"<b>{escape(str(t))}</b>", st)

    def table(data, widths, header_bg=C_INK):
        t = Table(data, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), header_bg),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, C_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_ROW_ALT]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]))
        return t

    def badge(text, color):
        return Paragraph(f'<font color="#{color.hexval()[2:]}"><b>{escape(str(text))}</b></font>',
                         _style("b", fontSize=7.6, leading=10))

    elems = []
    today = utcnow().strftime("%d %B %Y")

    # ══ COVER PAGE ═══════════════════════════════════════════════════════════
    elems.append(Spacer(1, 2.2 * cm))
    elems.append(Paragraph("VIPER", _style("brand", fontSize=46, textColor=C_ACCENT,
                 alignment=TA_CENTER, fontName="Helvetica-Bold", leading=48)))
    elems.append(Paragraph("RISK ANALYSIS", _style("brandsub", fontSize=12, textColor=C_GRAY,
                 alignment=TA_CENTER, leading=20)))
    elems.append(Spacer(1, 0.8 * cm))
    elems.append(Paragraph("Network Security Assessment Report", _style("ctitle", fontSize=19,
                 textColor=C_INK, alignment=TA_CENTER, fontName="Helvetica-Bold")))
    elems.append(Spacer(1, 1.4 * cm))

    posture_tbl = Table([[f"RISK POSTURE:  {posture}"]], colWidths=[W])
    posture_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SEV_COLORS.get(p_color_key, C_GRAY)),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 15), ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 12), ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    elems.append(posture_tbl)
    elems.append(Spacer(1, 1.2 * cm))

    meta = [
        ["Target / scope", escape(scan.target or "N/A")],
        ["Assessment type", f"{scan.type.upper()} scan"],
        ["Hosts in scope", str(len(hosts))],
        ["Scan status", (scan.status or "").upper()],
        ["Report date", today],
        ["Scan reference", scan.id[:18]],
    ]
    meta_tbl = Table(meta, colWidths=[5 * cm, W - 5 * cm])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), C_INK),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("GRID", (0, 0), (-1, -1), 0.4, C_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    elems.append(meta_tbl)
    elems.append(Spacer(1, 1.4 * cm))

    auth_p = Paragraph(
        "<b>AUTHORIZED USE ONLY</b> — This report documents a security assessment conducted with "
        "explicit authorisation on the scope above. It is confidential and intended solely for the "
        "asset owner and authorised personnel.",
        _style("auth", fontSize=8.8, leading=13, textColor=C_ACCENT2, alignment=TA_CENTER,
               fontName="Helvetica-Bold"))
    auth = Table([[auth_p]], colWidths=[W])
    auth.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_SOFT),
        ("BOX", (0, 0), (-1, -1), 1, C_ACCENT),
        ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 14), ("RIGHTPADDING", (0, 0), (-1, -1), 14),
    ]))
    elems.append(auth)
    elems.append(PageBreak())

    # ══ 1. EXECUTIVE SUMMARY ════════════════════════════════════════════════
    elems.append(h1("1", "Executive summary"))
    elems.append(divider())

    top = findings[0] if findings else None
    posture_sentence = {
        "CRITICAL": "requires immediate attention",
        "ELEVATED": "is elevated and should be addressed promptly",
        "MODERATE": "is moderate",
        "LOW": "is low",
    }[posture]
    s1 = (f"This assessment of <b>{escape(scan.target or 'the target')}</b> covered "
          f"<b>{len(hosts)}</b> host(s) and identified <b>{len(all_vulns)}</b> potential "
          f"vulnerabilities, of which <b>{confirmed}</b> are confirmed against the detected "
          f"product and version (CPE) and <b>{weak}</b> are weaker keyword matches that should "
          f"be verified. The overall risk posture {posture_sentence}.")
    elems.append(body(s1))
    if kev_count or weaponized:
        s2 = (f"Critically, <b>{kev_count}</b> finding(s) correspond to vulnerabilities that are "
              f"<b>known to be exploited in the wild</b> (CISA KEV), and <b>{weaponized}</b> have a "
              f"weaponized public exploit. ")
    else:
        s2 = ("No findings are currently listed as exploited in the wild (CISA KEV), though this "
              "does not rule out risk. ")
    if top:
        s2 += (f"The highest-priority issue is <b>{escape(top['cve_id'])}</b> on "
               f"<b>{escape(top['host_ip'])}</b> ({escape(top.get('affected_service') or 'service')}), "
               f"ranked {top['score']:.0f}/100.")
    elems.append(body(s2))
    elems.append(Spacer(1, 0.3 * cm))

    # Key figures
    elems.append(Paragraph("Key figures", H2))
    kf = [
        [cell("Hosts in scope", bold=True), cell(len(hosts)),
         cell("Confirmed vulnerabilities (CPE)", bold=True), cell(confirmed)],
        [cell("Exploited in the wild (KEV)", bold=True), cell(kev_count),
         cell("Weaponized / functional exploits", bold=True), cell(f"{weaponized} / {functional}")],
        [cell("Critical / high severity", bold=True), cell(f"{by_sev['CRITICAL']} / {by_sev['HIGH']}"),
         cell("Attack paths identified", bold=True), cell(ag.path_count if ag else 0)],
    ]
    kf_tbl = Table(kf, colWidths=[W * 0.3, W * 0.2, W * 0.3, W * 0.2])
    kf_tbl.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, C_BORDER),
        ("BACKGROUND", (0, 0), (0, -1), C_ROW_ALT), ("BACKGROUND", (2, 0), (2, -1), C_ROW_ALT),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elems.append(kf_tbl)
    elems.append(Spacer(1, 0.3 * cm))

    # Top 3 priority actions
    elems.append(Paragraph("Top priority actions", H2))
    def _remediate(f):
        svc = escape(f.get("affected_service") or "the affected service")
        port = f.get("affected_port")
        tail = f" (or restrict network access to {escape(port)})" if port else ""
        return f"upgrade {svc} to a fixed release{tail}"
    actions = []
    for f in findings[:3]:
        host = host_by_id.get(f["host_id"])
        fix = _remediate(f)
        actions.append(f"<b>{escape(f['cve_id'])}</b> on {escape(f['host_ip'])} "
                       f"({escape(f.get('affected_service') or 'service')}) — {fix}.")
    if not actions:
        actions = ["No material findings require action; maintain the regular scanning cadence."]
    for i, a in enumerate(actions, 1):
        elems.append(body(f"{i}. {a}"))
    elems.append(Spacer(1, 0.2 * cm))
    elems.append(note("prioritisation is a decision aid, not a verdict. Findings marked as a weak "
                      "keyword match may be false positives and must be verified before action; "
                      "KEV/EPSS describe a CVE's exploitation in the world, not that this host is "
                      "necessarily vulnerable."))
    elems.append(PageBreak())

    # ══ 2. METHODOLOGY ══════════════════════════════════════════════════════
    elems.append(h1("2", "Methodology"))
    elems.append(divider())
    elems.append(body(
        "Findings in this report are derived from real data collected during the assessment; "
        "no results are simulated. The approach was:"))
    for m in [
        "<b>Discovery &amp; service detection.</b> Live hosts and open ports were enumerated, and "
        "service names and versions identified with Nmap (<i>-sV</i>; OS detection <i>-O</i> where "
        "privileges allowed).",
        "<b>Vulnerability correlation (NVD).</b> Each service was correlated against the National "
        "Vulnerability Database. Where the product and version were known, CVEs were matched by "
        "<b>CPE</b> and marked <i>Confirmed</i>; otherwise a keyword search was used and the result "
        "flagged as a <i>weak match</i> (possible false positive).",
        "<b>Real-world exploitation signals.</b> Every CVE was enriched with the <b>CISA KEV</b> "
        "catalogue (exploited in the wild) and its <b>EPSS</b> score (exploitation probability).",
        "<b>Evidence-based exploitability.</b> Exploit maturity is derived from real evidence "
        "(KEV, public exploit references such as Exploit-DB / Metasploit, EPSS) — never guessed "
        "from CVSS. No exploitation was performed; the assessment is intelligence only.",
        "<b>Prioritisation &amp; attack paths.</b> Findings were ranked by a transparent score "
        "(exploitation evidence, EPSS, CVSS, match confidence, exposure, lateral movement). Attack "
        "paths were modelled from this evidence as a heuristic graph.",
    ]:
        elems.append(body(f"&bull;&nbsp; {m}"))
    elems.append(note("the attack-path model is a heuristic, evidence-based ranking — not a formal "
                      "attack graph (e.g. MulVAL); it does not prove reachability or chain exploit "
                      "preconditions. Host roles are inferred from observed services, not certified."))
    elems.append(PageBreak())

    # ══ 3. PRIORITISED FINDINGS ═════════════════════════════════════════════
    elems.append(h1("3", "Prioritised findings"))
    elems.append(divider())
    if findings:
        elems.append(body(
            "Findings are ordered by the evidence-based priority score. <b>Match</b> shows whether "
            "the CVE was confirmed by CPE or is a weaker keyword match; <b>KEV</b> marks "
            "exploitation in the wild; <b>EPSS</b> is the exploitation probability."))
        rows = [[cell("#", bold=True, color=colors.white), cell("CVE", bold=True, color=colors.white),
                 cell("Host · Service", bold=True, color=colors.white), cell("Sev", bold=True, color=colors.white),
                 cell("Match", bold=True, color=colors.white), cell("KEV", bold=True, color=colors.white),
                 cell("EPSS", bold=True, color=colors.white), cell("Maturity", bold=True, color=colors.white),
                 cell("Score", bold=True, color=colors.white)]]
        for f in findings[:28]:
            sev = (f.get("severity") or "").upper()
            rows.append([
                cell(f["rank"]), cell(f["cve_id"]),
                cell(f"{f['host_ip']} · {(f.get('affected_service') or '')[:26]}"),
                badge(sev or "-", SEV_COLORS.get(sev, C_GRAY)),
                cell("Confirmed" if f["confirmed"] else "Weak", color=(C_GREEN if f["confirmed"] else C_ORANGE)),
                cell("Yes" if f["kev"] else "-", color=(C_RED if f["kev"] else C_GRAY)),
                cell(f"{f['epss'] * 100:.0f}%" if f.get("epss") is not None else "-"),
                badge(f.get("maturity") or "UNKNOWN", MAT_COLORS.get(f.get("maturity"), C_GRAY)),
                cell(f"{f['score']:.0f}", bold=True),
            ])
        elems.append(table(rows, [0.8 * cm, 2.7 * cm, W - 13.6 * cm, 2.0 * cm, 1.6 * cm,
                                  1.0 * cm, 1.2 * cm, 2.5 * cm, 1.5 * cm]))
        elems.append(Spacer(1, 0.35 * cm))

        elems.append(Paragraph("Analyst notes on the highest-priority findings", H2))
        for f in findings[:8]:
            a = assess_by_vuln.get(f["vuln_id"])
            vuln = next((v for v in all_vulns if v.id == f["vuln_id"]), None)
            match_txt = ("confirmed by CPE against the detected version" if f["confirmed"]
                         else "a keyword-only match that should be verified (possible false positive)")
            ev = []
            if f["kev"]:
                ev.append("is listed in CISA KEV (exploited in the wild)")
            if f.get("epss") is not None:
                ev.append(f"has an EPSS exploitation probability of {f['epss'] * 100:.0f}%")
            if a and a.exploit_maturity and a.exploit_maturity != "UNKNOWN":
                ev.append(f"has {a.exploit_maturity.lower()} exploit evidence")
            ev_txt = ("It " + "; it ".join(ev) + ". ") if ev else "No public-exploit evidence was found. "
            fix = _remediate(f)
            desc = ""
            if vuln and vuln.description:
                desc = escape(vuln.description[:180].rsplit(" ", 1)[0]) + "… "
            elems.append(body(
                f"<b>{f['rank']}. {escape(f['cve_id'])}</b> — {escape(f.get('affected_service') or 'service')} "
                f"on {escape(f['host_ip'])} ({escape((f.get('severity') or '').title())}, "
                f"CVSS {f.get('cvss') if f.get('cvss') is not None else 'n/a'}, score {f['score']:.0f}/100). "
                f"{desc}This finding is {match_txt}. {ev_txt}"
                f"<b>Remediation:</b> {fix}."))
    else:
        elems.append(body("No vulnerabilities were correlated for this scan."))
    elems.append(PageBreak())

    # ══ 4. ATTACK PATHS ═════════════════════════════════════════════════════
    elems.append(h1("4", "Attack paths"))
    elems.append(divider())
    if attack_paths:
        elems.append(body(
            f"The attack-path model identified <b>{ag.path_count}</b> plausible path(s); the most "
            f"significant are listed below with their justification and MITRE ATT&amp;CK references."))
        rows = [[cell("#", bold=True, color=colors.white), cell("Score", bold=True, color=colors.white),
                 cell("Severity", bold=True, color=colors.white), cell("Justification", bold=True, color=colors.white)]]
        for i, p in enumerate(attack_paths[:6], 1):
            sev = (p.severity or "").upper()
            rows.append([cell(i, bold=True), cell(f"{p.total_score:.0f}", bold=True),
                         badge(sev or "-", SEV_COLORS.get(sev, C_GRAY)),
                         cell((p.justification or "").replace("→", "->"))])
        elems.append(table(rows, [0.9 * cm, 1.4 * cm, 2.0 * cm, W - 4.3 * cm]))
        elems.append(Spacer(1, 0.25 * cm))
        mitre = {}
        for p in attack_paths[:6]:
            for t in json.loads(p.mitre_json or "[]"):
                mitre[t["id"]] = t["name"]
        if mitre:
            tags = ", ".join(f"{k} ({escape(v)})" for k, v in sorted(mitre.items()))
            elems.append(body(f"<b>MITRE ATT&amp;CK techniques referenced:</b> {tags}."))
        elems.append(note("this is a heuristic, evidence-based model, not a formal attack graph "
                          "(MulVAL). Paths rank plausible routes from the real evidence for analyst "
                          "review; they do not prove reachability or chain exploit preconditions."))
    else:
        elems.append(body("No attack paths were generated for this scan."))
    elems.append(PageBreak())

    # ══ 5. TOPOLOGY & ROLES ═════════════════════════════════════════════════
    elems.append(h1("5", "Topology & host roles"))
    elems.append(divider())
    elems.append(body(
        "Each host is classified by the role its observed services suggest. A host may hold "
        "several roles; the table lists them in order of significance."))
    rows = [[cell("Host", bold=True, color=colors.white), cell("Inferred role(s)", bold=True, color=colors.white),
             cell("OS", bold=True, color=colors.white), cell("Open ports", bold=True, color=colors.white),
             cell("CVEs", bold=True, color=colors.white), cell("Max severity", bold=True, color=colors.white)]]
    for h in hosts:
        role = classify_host(h.ports or [])
        role_txt = ", ".join(ROLE_LABELS.get(r, r) for r in role["roles"])
        sev = h.max_severity() or "-"
        rows.append([cell(h.ip or "-"), cell(role_txt), cell((h.os or "Unknown")[:26]),
                     cell(h.open_ports_count), cell(h.vuln_count),
                     badge(sev, SEV_COLORS.get(sev, C_GRAY))])
    elems.append(table(rows, [3.0 * cm, W - 12.3 * cm, 4.0 * cm, 1.8 * cm, 1.2 * cm, 2.3 * cm]))
    elems.append(Spacer(1, 0.2 * cm))
    elems.append(note("roles are inferred from observed services, not certified — e.g. an open "
                      "port 53 does not prove an authoritative DNS server."))
    elems.append(PageBreak())

    # ══ 6. TECHNICAL APPENDIX ═══════════════════════════════════════════════
    elems.append(h1("6", "Technical appendix"))
    elems.append(divider())
    elems.append(Paragraph("A. Open ports &amp; services", H2))
    prows = [[cell("Host", bold=True, color=colors.white), cell("Port", bold=True, color=colors.white),
              cell("Proto", bold=True, color=colors.white), cell("Service", bold=True, color=colors.white),
              cell("Version", bold=True, color=colors.white)]]
    for h in hosts:
        for p in [p for p in (h.ports or []) if p.get("state") == "open"]:
            prows.append([cell(h.ip or "-"), cell(p.get("port", "")), cell(p.get("protocol", "tcp")),
                          cell((p.get("service") or "-")[:22]), cell((p.get("version") or "-")[:46])])
    if len(prows) > 1:
        elems.append(table(prows, [3.0 * cm, 1.4 * cm, 1.6 * cm, 3.4 * cm, W - 9.4 * cm]))
    else:
        elems.append(body("No open ports recorded."))
    elems.append(Spacer(1, 0.4 * cm))

    elems.append(Paragraph("B. All correlated CVEs", H2))
    if all_vulns:
        crows = [[cell("CVE", bold=True, color=colors.white), cell("Host", bold=True, color=colors.white),
                  cell("Service", bold=True, color=colors.white), cell("CVSS", bold=True, color=colors.white),
                  cell("Sev", bold=True, color=colors.white), cell("Match", bold=True, color=colors.white),
                  cell("KEV", bold=True, color=colors.white)]]
        for v in sorted(all_vulns, key=lambda x: -(x.cvss or 0)):
            host_ip = host_by_id.get(v.host_id).ip if host_by_id.get(v.host_id) else "-"
            sev = (v.severity or "-").upper()
            crows.append([cell(v.cve_id), cell(host_ip), cell((v.affected_service or "-")[:24]),
                          cell(v.cvss if v.cvss is not None else "-"),
                          badge(sev, SEV_COLORS.get(sev, C_GRAY)),
                          cell("CPE" if (v.match_type or "cpe") == "cpe" else "weak",
                               color=(C_GREEN if (v.match_type or "cpe") == "cpe" else C_ORANGE)),
                          cell("Y" if v.kev else "-", color=(C_RED if v.kev else C_GRAY))])
        elems.append(table(crows, [2.6 * cm, 2.6 * cm, W - 11.1 * cm, 1.4 * cm, 1.5 * cm, 1.6 * cm, 1.4 * cm]))
    else:
        elems.append(body("No CVEs were correlated."))

    # Footer
    elems.append(Spacer(1, 0.8 * cm))
    elems.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=4))
    elems.append(Paragraph(
        f"VIPER · Network Security Assessment · generated {utcnow().strftime('%Y-%m-%d %H:%M UTC')} · "
        "Authorized use only — confidential.",
        _style("foot", fontSize=7.5, textColor=C_GRAY, alignment=TA_CENTER)))

    doc.build(elems)
    return buf.getvalue()


def _os_distribution(hosts: list) -> dict:
    dist: dict = {}
    for h in hosts:
        key = h.os or "Unknown"
        dist[key] = dist.get(key, 0) + 1
    return dist
