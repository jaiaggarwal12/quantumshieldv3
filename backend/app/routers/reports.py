"""
QuantumShield — PDF Report Generator
Generates bank-grade PDF reports using reportlab.
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timezone
import io

router = APIRouter(prefix="/api/v1/reports", tags=["Reports"])


class ReportTarget(BaseModel):
    target: str
    pqc_score: int
    pqc_status: str
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    key_exchange: Optional[str] = None
    cert_key_type: Optional[str] = None
    cert_key_bits: Optional[int] = None
    forward_secrecy: Optional[bool] = None
    days_until_expiry: Optional[int] = None
    vulnerabilities: Optional[list] = []
    issues: Optional[list] = []
    positives: Optional[list] = []


class PDFReportRequest(BaseModel):
    scan_title: Optional[str] = "QuantumShield Security Assessment"
    organization: Optional[str] = "Organisation"
    prepared_by: Optional[str] = "QuantumShield Scanner"
    targets: List[ReportTarget] = []


def _status_color_rgb(status: str):
    colors_map = {
        "QUANTUM_SAFE":  (0, 0.6, 0.2),
        "PQC_READY":     (0.7, 0.8, 0.0),
        "TRANSITIONING": (0.9, 0.5, 0.0),
        "VULNERABLE":    (0.8, 0.1, 0.1),
    }
    return colors_map.get(status, (0.4, 0.4, 0.6))


@router.post("/pdf")
async def generate_pdf(req: PDFReportRequest):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm, cm
        from reportlab.lib import colors
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                        TableStyle, HRFlowable, PageBreak)
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    except ImportError:
        raise HTTPException(status_code=500, detail="reportlab not installed. Add reportlab to requirements.txt.")

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            rightMargin=2*cm, leftMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)

    PURPLE = colors.HexColor("#6A0DAD")
    DARK   = colors.HexColor("#1A1A2E")
    TEAL   = colors.HexColor("#0E6655")
    GRAY   = colors.HexColor("#555555")
    LGRAY  = colors.HexColor("#F5F5F5")
    RED    = colors.HexColor("#C0392B")

    h1_style = ParagraphStyle("QSH1", fontSize=14, textColor=PURPLE, fontName="Helvetica-Bold",
                               spaceAfter=6, spaceBefore=16)
    h2_style = ParagraphStyle("QSH2", fontSize=11, textColor=TEAL, fontName="Helvetica-Bold",
                               spaceAfter=4, spaceBefore=10)
    body_style = ParagraphStyle("QSBody", fontSize=9, textColor=DARK, fontName="Helvetica",
                                 spaceAfter=4, leading=14)

    story = []
    now = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")

    # Cover — clean single heading block
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph("QuantumShield",
        ParagraphStyle("Cov1", fontSize=32, textColor=PURPLE, fontName="Helvetica-Bold", spaceAfter=2)))
    story.append(Paragraph("Post-Quantum Cryptography Assessment Report",
        ParagraphStyle("Cov2", fontSize=13, textColor=DARK, fontName="Helvetica", spaceAfter=2)))
    story.append(Paragraph(req.scan_title,
        ParagraphStyle("Cov3", fontSize=10, textColor=GRAY, fontName="Helvetica-Oblique", spaceAfter=8)))
    story.append(HRFlowable(width="100%", thickness=2, color=PURPLE, spaceAfter=12))

    meta = [
        ["Organisation:",  req.organization],
        ["Prepared By:",   req.prepared_by],
        ["Generated:",     now],
        ["NIST Standards:","FIPS 203 (ML-KEM) · FIPS 204 (ML-DSA) · FIPS 205 (SLH-DSA)"],
        ["Assets Scanned:",str(len(req.targets))],
    ]
    mt = Table(meta, colWidths=[4*cm, 12*cm])
    mt.setStyle(TableStyle([
        ("FONTNAME",(0,0),(-1,-1),"Helvetica"),
        ("FONTSIZE",(0,0),(-1,-1),9),
        ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),
        ("TEXTCOLOR",(0,0),(0,-1),PURPLE),
        ("BOTTOMPADDING",(0,0),(-1,-1),4),
        ("TOPPADDING",(0,0),(-1,-1),4),
    ]))
    story.append(mt)
    story.append(Spacer(1, 0.5*cm))

    # Executive Summary
    story.append(Paragraph("EXECUTIVE SUMMARY", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=PURPLE, spaceAfter=8))

    total = len(req.targets)
    if total > 0:
        scores = [t.pqc_score for t in req.targets]
        avg_score = round(sum(scores) / total, 1)
        safe  = sum(1 for t in req.targets if t.pqc_status == "QUANTUM_SAFE")
        ready = sum(1 for t in req.targets if t.pqc_status == "PQC_READY")
        trans = sum(1 for t in req.targets if t.pqc_status == "TRANSITIONING")
        vuln  = sum(1 for t in req.targets if t.pqc_status == "VULNERABLE")
        total_vulns = sum(len(t.vulnerabilities or []) for t in req.targets)
        hndl_count  = sum(1 for t in req.targets if any(v.get("name")=="HNDL" for v in (t.vulnerabilities or [])))

        sd = [
            ["METRIC","VALUE","RISK IMPLICATION"],
            ["Total Assets Scanned",str(total),"Full cryptographic inventory completed"],
            ["Average PQC Score",f"{avg_score}/100","Below 65 = migration action needed"],
            ["Quantum Safe Assets",str(safe),"Deployed NIST PQC algorithms"],
            ["PQC Ready Assets",str(ready),"Certificate migration pending"],
            ["Transitioning Assets",str(trans),"Significant gaps — 3-month priority"],
            ["Vulnerable Assets",str(vuln),"Critical — immediate action required"],
            ["Total CVE Matches",str(total_vulns),"Known vulnerability cross-reference"],
            ["HNDL Exposed Assets",str(hndl_count),"Traffic recorded NOW for future decryption"],
        ]
        st = Table(sd, colWidths=[6*cm, 3*cm, 8*cm])
        st.setStyle(TableStyle([
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
            ("FONTNAME",(0,1),(-1,-1),"Helvetica"),
            ("FONTSIZE",(0,0),(-1,-1),8),
            ("BACKGROUND",(0,0),(-1,0),PURPLE),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,LGRAY]),
            ("GRID",(0,0),(-1,-1),0.5,colors.HexColor("#DDDDDD")),
            ("TOPPADDING",(0,0),(-1,-1),5),
            ("BOTTOMPADDING",(0,0),(-1,-1),5),
            ("LEFTPADDING",(0,0),(-1,-1),6),
        ]))
        story.append(st)
        story.append(Spacer(1, 0.4*cm))

        narrative = (
            f"CRITICAL RISK: Fleet average {avg_score}/100 — emergency action required."
            if avg_score < 40 else
            f"HIGH RISK: Fleet average {avg_score}/100 — structured 12-month PQC migration required."
            if avg_score < 65 else
            f"MODERATE RISK: Fleet average {avg_score}/100 — PQC migration required before 2030."
        )
        story.append(Paragraph(narrative, ParagraphStyle("Narr", fontSize=9, textColor=DARK,
            fontName="Helvetica-Bold", spaceAfter=8,
            borderPadding=8, borderColor=PURPLE, borderWidth=1)))

    # HNDL Warning
    story.append(Paragraph("HARVEST NOW DECRYPT LATER (HNDL) THREAT", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=RED, spaceAfter=8))
    story.append(Paragraph(
        "Nation-state adversaries are currently intercepting and archiving encrypted network traffic at scale. "
        "While RSA-2048 and ECDSA-256 are classically secure, adversaries are storing this data to decrypt "
        "retroactively once quantum computers arrive (estimated 2030-2035). Any data encrypted today with "
        "quantum-vulnerable algorithms that has sensitivity beyond 2030 is at risk.",
        ParagraphStyle("Warn", fontSize=9, textColor=DARK, fontName="Helvetica", leading=14,
            spaceAfter=8, borderPadding=8, borderColor=RED, borderWidth=1)))

    # Per-asset
    story.append(PageBreak())
    story.append(Paragraph("ASSET-BY-ASSET ANALYSIS", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=PURPLE, spaceAfter=8))

    for i, t in enumerate(req.targets):
        story.append(Paragraph(f"{i+1}. {t.target}", h2_style))
        ad = [
            ["PARAMETER","VALUE","QUANTUM RISK"],
            ["PQC Score",f"{t.pqc_score}/100",t.pqc_status.replace("_"," ")],
            ["TLS Version",t.tls_version or "—","TLS 1.3 required"],
            ["Cipher Suite",(t.cipher_suite or "—")[:40],"AES-256-GCM required"],
            ["Key Exchange",(t.key_exchange or "—")[:40],"ML-KEM-768 required"],
            ["Certificate",f"{t.cert_key_type or '?'}-{t.cert_key_bits or 0}","ML-DSA-65 required"],
            ["Forward Secrecy","Yes" if t.forward_secrecy else "No","Required to limit HNDL"],
            ["Cert Expires",f"{t.days_until_expiry or '?'} days","<30 days = CRITICAL"],
        ]
        tbl = Table(ad, colWidths=[5*cm, 5*cm, 7*cm])
        tbl.setStyle(TableStyle([
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
            ("FONTNAME",(0,1),(-1,-1),"Helvetica"),
            ("FONTSIZE",(0,0),(-1,-1),8),
            ("BACKGROUND",(0,0),(-1,0),DARK),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,LGRAY]),
            ("GRID",(0,0),(-1,-1),0.5,colors.HexColor("#DDDDDD")),
            ("TOPPADDING",(0,0),(-1,-1),4),
            ("BOTTOMPADDING",(0,0),(-1,-1),4),
            ("LEFTPADDING",(0,0),(-1,-1),5),
        ]))
        story.append(tbl)
        if t.vulnerabilities:
            story.append(Spacer(1, 0.1*cm))
            story.append(Paragraph("Vulnerabilities:",
                ParagraphStyle("VH",fontSize=8,fontName="Helvetica-Bold",textColor=RED,spaceAfter=2)))
            for v in t.vulnerabilities[:5]:
                story.append(Paragraph(
                    f"• {v.get('name','')} [{v.get('cve','N/A')}] {v.get('severity','')} — {v.get('description','')[:70]}",
                    ParagraphStyle("VI",fontSize=7,fontName="Helvetica",textColor=DARK,leftIndent=10,spaceAfter=1)))
        story.append(Spacer(1, 0.3*cm))
        story.append(HRFlowable(width="100%",thickness=0.5,color=colors.HexColor("#EEEEEE"),spaceAfter=6))

    # Roadmap
    story.append(PageBreak())
    story.append(Paragraph("NIST PQC MIGRATION ROADMAP", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=PURPLE, spaceAfter=8))
    phases = [
        ("Phase 1 — Immediate (0–3 months)","#C0392B",[
            "Disable TLS 1.0 and TLS 1.1 on all endpoints",
            "Replace RC4, 3DES, NULL ciphers with AES-256-GCM",
            "Enforce TLS 1.3 minimum organisation-wide",
            "Enable HSTS with max-age=31536000 on all domains",
            "Replace SHA-1 certificates with SHA-256",
        ]),
        ("Phase 2 — Short-term (3–12 months)","#D35400",[
            "Deploy hybrid key exchange: X25519 + ML-KEM-768 (FIPS 203)",
            "Initiate PKI migration to ML-DSA-65 (FIPS 204)",
            "Implement crypto-agility framework",
            "Add CAA DNS records, enable CT logging",
        ]),
        ("Phase 3 — Long-term (1–3 years)","#1E8449",[
            "Full certificate migration to ML-DSA-65 (FIPS 204)",
            "Deploy ML-KEM-1024 for highest-security endpoints",
            "Achieve NIST SP 800-208 compliance",
            "Annual PQC re-assessment with QuantumShield",
        ]),
    ]
    for title, chex, items in phases:
        story.append(Paragraph(title.upper(),
            ParagraphStyle("PH",fontSize=10,fontName="Helvetica-Bold",
                textColor=colors.HexColor(chex),spaceAfter=4,spaceBefore=8)))
        for item in items:
            story.append(Paragraph(f"   → {item}",
                ParagraphStyle("PI",fontSize=8,fontName="Helvetica",textColor=DARK,spaceAfter=3,leading=12)))
        story.append(Spacer(1, 0.15*cm))

    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=PURPLE, spaceAfter=6))
    story.append(Paragraph(
        f"Generated by QuantumShield v2.0 on {now}. NIST FIPS 203 · FIPS 204 · FIPS 205 · 40+ parameters per asset.",
        ParagraphStyle("Foot",fontSize=7,textColor=GRAY,fontName="Helvetica",
            alignment=TA_CENTER,leading=10)))

    doc.build(story)
    buf.seek(0)
    pdf_bytes = buf.read()
    filename = f"QuantumShield-{datetime.now().strftime('%Y%m%d-%H%M')}.pdf"
    return Response(content=pdf_bytes, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.get("/badge/{target}")
async def get_badge(target: str):
    return {"target": target, "badge": "PQC_READY", "generated": datetime.now(timezone.utc).isoformat()}


@router.get("/cbom")
async def get_cbom():
    return {"message": "Use POST /api/v1/scan/quick and export CBOM from results"}
