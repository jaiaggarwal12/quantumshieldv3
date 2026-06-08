"""
QuantumShield — API Scanner & VPN Probe Router

  - SSRF-guarded targets
  - Database-backed async jobs (poll-friendly, survive restarts/workers)
  - CSV / XML (CERT-In CBOM) export
"""

import asyncio
import csv
import io
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.core.net_guard import validate_target
from app.database import get_db, SessionLocal
from app.models.scan_job import ScanJob
from app.models.user import User
from app.routers.auth import get_current_user, require_auth, _client_ip
from app.services import audit_service as audit
from app.services.api_scanner import scan_api_endpoints, scan_vpn_endpoints

logger = get_logger("quantumshield.api_scanner")
router = APIRouter(prefix="/api/v1", tags=["API Scanner", "VPN", "Export"])

_executor = ThreadPoolExecutor(max_workers=4)


# ── Schemas ───────────────────────────────────────────────────────────────────
class APIScanRequest(BaseModel):
    base_url: str
    port: int = 443

class VPNScanRequest(BaseModel):
    hostname: str
    timeout: float = 2.5

class CSVExportRequest(BaseModel):
    results: list


# ── Job persistence helpers ───────────────────────────────────────────────────
def _create_job(db: Session, job_type: str, target: str, user_id: Optional[int]) -> str:
    job_id = str(uuid.uuid4())
    job = ScanJob(job_id=job_id, user_id=user_id, job_type=job_type, target=target, status="queued")
    db.add(job)
    db.commit()
    return job_id


def _run_scan_bg(job_id: str, kind: str, target: str, timeout: float):
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
        if not job:
            return
        job.status = "running"
        db.commit()
        if kind == "api":
            result = scan_api_endpoints(target, timeout=6)
        else:
            result = scan_vpn_endpoints(target, timeout=timeout)
        job.set_result(result)
        job.status = "done"
        db.commit()
    except Exception as e:
        logger.exception("%s scan job %s failed", kind, job_id)
        try:
            job = db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
            if job:
                job.status = "error"
                job.error = str(e)[:300]
                db.commit()
        except Exception:
            db.rollback()
    finally:
        db.close()


# ── API Scanner ────────────────────────────────────────────────────────────────
@router.post("/scan/api")
async def scan_api(request: APIScanRequest, req: Request,
                   current_user: User = Depends(require_auth), db: Session = Depends(get_db)):
    """Start an async API endpoint scan. Poll GET /scan/api/job/{job_id}."""
    base = request.base_url.strip()
    if not base:
        raise HTTPException(status_code=400, detail="base_url is required")
    host = base.replace("https://", "").replace("http://", "").split("/")[0].strip()
    ok, reason = validate_target(host, request.port)
    if not ok:
        audit.record(db, "scan.api.blocked", user_id=current_user.id, username=current_user.username,
                     ip=_client_ip(req), target=host, status="blocked", detail={"reason": reason})
        raise HTTPException(status_code=400, detail=reason)

    job_id = _create_job(db, "api", base, current_user.id)
    audit.record(db, "scan.api", user_id=current_user.id, username=current_user.username,
                 ip=_client_ip(req), target=host, detail={"job_id": job_id})
    asyncio.get_event_loop().run_in_executor(_executor, _run_scan_bg, job_id, "api", base, 6.0)
    return {"job_id": job_id, "status": "queued", "message": "Scan started — poll /scan/api/job/{job_id}"}


@router.get("/scan/api/job/{job_id}")
async def get_api_scan_job(job_id: str, current_user: User = Depends(require_auth), db: Session = Depends(get_db)):
    job = db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.user_id not in (None, current_user.id) and current_user.role != "Admin":
        raise HTTPException(status_code=403, detail="Access denied")
    return job.to_dict()


# ── VPN Probe ─────────────────────────────────────────────────────────────────
@router.post("/scan/vpn")
async def scan_vpn(request: VPNScanRequest, req: Request,
                   current_user: User = Depends(require_auth), db: Session = Depends(get_db)):
    """Start an async VPN port probe. Poll GET /scan/vpn/job/{job_id}."""
    hostname = request.hostname.replace("https://", "").replace("http://", "").split("/")[0].strip()
    if not hostname:
        raise HTTPException(status_code=400, detail="hostname is required")
    ok, reason = validate_target(hostname, 443)
    if not ok:
        audit.record(db, "scan.vpn.blocked", user_id=current_user.id, username=current_user.username,
                     ip=_client_ip(req), target=hostname, status="blocked", detail={"reason": reason})
        raise HTTPException(status_code=400, detail=reason)

    job_id = _create_job(db, "vpn", hostname, current_user.id)
    audit.record(db, "scan.vpn", user_id=current_user.id, username=current_user.username,
                 ip=_client_ip(req), target=hostname, detail={"job_id": job_id})
    asyncio.get_event_loop().run_in_executor(_executor, _run_scan_bg, job_id, "vpn", hostname, request.timeout)
    return {"job_id": job_id, "status": "queued", "message": "VPN probe started — poll /scan/vpn/job/{job_id}"}


@router.get("/scan/vpn/job/{job_id}")
async def get_vpn_scan_job(job_id: str, current_user: User = Depends(require_auth), db: Session = Depends(get_db)):
    job = db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.user_id not in (None, current_user.id) and current_user.role != "Admin":
        raise HTTPException(status_code=403, detail="Access denied")
    return job.to_dict()


# ── CSV Export ───────────────────────────────────────────────────────────────
@router.post("/export/csv")
async def export_csv(request: CSVExportRequest, current_user: User = Depends(require_auth)):
    """Export scan results as CSV."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Target","Port","Scan Status","TLS Version","Cipher Suite","Cipher Grade",
        "Forward Secrecy","Key Exchange","Cert Type","Cert Bits","Cert Expires (Days)",
        "Self Signed","CT Logs","PQC Score","PQC Status",
        "Vulnerabilities Count","Vulnerabilities","HSTS","DNS CAA","Timestamp"
    ])
    for r in request.results:
        tls   = r.get("tls_info", {})
        cert  = r.get("certificate", {})
        pqc   = r.get("pqc_assessment", {})
        dns   = r.get("dns", {})
        http  = r.get("http_headers", {})
        vulns = r.get("vulnerabilities", [])
        writer.writerow([
            r.get("target",""), r.get("port",443), r.get("status",""),
            tls.get("tls_version",""), tls.get("cipher_suite",""), tls.get("cipher_grade",""),
            "Yes" if tls.get("forward_secrecy") else "No",
            tls.get("key_exchange",""),
            cert.get("key_type",""), cert.get("key_bits",""), cert.get("days_until_expiry",""),
            "Yes" if cert.get("is_self_signed") else "No",
            cert.get("ct_sct_count",0),
            pqc.get("score",""), pqc.get("status",""),
            len(vulns), "|".join(v.get("name","") for v in vulns),
            "Yes" if http.get("hsts",{}).get("present") else "No",
            "Yes" if dns.get("caa_present") else "No",
            r.get("timestamp",""),
        ])
    output.seek(0)
    filename = f"QuantumShield-{datetime.now().strftime('%Y%m%d-%H%M')}.csv"
    return Response(content=output.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


# ── XML Export ────────────────────────────────────────────────────────────────
@router.post("/export/xml")
async def export_xml(request: CSVExportRequest, current_user: User = Depends(require_auth)):
    """Export scan results as CERT-In compliant XML."""
    ts  = datetime.now(timezone.utc).isoformat()
    esc = lambda s: str(s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<QuantumShieldReport generated="{ts}" schema="CERT-In-CBOM-v1.0" standard="NIST-FIPS-203-204-205">',
    ]
    for r in request.results:
        tls  = r.get("tls_info", {})
        cert = r.get("certificate", {})
        pqc  = r.get("pqc_assessment", {})
        vulns = r.get("vulnerabilities", [])
        lines += [
            f'  <Asset target="{esc(r.get("target"))}" port="{r.get("port",443)}" status="{esc(r.get("status"))}">',
            f'    <TLS version="{esc(tls.get("tls_version"))}" cipher="{esc(tls.get("cipher_suite"))}" grade="{esc(tls.get("cipher_grade"))}" forward_secrecy="{tls.get("forward_secrecy",False)}"/>',
            f'    <KeyExchange algorithm="{esc(tls.get("key_exchange"))}" quantum_safe="{"true" if "Safe" in (tls.get("key_exchange") or "") else "false"}"/>',
            f'    <Certificate type="{esc(cert.get("key_type"))}" bits="{cert.get("key_bits","")}" expires_days="{cert.get("days_until_expiry","")}" quantum_safe="{cert.get("pqc_cert",False)}" sig_algo="{esc(cert.get("signature_algorithm"))}"/>',
            f'    <PQCAssessment score="{pqc.get("score","")}" status="{esc(pqc.get("status"))}" label="{esc(pqc.get("label"))}">',
        ] + [
            f'      <Issue severity="{esc(i.get("severity"))}" description="{esc(i.get("issue"))}" action="{esc(i.get("action"))}"/>'
            for i in pqc.get("issues", [])[:6]
        ] + [
            f'    </PQCAssessment>',
            f'    <Vulnerabilities count="{len(vulns)}">',
        ] + [
            f'      <Vulnerability name="{esc(v.get("name"))}" cve="{esc(v.get("cve"))}" severity="{esc(v.get("severity"))}" description="{esc(v.get("description"))}"/>'
            for v in vulns
        ] + [
            f'    </Vulnerabilities>',
            f'  </Asset>',
        ]
    lines.append('</QuantumShieldReport>')
    filename = f"QuantumShield-{datetime.now().strftime('%Y%m%d-%H%M')}.xml"
    return Response(content="\n".join(lines), media_type="application/xml",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})
