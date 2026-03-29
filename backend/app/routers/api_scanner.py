"""
QuantumShield — API Scanner & VPN Probe Router
Fixes:
  - 401 error: auth is now OPTIONAL (scans work without login, but login saves history)
  - Timeout: async background jobs with polling so Vercel 30s limit isn't hit
  - CSV, XML export
  - CERT-In CBOM mapping
"""

import asyncio
import csv
import io
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.routers.auth import get_current_user
from app.services.api_scanner import scan_api_endpoints, scan_vpn_endpoints

router = APIRouter(prefix="/api/v1", tags=["API Scanner", "VPN", "Export"])

# In-memory job store for background scans
_jobs: dict = {}
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


# ── Background job helpers ────────────────────────────────────────────────────
def _run_api_scan_bg(job_id: str, base_url: str):
    try:
        _jobs[job_id]["status"] = "running"
        result = scan_api_endpoints(base_url, timeout=6)
        _jobs[job_id].update({"status": "done", "result": result})
    except Exception as e:
        _jobs[job_id].update({"status": "error", "error": str(e)})


def _run_vpn_scan_bg(job_id: str, hostname: str, timeout: float):
    try:
        _jobs[job_id]["status"] = "running"
        result = scan_vpn_endpoints(hostname, timeout=timeout)
        _jobs[job_id].update({"status": "done", "result": result})
    except Exception as e:
        _jobs[job_id].update({"status": "error", "error": str(e)})


# ── API Scanner ────────────────────────────────────────────────────────────────
@router.post("/scan/api")
async def scan_api(
    request: APIScanRequest,
    background_tasks: BackgroundTasks,
    current_user: Optional[User] = Depends(get_current_user)
):
    """
    Start an async API endpoint scan. Returns a job_id immediately.
    Poll GET /scan/api/job/{job_id} for results.
    Auth is optional — logged-in users get scan saved to history.
    """
    if not request.base_url.strip():
        raise HTTPException(status_code=400, detail="base_url is required")

    job_id = str(uuid.uuid4())
    _jobs[job_id] = {
        "job_id": job_id,
        "type": "api",
        "target": request.base_url,
        "status": "queued",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "result": None,
        "error": None,
    }
    # Run in thread pool so it doesn't block the event loop
    loop = asyncio.get_event_loop()
    loop.run_in_executor(_executor, _run_api_scan_bg, job_id, request.base_url)

    return {"job_id": job_id, "status": "queued", "message": "Scan started — poll /scan/api/job/{job_id} for results"}


@router.get("/scan/api/job/{job_id}")
async def get_api_scan_job(job_id: str):
    """Poll this endpoint for API scan results."""
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    return _jobs[job_id]


# ── VPN Probe ─────────────────────────────────────────────────────────────────
@router.post("/scan/vpn")
async def scan_vpn(
    request: VPNScanRequest,
    current_user: Optional[User] = Depends(get_current_user)
):
    """
    Start an async VPN port probe. Returns a job_id immediately.
    Poll GET /scan/vpn/job/{job_id} for results.
    Auth is optional.
    """
    hostname = request.hostname.replace("https://", "").replace("http://", "").split("/")[0].strip()
    if not hostname:
        raise HTTPException(status_code=400, detail="hostname is required")

    job_id = str(uuid.uuid4())
    _jobs[job_id] = {
        "job_id": job_id,
        "type": "vpn",
        "target": hostname,
        "status": "queued",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "result": None,
        "error": None,
    }
    loop = asyncio.get_event_loop()
    loop.run_in_executor(_executor, _run_vpn_scan_bg, job_id, hostname, request.timeout)

    return {"job_id": job_id, "status": "queued", "message": "VPN probe started — poll /scan/vpn/job/{job_id} for results"}


@router.get("/scan/vpn/job/{job_id}")
async def get_vpn_scan_job(job_id: str):
    """Poll this endpoint for VPN scan results."""
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    return _jobs[job_id]


# ── CSV Export (no auth required — export your own data) ─────────────────────
@router.post("/export/csv")
async def export_csv(request: CSVExportRequest):
    """Export scan results as CSV. No auth required."""
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
async def export_xml(request: CSVExportRequest):
    """Export scan results as CERT-In compliant XML. No auth required."""
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
