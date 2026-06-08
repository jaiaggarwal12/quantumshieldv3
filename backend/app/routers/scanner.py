"""
QuantumShield — Scanner Router

Authenticated scanning with:
  - SSRF protection (targets validated before any connection)
  - Database-backed async jobs (survive restarts, work across workers)
  - Audit logging of every scan
  - Scan history persistence
"""
import asyncio
import concurrent.futures
import json
import re
import uuid
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging_config import get_logger
from app.core.net_guard import validate_target
from app.database import get_db, SessionLocal
from app.models.scan_history import ScanHistory
from app.models.scan_job import ScanJob
from app.models.user import User
from app.routers.auth import require_auth, _client_ip
from app.services import audit_service as audit
from app.services.scanner_service import (
    PQC_ALGORITHMS, PQC_RECOMMENDATIONS, scan_tls_target, check_http_security_headers
)
from app.services.pqc_detect import detect_key_exchange_group
try:
    from app.services.scanner_service import VULNERABLE_ALGORITHMS
except ImportError:
    VULNERABLE_ALGORITHMS = {}

logger = get_logger("quantumshield.scanner")
router = APIRouter()


# ── Pydantic ──────────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    targets: List[str]
    port: int = 443
    include_headers: bool = True
    scan_name: Optional[str] = None

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, v):
        if len(v) > settings.MAX_TARGETS_PER_SCAN:
            raise ValueError(f"Maximum {settings.MAX_TARGETS_PER_SCAN} targets per scan")
        return [re.sub(r"^https?://", "", t).split("/")[0].strip() for t in v if t.strip()]

class SingleScanRequest(BaseModel):
    target: str
    port: int = 443


# ── Helpers ───────────────────────────────────────────────────────────────────
def _save_scan(db: Session, user_id: int, result: dict):
    """Persist a single scan result to the database."""
    try:
        pqc = result.get("pqc_assessment", {})
        tls = result.get("tls_info", {})
        record = ScanHistory(
            user_id=user_id,
            target=result.get("target", ""),
            port=result.get("port", 443),
            pqc_score=pqc.get("score"),
            pqc_status=pqc.get("status"),
            tls_version=tls.get("tls_version"),
            cipher_suite=tls.get("cipher_suite"),
            scan_status=result.get("status", "success"),
            result_json=json.dumps(result),
        )
        db.add(record)
        db.commit()
    except Exception:
        db.rollback()   # non-fatal — scan still returned


def run_scan_job(job_id: str, targets: list, port: int, include_headers: bool, user_id: int):
    """Background job — scans multiple targets, persisting state to the DB."""
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
        if not job:
            return
        job.status = "running"
        db.commit()

        results = []
        for idx, target in enumerate(targets):
            job.set_progress({"current": idx + 1, "total": len(targets), "current_target": target})
            db.commit()

            ok, reason = validate_target(target, port)
            if not ok:
                results.append({"target": target, "status": "blocked", "errors": [reason]})
                continue
            try:
                result = scan_tls_target(target, port)
                if include_headers:
                    result["http_headers"] = check_http_security_headers(target, port)
                _save_scan(db, user_id, result)
                results.append(result)
            except Exception as e:
                results.append({"target": target, "status": "error", "errors": [str(e)[:200]]})

        statuses = [r.get("pqc_assessment", {}).get("status", "UNKNOWN") for r in results]
        job.set_result(results)
        job.set_summary({
            "total_scanned": len(results),
            "quantum_safe":  statuses.count("QUANTUM_SAFE"),
            "pqc_ready":     statuses.count("PQC_READY"),
            "transitioning": statuses.count("TRANSITIONING"),
            "vulnerable":    statuses.count("VULNERABLE"),
            "blocked":       sum(1 for r in results if r.get("status") == "blocked"),
            "errors":        sum(1 for r in results if r.get("status") == "error"),
        })
        job.status = "completed"
        db.commit()
    except Exception as e:
        logger.exception("Batch job %s failed", job_id)
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


# ── Endpoints ─────────────────────────────────────────────────────────────────
@router.post("/scan/quick")
async def quick_scan(request: SingleScanRequest, req: Request,
                     current_user: User = Depends(require_auth),
                     db: Session = Depends(get_db)):
    """Single-target deep scan (authenticated, SSRF-guarded)."""
    target = re.sub(r"^https?://", "", request.target).split("/")[0].strip()
    if not target:
        raise HTTPException(status_code=400, detail="Invalid target")

    ok, reason = validate_target(target, request.port)
    if not ok:
        audit.record(db, "scan.blocked", user_id=current_user.id, username=current_user.username,
                     ip=_client_ip(req), target=target, status="blocked", detail={"reason": reason})
        raise HTTPException(status_code=400, detail=reason)

    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        result  = await loop.run_in_executor(pool, scan_tls_target, target, request.port)
        headers = await loop.run_in_executor(pool, check_http_security_headers, target, request.port)

    result["http_headers"] = headers
    _save_scan(db, current_user.id, result)
    audit.record(db, "scan.quick", user_id=current_user.id, username=current_user.username,
                 ip=_client_ip(req), target=target, detail={"score": result.get("pqc_assessment", {}).get("score")})
    return result


@router.post("/scan/batch")
async def batch_scan(request: ScanRequest, background_tasks: BackgroundTasks, req: Request,
                     current_user: User = Depends(require_auth), db: Session = Depends(get_db)):
    """Async batch scan (authenticated). State persisted to the DB."""
    if not request.targets:
        raise HTTPException(status_code=400, detail="No valid targets provided")

    job_id = str(uuid.uuid4())
    job = ScanJob(
        job_id=job_id, user_id=current_user.id, job_type="batch",
        scan_name=request.scan_name or f"Batch Scan — {len(request.targets)} targets",
        status="queued",
    )
    job.set_progress({"current": 0, "total": len(request.targets), "current_target": ""})
    db.add(job)
    db.commit()

    audit.record(db, "scan.batch", user_id=current_user.id, username=current_user.username,
                 ip=_client_ip(req), detail={"count": len(request.targets), "job_id": job_id})

    background_tasks.add_task(
        run_scan_job, job_id, request.targets, request.port, request.include_headers, current_user.id
    )
    return {"job_id": job_id, "status": "queued", "targets_count": len(request.targets)}


@router.get("/scan/job/{job_id}")
async def get_scan_job(job_id: str, current_user: User = Depends(require_auth), db: Session = Depends(get_db)):
    job = db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.user_id not in (None, current_user.id) and current_user.role != "Admin":
        raise HTTPException(status_code=403, detail="Access denied")
    return job.to_dict()


@router.get("/scan/jobs")
async def list_scan_jobs(current_user: User = Depends(require_auth), db: Session = Depends(get_db)):
    q = db.query(ScanJob)
    if current_user.role != "Admin":
        q = q.filter(ScanJob.user_id == current_user.id)
    jobs = q.order_by(ScanJob.created_at.desc()).limit(100).all()
    return [{"job_id": j.job_id, "scan_name": j.scan_name, "status": j.status,
             "summary": json.loads(j.summary_json) if j.summary_json else {}} for j in jobs]


@router.get("/history")
async def get_history(limit: int = 50, current_user: User = Depends(require_auth), db: Session = Depends(get_db)):
    scans = (db.query(ScanHistory)
             .filter(ScanHistory.user_id == current_user.id)
             .order_by(ScanHistory.created_at.desc())
             .limit(min(limit, 500))
             .all())
    return [{"id": s.id, "target": s.target, "port": s.port, "pqc_score": s.pqc_score,
             "pqc_status": s.pqc_status, "tls_version": s.tls_version, "cipher_suite": s.cipher_suite,
             "scan_status": s.scan_status, "created_at": s.created_at.isoformat() if s.created_at else None}
            for s in scans]


@router.get("/history/{scan_id}")
async def get_history_scan(scan_id: int, current_user: User = Depends(require_auth), db: Session = Depends(get_db)):
    scan = db.query(ScanHistory).filter(ScanHistory.id == scan_id, ScanHistory.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan.get_result()


@router.delete("/history/{scan_id}")
async def delete_history_scan(scan_id: int, current_user: User = Depends(require_auth), db: Session = Depends(get_db)):
    scan = db.query(ScanHistory).filter(ScanHistory.id == scan_id, ScanHistory.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return {"message": "Scan deleted"}


@router.get("/algorithms/pqc")
async def get_pqc_algorithms(_: User = Depends(require_auth)):
    return {
        "pqc_algorithms": PQC_ALGORITHMS,
        "vulnerable_algorithms": VULNERABLE_ALGORITHMS,
        "recommendations": PQC_RECOMMENDATIONS,
        "nist_standards": {
            "FIPS_203": "ML-KEM (Module Lattice-based Key Encapsulation Mechanism)",
            "FIPS_204": "ML-DSA (Module Lattice-based Digital Signature Algorithm)",
            "FIPS_205": "SLH-DSA (Stateless Hash-based Digital Signature Algorithm)",
        },
    }


@router.post("/scan/pqc-kex")
async def detect_pqc_kex(request: SingleScanRequest, req: Request,
                         current_user: User = Depends(require_auth), db: Session = Depends(get_db)):
    """Standalone active post-quantum key-exchange detection (raw TLS 1.3 probe)."""
    target = re.sub(r"^https?://", "", request.target).split("/")[0].strip()
    if not target:
        raise HTTPException(status_code=400, detail="Invalid target")

    ok, reason = validate_target(target, request.port)
    if not ok:
        raise HTTPException(status_code=400, detail=reason)

    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        detection = await loop.run_in_executor(pool, detect_key_exchange_group, target, request.port)
    audit.record(db, "scan.pqc_kex", user_id=current_user.id, username=current_user.username,
                 ip=_client_ip(req), target=target)
    return {"target": target, "port": request.port, "detection": detection}
