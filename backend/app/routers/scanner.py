"""
QuantumShield — Scanner Router (with Auth + Scan History persistence)
"""
import asyncio
import concurrent.futures
import json
import re
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, validator
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan_history import ScanHistory
from app.models.user import User
from app.routers.auth import get_current_user, require_auth
from app.services.scanner_service import (
    PQC_ALGORITHMS, PQC_RECOMMENDATIONS, scan_tls_target, check_http_security_headers
)
try:
    from app.services.scanner_service import VULNERABLE_ALGORITHMS
except ImportError:
    VULNERABLE_ALGORITHMS = {}

router = APIRouter()
scan_jobs = {}   # in-memory job store


# ── Pydantic ──────────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    targets: List[str]
    port: int = 443
    include_headers: bool = True
    scan_name: Optional[str] = None

    @validator("targets")
    def validate_targets(cls, v):
        if len(v) > 20:
            raise ValueError("Maximum 20 targets per scan")
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


def run_scan_job(job_id: str, targets: list, port: int, include_headers: bool,
                 user_id: int, db_url: str):
    """Background job — scans multiple targets and persists results."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine(db_url, connect_args={"check_same_thread": False} if "sqlite" in db_url else {})
    Session = sessionmaker(bind=engine)
    db = Session()

    scan_jobs[job_id]["status"] = "running"
    results = []
    for idx, target in enumerate(targets):
        scan_jobs[job_id]["progress"] = {
            "current": idx + 1, "total": len(targets), "current_target": target
        }
        try:
            result = scan_tls_target(target, port)
            if include_headers:
                result["http_headers"] = check_http_security_headers(target, port)
            _save_scan(db, user_id, result)
            results.append(result)
        except Exception as e:
            results.append({"target": target, "status": "error", "errors": [str(e)]})

    db.close()
    scan_jobs[job_id]["status"] = "completed"
    scan_jobs[job_id]["results"] = results
    statuses = [r.get("pqc_assessment", {}).get("status", "UNKNOWN") for r in results]
    scan_jobs[job_id]["summary"] = {
        "total_scanned": len(results),
        "quantum_safe":  statuses.count("QUANTUM_SAFE"),
        "pqc_ready":     statuses.count("PQC_READY"),
        "transitioning": statuses.count("TRANSITIONING"),
        "vulnerable":    statuses.count("VULNERABLE"),
        "errors":        sum(1 for r in results if r.get("status") == "error"),
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────
@router.post("/scan/quick")
async def quick_scan(request: SingleScanRequest,
                     current_user: User = Depends(require_auth),
                     db: Session = Depends(get_db)):
    """Single-target deep scan (authenticated)."""
    target = re.sub(r"^https?://", "", request.target).split("/")[0].strip()
    if not target:
        raise HTTPException(status_code=400, detail="Invalid target")

    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        result  = await loop.run_in_executor(pool, scan_tls_target, target, request.port)
        headers = await loop.run_in_executor(pool, check_http_security_headers, target, request.port)

    result["http_headers"] = headers
    _save_scan(db, current_user.id, result)
    return result


@router.post("/scan/batch")
async def batch_scan(request: ScanRequest,
                     background_tasks: BackgroundTasks,
                     current_user: User = Depends(require_auth)):
    """Async batch scan (authenticated)."""
    import os
    job_id = str(uuid.uuid4())
    db_url = os.getenv("DATABASE_URL", "sqlite:///./quantumshield.db")
    scan_jobs[job_id] = {
        "job_id": job_id,
        "scan_name": request.scan_name or f"Batch Scan — {len(request.targets)} targets",
        "status": "queued",
        "targets": request.targets,
        "progress": {"current": 0, "total": len(request.targets), "current_target": ""},
        "results": [], "summary": {},
    }
    background_tasks.add_task(
        run_scan_job, job_id, request.targets, request.port,
        request.include_headers, current_user.id, db_url
    )
    return {"job_id": job_id, "status": "queued", "targets_count": len(request.targets)}


@router.get("/scan/job/{job_id}")
async def get_scan_job(job_id: str, _: User = Depends(require_auth)):
    if job_id not in scan_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    return scan_jobs[job_id]


@router.get("/scan/jobs")
async def list_scan_jobs(_: User = Depends(require_auth)):
    return [
        {"job_id": v["job_id"], "scan_name": v.get("scan_name"),
         "status": v["status"], "targets_count": len(v.get("targets", [])),
         "summary": v.get("summary", {})}
        for v in scan_jobs.values()
    ]


@router.get("/history")
async def get_history(limit: int = 50, current_user: User = Depends(require_auth),
                      db: Session = Depends(get_db)):
    """Return scan history for the current user."""
    scans = (db.query(ScanHistory)
             .filter(ScanHistory.user_id == current_user.id)
             .order_by(ScanHistory.created_at.desc())
             .limit(limit)
             .all())
    return [
        {
            "id":          s.id,
            "target":      s.target,
            "port":        s.port,
            "pqc_score":   s.pqc_score,
            "pqc_status":  s.pqc_status,
            "tls_version": s.tls_version,
            "cipher_suite": s.cipher_suite,
            "scan_status": s.scan_status,
            "created_at":  s.created_at.isoformat() if s.created_at else None,
        }
        for s in scans
    ]


@router.get("/history/{scan_id}")
async def get_history_scan(scan_id: int, current_user: User = Depends(require_auth),
                            db: Session = Depends(get_db)):
    """Return full result for a specific historical scan."""
    scan = db.query(ScanHistory).filter(
        ScanHistory.id == scan_id,
        ScanHistory.user_id == current_user.id
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan.get_result()


@router.delete("/history/{scan_id}")
async def delete_history_scan(scan_id: int, current_user: User = Depends(require_auth),
                               db: Session = Depends(get_db)):
    scan = db.query(ScanHistory).filter(
        ScanHistory.id == scan_id,
        ScanHistory.user_id == current_user.id
    ).first()
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
