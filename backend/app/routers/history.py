"""
QuantumShield — Scan History Router
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional
import json

from app.database import get_db, ScanHistory
from app.routers.auth import require_auth, get_current_user
from app.database import User

router = APIRouter(prefix="/api/v1/history", tags=["History"])


@router.get("/")
def get_history(limit: int = 50, skip: int = 0,
                user: User = Depends(require_auth),
                db: Session = Depends(get_db)):
    """Get scan history. Admins see all, others see only their own."""
    query = db.query(ScanHistory).order_by(ScanHistory.scanned_at.desc())

    if user.role not in ("Admin",):
        query = query.filter(ScanHistory.user_id == user.id)

    total = query.count()
    records = query.offset(skip).limit(limit).all()

    return {
        "total": total,
        "scans": [
            {
                "id": r.id,
                "scan_id": r.scan_id,
                "target": r.target,
                "port": r.port,
                "pqc_score": r.pqc_score,
                "pqc_status": r.pqc_status,
                "tls_version": r.tls_version,
                "cipher_suite": r.cipher_suite,
                "scanned_at": r.scanned_at.isoformat(),
                "username": r.username,
            }
            for r in records
        ]
    }


@router.get("/{scan_id}")
def get_scan_detail(scan_id: str,
                    user: User = Depends(require_auth),
                    db: Session = Depends(get_db)):
    """Get full scan result by scan_id."""
    record = db.query(ScanHistory).filter(ScanHistory.scan_id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Non-admins can only see their own
    if user.role not in ("Admin",) and record.user_id != user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    result = json.loads(record.result_json) if record.result_json else {}
    return result


@router.delete("/{scan_id}")
def delete_scan(scan_id: str,
                user: User = Depends(require_auth),
                db: Session = Depends(get_db)):
    """Delete a scan record. Admin or owner only."""
    record = db.query(ScanHistory).filter(ScanHistory.scan_id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    if user.role not in ("Admin",) and record.user_id != user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    db.delete(record)
    db.commit()
    return {"message": "Scan deleted"}


@router.get("/stats/summary")
def get_stats(user: User = Depends(require_auth), db: Session = Depends(get_db)):
    """Summary statistics for the current user (or all for admins)."""
    query = db.query(ScanHistory)
    if user.role not in ("Admin",):
        query = query.filter(ScanHistory.user_id == user.id)

    records = query.all()
    if not records:
        return {"total": 0, "avg_score": 0, "by_status": {}}

    scores = [r.pqc_score for r in records if r.pqc_score is not None]
    statuses = {}
    for r in records:
        s = r.pqc_status or "UNKNOWN"
        statuses[s] = statuses.get(s, 0) + 1

    return {
        "total": len(records),
        "avg_score": round(sum(scores) / len(scores), 1) if scores else 0,
        "by_status": statuses,
        "unique_targets": len(set(r.target for r in records)),
    }
