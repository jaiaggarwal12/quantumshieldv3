from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app import __version__
from app.database import get_db

router = APIRouter()


@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    db_ok = True
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db_ok = False
    return {
        "status": "healthy" if db_ok else "degraded",
        "service": "QuantumShield PQC Scanner",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": __version__,
        "checks": {"database": "ok" if db_ok else "error"},
    }
