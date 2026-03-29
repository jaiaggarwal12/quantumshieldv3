from fastapi import APIRouter
from datetime import datetime, timezone

router = APIRouter()

@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "QuantumShield PQC Scanner",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "3.0.0",
    }
