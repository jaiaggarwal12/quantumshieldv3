"""
QuantumShield — Scan job persistence.

Batch / API / VPN scans run asynchronously. Storing job state in the database
(instead of a process-memory dict) means polling works across workers and
survives restarts.
"""
import json
from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, DateTime, Text

from app.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id           = Column(Integer, primary_key=True, index=True)
    job_id       = Column(String(64), unique=True, index=True, nullable=False)
    user_id      = Column(Integer, nullable=True, index=True)
    job_type     = Column(String(16), default="batch")   # batch | api | vpn
    scan_name    = Column(String(256), nullable=True)
    status       = Column(String(16), default="queued")  # queued|running|completed|done|error
    target       = Column(String(256), nullable=True)
    progress_json = Column(Text, nullable=True)
    result_json  = Column(Text, nullable=True)
    summary_json = Column(Text, nullable=True)
    error        = Column(Text, nullable=True)
    created_at   = Column(DateTime, default=_utcnow)
    updated_at   = Column(DateTime, default=_utcnow, onupdate=_utcnow)

    # ── JSON helpers ────────────────────────────────────────────────────────
    def set_progress(self, value: dict):
        self.progress_json = json.dumps(value) if value is not None else None

    def set_result(self, value):
        self.result_json = json.dumps(value) if value is not None else None

    def set_summary(self, value: dict):
        self.summary_json = json.dumps(value) if value is not None else None

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "type": self.job_type,
            "scan_name": self.scan_name,
            "status": self.status,
            "target": self.target,
            "progress": json.loads(self.progress_json) if self.progress_json else {},
            "result": json.loads(self.result_json) if self.result_json else None,
            "results": json.loads(self.result_json) if (self.result_json and self.job_type == "batch") else None,
            "summary": json.loads(self.summary_json) if self.summary_json else {},
            "error": self.error,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
