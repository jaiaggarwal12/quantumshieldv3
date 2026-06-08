"""
QuantumShield — Audit logging service.

Records security-relevant actions (auth events, scans, user management) to an
append-only table. Essential for CERT-In / RBI-style accountability: who did
what, when, from where.
"""
import json
from typing import Optional

from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.models.security import AuditLog

logger = get_logger("quantumshield.audit")


def record(
    db: Session,
    action: str,
    *,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    target: Optional[str] = None,
    ip: Optional[str] = None,
    status: str = "ok",
    detail: Optional[dict] = None,
) -> None:
    """Write an audit entry. Never raises — auditing must not break the request."""
    try:
        entry = AuditLog(
            action=action,
            user_id=user_id,
            username=username,
            target=(target or "")[:256] or None,
            ip=ip,
            status=status,
            detail=json.dumps(detail) if detail else None,
        )
        db.add(entry)
        db.commit()
        logger.info("audit action=%s user=%s target=%s status=%s ip=%s",
                    action, username, target, status, ip)
    except Exception as e:  # pragma: no cover — defensive
        db.rollback()
        logger.warning("Failed to write audit log for action=%s: %s", action, e)
