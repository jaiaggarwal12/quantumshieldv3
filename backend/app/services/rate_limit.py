"""
QuantumShield — Database-backed sliding-window rate limiter.

Works across multiple workers/processes (unlike an in-memory counter). Each
call to `hit` increments the counter for a key within the current window and
returns whether the caller is still under the limit.
"""
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models.security import RateLimit


def _utcnow():
    return datetime.now(timezone.utc)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def hit(db: Session, key: str, max_count: int, window_seconds: int) -> tuple[bool, int]:
    """
    Register an attempt for `key`. Returns (allowed, retry_after_seconds).
    `allowed` is False once the count exceeds `max_count` within the window.
    """
    now = _utcnow()
    window_floor = now - timedelta(seconds=window_seconds)

    row = db.query(RateLimit).filter(RateLimit.key == key).first()
    if row is None or _aware(row.window_start) < window_floor:
        # Start a fresh window
        if row is None:
            row = RateLimit(key=key, window_start=now, count=1)
            db.add(row)
        else:
            row.window_start = now
            row.count = 1
        db.commit()
        return True, 0

    row.count += 1
    db.commit()
    if row.count > max_count:
        elapsed = (now - _aware(row.window_start)).total_seconds()
        retry_after = max(1, int(window_seconds - elapsed))
        return False, retry_after
    return True, 0


def reset(db: Session, key: str) -> None:
    db.query(RateLimit).filter(RateLimit.key == key).delete()
    db.commit()
