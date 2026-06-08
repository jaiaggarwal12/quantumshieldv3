"""
QuantumShield — Security-related persistence models.

These move ephemeral, security-critical state out of process memory and into the
database so the app behaves correctly across multiple workers and restarts:
  - OTPCode        : hashed login OTPs (never store plaintext)
  - RateLimit      : sliding-window counters for login / OTP endpoints
  - RevokedToken   : JWT denylist (logout / forced revocation)
  - AuditLog       : immutable record of security-relevant actions
"""
from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, DateTime, Text, Index

from app.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class OTPCode(Base):
    __tablename__ = "otp_codes"

    id          = Column(Integer, primary_key=True, index=True)
    email       = Column(String(128), index=True, nullable=False)
    code_hash   = Column(String(128), nullable=False)   # bcrypt hash of the OTP
    username    = Column(String(64), nullable=True)
    attempts    = Column(Integer, default=0)
    expires_at  = Column(DateTime, nullable=False)
    created_at  = Column(DateTime, default=_utcnow)


class RateLimit(Base):
    __tablename__ = "rate_limits"

    id            = Column(Integer, primary_key=True, index=True)
    key           = Column(String(160), index=True, nullable=False)  # e.g. "login:user@x"
    window_start  = Column(DateTime, nullable=False)
    count         = Column(Integer, default=0)

    __table_args__ = (Index("ix_rate_limit_key", "key"),)


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    id          = Column(Integer, primary_key=True, index=True)
    jti         = Column(String(64), unique=True, index=True, nullable=False)
    expires_at  = Column(DateTime, nullable=False)   # for periodic cleanup
    revoked_at  = Column(DateTime, default=_utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id          = Column(Integer, primary_key=True, index=True)
    ts          = Column(DateTime, default=_utcnow, index=True)
    user_id     = Column(Integer, nullable=True)
    username    = Column(String(64), nullable=True, index=True)
    action      = Column(String(64), nullable=False, index=True)
    target      = Column(String(256), nullable=True)
    ip          = Column(String(64), nullable=True)
    status      = Column(String(16), default="ok")
    detail      = Column(Text, nullable=True)
