"""
QuantumShield — Email OTP Service (database-backed, hardened)

Improvements over the prototype:
  - OTPs generated with `secrets` (CSPRNG), not `random`.
  - OTPs are hashed (bcrypt) before storage — plaintext never persisted.
  - State lives in the database, so OTP login works across multiple workers
    and survives restarts (no in-memory dict).
"""
import secrets
import smtplib
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging_config import get_logger
from app.models.security import OTPCode

logger = get_logger("quantumshield.otp")

_otp_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _generate_otp() -> str:
    """Cryptographically secure 6-digit code."""
    return f"{secrets.randbelow(1_000_000):06d}"


def _utcnow():
    return datetime.now(timezone.utc)


def _ensure_aware(dt: datetime) -> datetime:
    # SQLite returns naive datetimes; treat stored values as UTC.
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def send_otp(db: Session, email: str, username: str) -> dict:
    """
    Generate, store (hashed), and email a 6-digit OTP.
    Returns {"sent": True} or {"sent": False, "error": "..."}.
    """
    otp = _generate_otp()
    expires = _utcnow() + timedelta(minutes=settings.OTP_EXPIRY_MINUTES)

    # Replace any existing codes for this email.
    db.query(OTPCode).filter(OTPCode.email == email).delete()
    db.add(OTPCode(
        email=email,
        code_hash=_otp_pwd.hash(otp),
        username=username,
        attempts=0,
        expires_at=expires,
    ))
    db.commit()

    if not settings.SMTP_USER or not settings.SMTP_PASSWORD:
        logger.error("SMTP not configured — OTP not sent to %s", email)
        return {"sent": False, "error": "SMTP not configured. Set SMTP_USER and SMTP_PASSWORD."}

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "QuantumShield Login Verification Code"
    msg["From"]    = f"{settings.FROM_NAME} <{settings.SMTP_USER}>"
    msg["To"]      = email
    msg.attach(MIMEText(_build_html(username, otp), "html"))

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_USER, [email], msg.as_string())
        return {"sent": True}
    except Exception as e:
        logger.error("Email send error to %s: %s", email, e)
        return {"sent": False, "error": "Email delivery failed"}


def verify_otp(db: Session, email: str, otp_input: str) -> dict:
    """Verify an OTP. Returns {"valid": True} or {"valid": False, "reason": "..."}."""
    record = (db.query(OTPCode)
              .filter(OTPCode.email == email)
              .order_by(OTPCode.created_at.desc())
              .first())
    if not record:
        return {"valid": False, "reason": "No OTP was sent to this email — please request a new one"}

    if _utcnow() > _ensure_aware(record.expires_at):
        db.delete(record); db.commit()
        return {"valid": False, "reason": "OTP has expired — please log in again to receive a new code"}

    record.attempts += 1
    db.commit()
    if record.attempts > settings.OTP_MAX_ATTEMPTS:
        db.delete(record); db.commit()
        return {"valid": False, "reason": "Too many incorrect attempts — please log in again"}

    if not _otp_pwd.verify(otp_input.strip(), record.code_hash):
        remaining = settings.OTP_MAX_ATTEMPTS - record.attempts
        if remaining <= 0:
            db.delete(record); db.commit()
            return {"valid": False, "reason": "Too many incorrect attempts — please log in again"}
        return {"valid": False, "reason": f"Incorrect code — {remaining} attempt{'s' if remaining != 1 else ''} remaining"}

    db.delete(record); db.commit()
    return {"valid": True}


def clear_otp(db: Session, email: str) -> None:
    db.query(OTPCode).filter(OTPCode.email == email).delete()
    db.commit()


def _build_html(username: str, otp: str) -> str:
    return f"""
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#F0F4FF;font-family:'Segoe UI',Arial,sans-serif;">
  <div style="max-width:480px;margin:40px auto;background:#FFFFFF;border-radius:12px;
              border:1px solid #DDE1EE;overflow:hidden;box-shadow:0 4px 24px rgba(27,63,171,0.08);">
    <div style="background:linear-gradient(135deg,#1B3FAB,#2563EB);padding:32px;text-align:center;">
      <div style="font-size:32px;margin-bottom:8px;">⚛</div>
      <div style="color:#FFFFFF;font-size:20px;font-weight:800;letter-spacing:1px;">QuantumShield</div>
      <div style="color:rgba(255,255,255,0.7);font-size:12px;margin-top:4px;">PQC Security Scanner</div>
    </div>
    <div style="padding:32px;">
      <div style="color:#1A1D2E;font-size:16px;font-weight:700;margin-bottom:8px;">Login Verification Code</div>
      <div style="color:#5A6080;font-size:14px;margin-bottom:24px;">
        Hi {username}, use the code below to complete your sign-in.
        This code expires in {settings.OTP_EXPIRY_MINUTES} minutes.
      </div>
      <div style="background:#F0F4FF;border:2px solid #1B3FAB;border-radius:10px;padding:24px;text-align:center;margin-bottom:24px;">
        <div style="font-size:36px;font-weight:900;letter-spacing:12px;color:#1B3FAB;font-family:'Courier New',monospace;">{otp}</div>
        <div style="color:#9CA3AF;font-size:12px;margin-top:8px;">Enter this code in the QuantumShield login screen</div>
      </div>
      <div style="background:#FEF2F2;border-radius:8px;padding:12px 16px;border-left:3px solid #DC2626;">
        <div style="color:#7F1D1D;font-size:12px;">
          ⚠️ If you did not request this code, someone may be attempting to access your account.
          Ignore this email and secure your password immediately.
        </div>
      </div>
    </div>
    <div style="padding:16px 32px;border-top:1px solid #EEF0F8;text-align:center;">
      <div style="color:#9CA3AF;font-size:11px;">QuantumShield Security Platform</div>
    </div>
  </div>
</body>
</html>
"""
