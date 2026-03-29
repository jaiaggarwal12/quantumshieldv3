"""
QuantumShield — Email OTP Service
Sends 6-digit OTP via Gmail SMTP for login verification.
Uses Python's built-in smtplib — no extra dependencies.
"""
import os
import smtplib
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone, timedelta
from typing import Optional

# ── Config from env vars ──────────────────────────────────────────────────────
SMTP_HOST     = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER", "")          # your Gmail address
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")      # Gmail App Password
FROM_NAME     = os.getenv("FROM_NAME", "QuantumShield Security")

# In-memory OTP store: {email: {otp, expires_at, attempts}}
# For production swap with Redis. Fine for hackathon.
_otp_store: dict = {}

OTP_EXPIRY_MINUTES = 10
MAX_ATTEMPTS       = 5


def _generate_otp() -> str:
    return "".join(random.choices(string.digits, k=6))


def send_otp(email: str, username: str) -> dict:
    """
    Generate and send a 6-digit OTP to the given email.
    Returns {"sent": True} or {"sent": False, "error": "..."}
    """
    otp = _generate_otp()
    expires = datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRY_MINUTES)

    # Store OTP
    _otp_store[email] = {
        "otp": otp,
        "expires_at": expires,
        "attempts": 0,
        "username": username,
    }

    # SMTP must be configured — no dev-mode fallback, OTP is never returned in API responses
    if not SMTP_USER or not SMTP_PASSWORD:
        print(f"[ERROR] SMTP_USER and SMTP_PASSWORD must be set in .env — OTP not sent to {email}")
        return {"sent": False, "error": "SMTP not configured. Set SMTP_USER and SMTP_PASSWORD in your .env file."}

    # Build email
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"QuantumShield Login OTP: {otp}"
    msg["From"]    = f"{FROM_NAME} <{SMTP_USER}>"
    msg["To"]      = email

    html = f"""
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#F0F4FF;font-family:'Segoe UI',Arial,sans-serif;">
  <div style="max-width:480px;margin:40px auto;background:#FFFFFF;border-radius:12px;
              border:1px solid #DDE1EE;overflow:hidden;box-shadow:0 4px 24px rgba(27,63,171,0.08);">
    <!-- Header -->
    <div style="background:linear-gradient(135deg,#1B3FAB,#2563EB);padding:32px;text-align:center;">
      <div style="font-size:32px;margin-bottom:8px;">⚛</div>
      <div style="color:#FFFFFF;font-size:20px;font-weight:800;letter-spacing:1px;">QuantumShield</div>
      <div style="color:rgba(255,255,255,0.7);font-size:12px;margin-top:4px;">PQC Security Scanner</div>
    </div>
    <!-- Body -->
    <div style="padding:32px;">
      <div style="color:#1A1D2E;font-size:16px;font-weight:700;margin-bottom:8px;">
        Login Verification Code
      </div>
      <div style="color:#5A6080;font-size:14px;margin-bottom:24px;">
        Hi {username}, use the code below to complete your sign-in.
        This code expires in {OTP_EXPIRY_MINUTES} minutes.
      </div>
      <!-- OTP Box -->
      <div style="background:#F0F4FF;border:2px solid #1B3FAB;border-radius:10px;
                  padding:24px;text-align:center;margin-bottom:24px;">
        <div style="font-size:36px;font-weight:900;letter-spacing:12px;
                    color:#1B3FAB;font-family:'Courier New',monospace;">
          {otp}
        </div>
        <div style="color:#9CA3AF;font-size:12px;margin-top:8px;">
          Enter this code in the QuantumShield login screen
        </div>
      </div>
      <div style="background:#FEF2F2;border-radius:8px;padding:12px 16px;
                  border-left:3px solid #DC2626;">
        <div style="color:#7F1D1D;font-size:12px;">
          ⚠️ If you did not request this code, someone may be attempting to access your account.
          Please ignore this email and secure your password immediately.
        </div>
      </div>
    </div>
    <!-- Footer -->
    <div style="padding:16px 32px;border-top:1px solid #EEF0F8;text-align:center;">
      <div style="color:#9CA3AF;font-size:11px;">
        PNB Cybersecurity Hackathon 2025-26 · QuantumShield Security Platform
      </div>
    </div>
  </div>
</body>
</html>
"""

    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, [email], msg.as_string())
        return {"sent": True}
    except Exception as e:
        print(f"Email send error: {e}")
        # Don't expose SMTP error to client — just fail gracefully
        return {"sent": False, "error": "Email delivery failed"}


def verify_otp(email: str, otp_input: str) -> dict:
    """
    Verify OTP for given email.
    Returns {"valid": True} or {"valid": False, "reason": "..."}
    """
    record = _otp_store.get(email)
    if not record:
        return {"valid": False, "reason": "No OTP was sent to this email — please request a new one"}

    # Check expiry
    if datetime.now(timezone.utc) > record["expires_at"]:
        del _otp_store[email]
        return {"valid": False, "reason": "OTP has expired — please log in again to receive a new code"}

    # Check attempts
    record["attempts"] += 1
    if record["attempts"] > MAX_ATTEMPTS:
        del _otp_store[email]
        return {"valid": False, "reason": "Too many incorrect attempts — please log in again"}

    # Check OTP
    if record["otp"] != otp_input.strip():
        remaining = MAX_ATTEMPTS - record["attempts"]
        return {"valid": False, "reason": f"Incorrect code — {remaining} attempt{'s' if remaining!=1 else ''} remaining"}

    # Valid — clean up
    del _otp_store[email]
    return {"valid": True}


def clear_otp(email: str):
    """Clear OTP for email (e.g. on logout)."""
    _otp_store.pop(email, None)
