"""
QuantumShield — Authentication Router (hardened)

Flow:
  1. POST /login      → validate password (rate-limited) → email a 6-digit OTP
  2. POST /verify-otp → validate OTP (rate-limited) → return JWT (with jti)
  3. POST /logout     → revoke the current token (server-side denylist)

All security-relevant events are written to the audit log.
"""
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database import get_db
from app.models.user import User
from app.models.security import RevokedToken
from app.services import rate_limit
from app.services import audit_service as audit
from app.services.email_service import send_otp, verify_otp, clear_otp

SECRET_KEY           = settings.SECRET_KEY
ALGORITHM            = settings.ALGORITHM
TOKEN_EXPIRE_MINUTES = settings.TOKEN_EXPIRE_MINUTES

pwd_context   = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)
router        = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ── Schemas ───────────────────────────────────────────────────────────────────
class Token(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    role:         str
    username:     str
    email:        str
    user_id:      int

class OTPRequest(BaseModel):
    email: str
    otp:   str

class UserCreate(BaseModel):
    username: str
    email:    str
    password: str
    role:     str = "Operator"

class ChangePassword(BaseModel):
    current_password: str
    new_password:     str

class UpdateRole(BaseModel):
    role: str


# ── Utilities ─────────────────────────────────────────────────────────────────
def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def hash_password(pwd: str) -> str:
    return pwd_context.hash(pwd)

def create_access_token(data: dict) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        **data,
        "iat": now,
        "exp": now + timedelta(minutes=TOKEN_EXPIRE_MINUTES),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


# ── Dependencies ──────────────────────────────────────────────────────────────
def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """Returns User or None — does NOT raise 401. Honors the token denylist."""
    if not token:
        return None
    try:
        payload  = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None
    username = payload.get("sub")
    jti = payload.get("jti")
    if not username:
        return None
    if jti and db.query(RevokedToken).filter(RevokedToken.jti == jti).first():
        return None  # token was logged out / revoked
    return db.query(User).filter(User.username == username, User.is_active == True).first()


def require_auth(user: Optional[User] = Depends(get_current_user)) -> User:
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Please log in to access this resource",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_admin(user: User = Depends(require_auth)) -> User:
    if user.role != "Admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# ── Step 1: Password check → send OTP ────────────────────────────────────────
@router.post("/login")
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    ip = _client_ip(request)

    allowed, retry = rate_limit.hit(
        db, f"login:{ip}", settings.LOGIN_MAX_ATTEMPTS, settings.LOGIN_WINDOW_SECONDS
    )
    if not allowed:
        audit.record(db, "login.rate_limited", username=form.username, ip=ip, status="blocked")
        raise HTTPException(status_code=429, detail=f"Too many attempts. Try again in {retry}s.",
                            headers={"Retry-After": str(retry)})

    user = db.query(User).filter(User.username == form.username, User.is_active == True).first()
    if not user or not verify_password(form.password, user.hashed_password):
        audit.record(db, "login.failed", username=form.username, ip=ip, status="fail")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")

    # Public demo account: skip the email-OTP step for frictionless access.
    # This is a real account hitting the real backend — only the OTP gate is bypassed.
    if settings.DEMO_ENABLED and user.username == settings.DEMO_USERNAME:
        user.last_login = datetime.now(timezone.utc)
        db.commit()
        rate_limit.reset(db, f"login:{ip}")
        token = create_access_token({"sub": user.username, "role": user.role})
        audit.record(db, "login.demo", user_id=user.id, username=user.username, ip=ip)
        return {
            "otp_required": False,
            "access_token": token,
            "token_type": "bearer",
            "role": user.role,
            "username": user.username,
            "email": user.email,
            "user_id": user.id,
        }

    # Throttle OTP emails per user to prevent mail-bombing.
    ok_send, retry_send = rate_limit.hit(
        db, f"otp_send:{user.email}", settings.OTP_SEND_MAX, settings.OTP_SEND_WINDOW_SECONDS
    )
    if not ok_send:
        audit.record(db, "otp.rate_limited", username=user.username, ip=ip, status="blocked")
        raise HTTPException(status_code=429, detail=f"Too many OTP requests. Try again in {retry_send}s.",
                            headers={"Retry-After": str(retry_send)})

    result = send_otp(db, user.email, user.username)
    if not result.get("sent"):
        audit.record(db, "otp.send_failed", username=user.username, ip=ip, status="error")
        raise HTTPException(status_code=500, detail=result.get("error", "Could not send OTP email."))

    audit.record(db, "login.password_ok", user_id=user.id, username=user.username, ip=ip)
    return {"message": f"OTP sent to {user.email}", "email": user.email,
            "username": user.username, "otp_required": True}


@router.get("/demo-info")
def demo_info():
    """Public: returns the demo account credentials to display on the login page."""
    if not settings.DEMO_ENABLED:
        return {"enabled": False}
    return {
        "enabled": True,
        "username": settings.DEMO_USERNAME,
        "password": settings.DEMO_PASSWORD,
        "note": "Real account · no OTP required",
    }


# ── Step 2: OTP verification → return JWT ────────────────────────────────────
@router.post("/verify-otp", response_model=Token)
def verify_otp_and_login(request: Request, data: OTPRequest, db: Session = Depends(get_db)):
    ip = _client_ip(request)
    allowed, retry = rate_limit.hit(
        db, f"otp_verify:{ip}", settings.LOGIN_MAX_ATTEMPTS, settings.LOGIN_WINDOW_SECONDS
    )
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Too many attempts. Try again in {retry}s.",
                            headers={"Retry-After": str(retry)})

    result = verify_otp(db, data.email, data.otp)
    if not result["valid"]:
        audit.record(db, "otp.verify_failed", username=data.email, ip=ip, status="fail",
                     detail={"reason": result["reason"]})
        raise HTTPException(status_code=400, detail=result["reason"])

    user = db.query(User).filter(User.email == data.email, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.last_login = datetime.now(timezone.utc)
    db.commit()
    rate_limit.reset(db, f"login:{ip}")

    token = create_access_token({"sub": user.username, "role": user.role})
    audit.record(db, "login.success", user_id=user.id, username=user.username, ip=ip)
    return Token(access_token=token, role=user.role, username=user.username,
                 email=user.email, user_id=user.id)


@router.post("/logout")
def logout(request: Request, token: Optional[str] = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Revoke the presented token by adding its jti to the denylist."""
    if not token:
        return {"message": "No active session"}
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return {"message": "Logged out"}
    jti = payload.get("jti")
    exp = payload.get("exp")
    if jti and not db.query(RevokedToken).filter(RevokedToken.jti == jti).first():
        expires_at = datetime.fromtimestamp(exp, tz=timezone.utc) if exp else datetime.now(timezone.utc)
        db.add(RevokedToken(jti=jti, expires_at=expires_at))
        db.commit()
        clear_otp(db, payload.get("sub", ""))
        audit.record(db, "logout", username=payload.get("sub"), ip=_client_ip(request))
    return {"message": "Logged out"}


# ── Profile ───────────────────────────────────────────────────────────────────
@router.get("/me")
def me(user: User = Depends(require_auth)):
    return {"id": user.id, "username": user.username, "email": user.email, "role": user.role,
            "is_active": user.is_active, "created_at": user.created_at, "last_login": user.last_login}


@router.post("/resend-otp")
def resend_otp(request: Request, data: dict, db: Session = Depends(get_db)):
    """Resend OTP. Rate-limited and does not reveal whether an email exists."""
    ip = _client_ip(request)
    email = (data.get("email") or "").strip()
    generic = {"message": "If this email is registered, a new OTP has been sent"}
    if not email:
        return generic

    ok, _ = rate_limit.hit(db, f"otp_send:{email}", settings.OTP_SEND_MAX, settings.OTP_SEND_WINDOW_SECONDS)
    if not ok:
        # Same generic message — don't leak rate-limit state per email.
        return generic

    user = db.query(User).filter(User.email == email, User.is_active == True).first()
    if user:
        send_otp(db, user.email, user.username)
        audit.record(db, "otp.resend", username=user.username, ip=ip)
    return generic


@router.post("/change-password")
def change_password(request: Request, data: ChangePassword, user: User = Depends(require_auth), db: Session = Depends(get_db)):
    if not verify_password(data.current_password, user.hashed_password):
        audit.record(db, "password.change_failed", user_id=user.id, username=user.username, ip=_client_ip(request), status="fail")
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(data.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")
    user.hashed_password = hash_password(data.new_password)
    db.commit()
    audit.record(db, "password.changed", user_id=user.id, username=user.username, ip=_client_ip(request))
    return {"message": "Password changed successfully"}


# ── Admin: User Management ────────────────────────────────────────────────────
@router.get("/users")
def list_users(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.query(User).order_by(User.created_at.desc()).all()
    return [{"id": u.id, "username": u.username, "email": u.email, "role": u.role,
             "is_active": u.is_active, "created_at": u.created_at, "last_login": u.last_login} for u in users]


@router.post("/users")
def create_user(request: Request, data: UserCreate, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    if data.role not in ("Admin", "Operator", "Checker"):
        raise HTTPException(status_code=400, detail="Role must be Admin, Operator, or Checker")
    if len(data.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    user = User(username=data.username, email=data.email,
                hashed_password=hash_password(data.password), role=data.role)
    db.add(user)
    db.commit()
    db.refresh(user)
    audit.record(db, "user.created", user_id=admin.id, username=admin.username,
                 ip=_client_ip(request), target=user.username, detail={"role": user.role})
    return {"id": user.id, "username": user.username, "email": user.email, "role": user.role,
            "message": f"User created. OTP will be sent to {user.email} on login."}


@router.put("/users/{user_id}/role")
def update_role(request: Request, user_id: int, data: UpdateRole, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot change your own role")
    if data.role not in ("Admin", "Operator", "Checker"):
        raise HTTPException(status_code=400, detail="Invalid role")
    user.role = data.role
    db.commit()
    audit.record(db, "user.role_changed", user_id=admin.id, username=admin.username,
                 ip=_client_ip(request), target=user.username, detail={"role": data.role})
    return {"message": f"Role updated to {data.role}"}


@router.put("/users/{user_id}/toggle")
def toggle_user(request: Request, user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate yourself")
    user.is_active = not user.is_active
    db.commit()
    audit.record(db, "user.toggled", user_id=admin.id, username=admin.username,
                 ip=_client_ip(request), target=user.username, detail={"is_active": user.is_active})
    return {"message": f"User {'activated' if user.is_active else 'deactivated'}"}


@router.delete("/users/{user_id}")
def delete_user(request: Request, user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    uname = user.username
    db.delete(user)
    db.commit()
    audit.record(db, "user.deleted", user_id=admin.id, username=admin.username,
                 ip=_client_ip(request), target=uname)
    return {"message": "User deleted"}


# ── Admin: Audit log access ───────────────────────────────────────────────────
@router.get("/audit")
def get_audit_log(limit: int = 100, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    from app.models.security import AuditLog
    rows = db.query(AuditLog).order_by(AuditLog.ts.desc()).limit(min(limit, 500)).all()
    return [{"id": r.id, "ts": r.ts.isoformat() if r.ts else None, "username": r.username,
             "action": r.action, "target": r.target, "ip": r.ip, "status": r.status} for r in rows]
