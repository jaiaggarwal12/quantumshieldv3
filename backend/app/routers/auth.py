"""
QuantumShield — Authentication Router
Flow:
  1. POST /login  → validates password → sends 6-digit OTP to user's email
  2. POST /verify-otp → validates OTP → returns JWT token
  3. All protected routes use JWT Bearer token

Admin can create users with username + email + password + role.
OTP is sent to the registered email on every login.
"""
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.services.email_service import send_otp, verify_otp

SECRET_KEY           = os.getenv("SECRET_KEY", "qs-super-secret-2026-change-in-production")
ALGORITHM            = "HS256"
TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MINUTES", "480"))

pwd_context   = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)
router        = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


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

class UserResponse(BaseModel):
    id:         int
    username:   str
    email:      str
    role:       str
    is_active:  bool
    created_at: datetime
    last_login: Optional[datetime]

    class Config:
        from_attributes = True

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
    exp = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    return jwt.encode({**data, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)


# ── Dependencies ──────────────────────────────────────────────────────────────
def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """Returns User or None — does NOT raise 401."""
    if not token:
        return None
    try:
        payload  = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            return None
    except JWTError:
        return None
    return db.query(User).filter(User.username == username, User.is_active == True).first()


def require_auth(user: Optional[User] = Depends(get_current_user)) -> User:
    """Raises 401 if not logged in."""
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
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Step 1 of login.
    Validates username + password.
    If correct, sends 6-digit OTP to the user's registered email.
    Client must then call /verify-otp with the code to get the JWT token.
    """
    user = db.query(User).filter(
        User.username == form.username,
        User.is_active == True
    ).first()

    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    # Send OTP via SMTP
    result = send_otp(user.email, user.username)

    if not result.get("sent"):
        raise HTTPException(
            status_code=500,
            detail=result.get("error", "Could not send OTP email. Please check SMTP configuration."),
        )

    return {
        "message": f"OTP sent to {user.email}",
        "email":   user.email,
        "username": user.username,
        "otp_required": True,
    }


# ── Step 2: OTP verification → return JWT ────────────────────────────────────
@router.post("/verify-otp", response_model=Token)
def verify_otp_and_login(data: OTPRequest, db: Session = Depends(get_db)):
    """
    Step 2 of login.
    Verifies the 6-digit OTP sent to the user's email.
    On success, returns a JWT access token.
    """
    result = verify_otp(data.email, data.otp)
    if not result["valid"]:
        raise HTTPException(status_code=400, detail=result["reason"])

    user = db.query(User).filter(User.email == data.email, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.last_login = datetime.now(timezone.utc)
    db.commit()

    token = create_access_token({"sub": user.username, "role": user.role})
    return Token(
        access_token=token,
        role=user.role,
        username=user.username,
        email=user.email,
        user_id=user.id,
    )


# ── Profile & token ───────────────────────────────────────────────────────────
@router.get("/me")
def me(user: User = Depends(require_auth)):
    return {
        "id":       user.id,
        "username": user.username,
        "email":    user.email,
        "role":     user.role,
        "is_active": user.is_active,
        "created_at": user.created_at,
        "last_login": user.last_login,
    }


@router.post("/resend-otp")
def resend_otp(data: dict, db: Session = Depends(get_db)):
    """Resend OTP to given email."""
    email = data.get("email", "")
    user  = db.query(User).filter(User.email == email, User.is_active == True).first()
    if not user:
        # Don't reveal whether email exists
        return {"message": "If this email is registered, a new OTP has been sent"}
    result = send_otp(user.email, user.username)
    return {"message": f"New OTP sent to {user.email}"}


@router.post("/change-password")
def change_password(
    data: ChangePassword,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    if not verify_password(data.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(data.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")
    user.hashed_password = hash_password(data.new_password)
    db.commit()
    return {"message": "Password changed successfully"}


# ── Admin: User Management ────────────────────────────────────────────────────
@router.get("/users")
def list_users(
    _: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    users = db.query(User).order_by(User.created_at.desc()).all()
    return [
        {"id": u.id, "username": u.username, "email": u.email, "role": u.role,
         "is_active": u.is_active, "created_at": u.created_at, "last_login": u.last_login}
        for u in users
    ]


@router.post("/users")
def create_user(
    data: UserCreate,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Admin creates a new user with email. OTP will be sent to that email on login."""
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    if data.role not in ("Admin", "Operator", "Checker"):
        raise HTTPException(status_code=400, detail="Role must be Admin, Operator, or Checker")
    if len(data.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    user = User(
        username=data.username,
        email=data.email,
        hashed_password=hash_password(data.password),
        role=data.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {
        "id":       user.id,
        "username": user.username,
        "email":    user.email,
        "role":     user.role,
        "message":  f"User created. OTP will be sent to {user.email} on login.",
    }


@router.put("/users/{user_id}/role")
def update_role(
    user_id: int,
    data: UpdateRole,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot change your own role")
    if data.role not in ("Admin", "Operator", "Checker"):
        raise HTTPException(status_code=400, detail="Invalid role")
    user.role = data.role
    db.commit()
    return {"message": f"Role updated to {data.role}"}


@router.put("/users/{user_id}/toggle")
def toggle_user(
    user_id: int,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate yourself")
    user.is_active = not user.is_active
    db.commit()
    return {"message": f"User {'activated' if user.is_active else 'deactivated'}"}


@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    db.delete(user)
    db.commit()
    return {"message": "User deleted"}
