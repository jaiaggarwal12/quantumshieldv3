from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id                = Column(Integer, primary_key=True, index=True)
    username          = Column(String(64), unique=True, index=True, nullable=False)
    email             = Column(String(128), unique=True, index=True, nullable=False)
    hashed_password   = Column(String(256), nullable=False)
    role              = Column(String(32), default="Operator")  # Admin | Operator | Checker
    is_active         = Column(Boolean, default=True)
    created_at        = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_login        = Column(DateTime, nullable=True)
    # 2FA fields
    totp_secret       = Column(String(64), nullable=True)   # None = 2FA not enabled
    totp_enabled      = Column(Boolean, default=False)

    scans = relationship("ScanHistory", back_populates="user", cascade="all, delete-orphan")
