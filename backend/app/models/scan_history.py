import json
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.database import Base

class ScanHistory(Base):
    __tablename__ = "scan_history"

    id          = Column(Integer, primary_key=True, index=True)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=False)
    target      = Column(String(256), nullable=False, index=True)
    port        = Column(Integer, default=443)
    pqc_score   = Column(Float, nullable=True)
    pqc_status  = Column(String(32), nullable=True)
    tls_version = Column(String(16), nullable=True)
    cipher_suite = Column(String(128), nullable=True)
    scan_status  = Column(String(32), default="success")
    result_json  = Column(Text, nullable=True)
    created_at   = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="scans")

    def get_result(self):
        return json.loads(self.result_json) if self.result_json else {}
