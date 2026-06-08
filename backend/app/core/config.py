"""
QuantumShield — Centralised configuration.

All tunables are read from the environment once, here, so the rest of the code
imports typed values instead of scattering os.getenv calls. Insecure defaults
emit a loud warning at startup rather than silently shipping to production.
"""
import os
import logging

logger = logging.getLogger("quantumshield.config")

_INSECURE_SECRET = "qs-super-secret-change-this-in-production"


def _get_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


class Settings:
    def __init__(self) -> None:
        # ── Security ───────────────────────────────────────────────────────────
        self.SECRET_KEY = os.getenv("SECRET_KEY", _INSECURE_SECRET)
        self.ALGORITHM = "HS256"
        self.TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MINUTES", "480"))

        # ── Database ───────────────────────────────────────────────────────────
        self.DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./quantumshield.db")

        # ── CORS ───────────────────────────────────────────────────────────────
        self.ALLOWED_ORIGINS = [
            o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",") if o.strip()
        ]

        # ── Scan target policy (SSRF protection) ────────────────────────────────
        # When False (default), targets resolving to private / loopback / link-local
        # / reserved / cloud-metadata addresses are rejected. Set True only for
        # trusted internal deployments scanning your own infrastructure.
        self.ALLOW_PRIVATE_TARGETS = _get_bool("ALLOW_PRIVATE_TARGETS", False)
        self.MAX_TARGETS_PER_SCAN = int(os.getenv("MAX_TARGETS_PER_SCAN", "20"))

        # ── Rate limiting (per identifier, sliding window) ──────────────────────
        self.LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "10"))
        self.LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "300"))
        self.OTP_SEND_MAX = int(os.getenv("OTP_SEND_MAX", "5"))
        self.OTP_SEND_WINDOW_SECONDS = int(os.getenv("OTP_SEND_WINDOW_SECONDS", "600"))

        # ── OTP ─────────────────────────────────────────────────────────────────
        self.OTP_EXPIRY_MINUTES = int(os.getenv("OTP_EXPIRY_MINUTES", "10"))
        self.OTP_MAX_ATTEMPTS = int(os.getenv("OTP_MAX_ATTEMPTS", "5"))

        # ── SMTP ────────────────────────────────────────────────────────────────
        self.SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
        self.SMTP_USER = os.getenv("SMTP_USER", "")
        self.SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
        self.FROM_NAME = os.getenv("FROM_NAME", "QuantumShield Security")

        # ── Public demo account ─────────────────────────────────────────────────
        # A real, fully-functional account that skips the email-OTP step so the
        # deployed app can be tried instantly. Its credentials are shown on the
        # login page. It is NOT a mock — it hits the real backend like any user.
        self.DEMO_ENABLED = _get_bool("DEMO_ENABLED", True)
        self.DEMO_USERNAME = os.getenv("DEMO_USERNAME", "demo")
        self.DEMO_PASSWORD = os.getenv("DEMO_PASSWORD", "demo12345")
        self.DEMO_EMAIL = os.getenv("DEMO_EMAIL", "demo@quantumshield.app")
        self.DEMO_ROLE = os.getenv("DEMO_ROLE", "Operator")

    @property
    def secret_is_insecure(self) -> bool:
        return self.SECRET_KEY == _INSECURE_SECRET or len(self.SECRET_KEY) < 16

    def warn_on_insecure(self) -> None:
        if self.secret_is_insecure:
            logger.warning(
                "SECRET_KEY is using an insecure default or is too short. "
                "Set a strong random SECRET_KEY (>= 32 chars) before production."
            )
        if not self.SMTP_USER or not self.SMTP_PASSWORD:
            logger.warning("SMTP is not configured — email OTP login will fail until SMTP_USER/SMTP_PASSWORD are set.")
        if self.ALLOW_PRIVATE_TARGETS:
            logger.warning("ALLOW_PRIVATE_TARGETS is enabled — the scanner may reach internal/private addresses (SSRF risk).")


settings = Settings()
