"""
QuantumShield — Main FastAPI Application
"""
from dotenv import load_dotenv
load_dotenv()

import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.core.config import settings
from app.core.logging_config import setup_logging, get_logger
from app.database import engine, SessionLocal, Base

setup_logging()
logger = get_logger("quantumshield.main")

from app.routers import scanner, reports, health, auth as auth_router, ai as ai_router
from app.routers import api_scanner as api_scanner_router


# ── Startup: DB init + seeding ────────────────────────────────────────────────
def _seed_database():
    # Import every model so create_all registers all tables.
    from app.models.user import User
    from app.models.scan_history import ScanHistory          # noqa: F401
    from app.models.scan_job import ScanJob                  # noqa: F401
    from app.models import security as _security_models      # noqa: F401
    from app.routers.auth import hash_password
    import os

    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            seeds = [
                User(username=os.getenv("ADMIN_USERNAME", "admin"),
                     email=os.getenv("ADMIN_EMAIL", "admin@quantumshield.io"),
                     hashed_password=hash_password(os.getenv("ADMIN_PASSWORD", "quantum2026")),
                     role="Admin", is_active=True),
                User(username=os.getenv("OPERATOR_USERNAME", "operator"),
                     email=os.getenv("OPERATOR_EMAIL", "operator@quantumshield.io"),
                     hashed_password=hash_password(os.getenv("OPERATOR_PASSWORD", "operator12345")),
                     role="Operator", is_active=True),
                User(username=os.getenv("CHECKER_USERNAME", "auditor"),
                     email=os.getenv("CHECKER_EMAIL", "auditor@quantumshield.io"),
                     hashed_password=hash_password(os.getenv("CHECKER_PASSWORD", "audit2026")),
                     role="Checker", is_active=True),
            ]
            db.add_all(seeds)
            db.commit()
            logger.info("DB seeded with %d initial users", len(seeds))
        else:
            logger.info("DB ready")

        # Ensure the public demo account exists (idempotent — runs every boot).
        if settings.DEMO_ENABLED:
            demo = db.query(User).filter(User.username == settings.DEMO_USERNAME).first()
            if demo is None:
                db.add(User(
                    username=settings.DEMO_USERNAME,
                    email=settings.DEMO_EMAIL,
                    hashed_password=hash_password(settings.DEMO_PASSWORD),
                    role=settings.DEMO_ROLE,
                    is_active=True,
                ))
                db.commit()
                logger.info("Demo account ensured: %s (role=%s)", settings.DEMO_USERNAME, settings.DEMO_ROLE)
    except Exception as e:
        logger.error("Startup seeding error: %s", e)
        db.rollback()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.warn_on_insecure()
    _seed_database()
    yield


app = FastAPI(
    title="QuantumShield PQC Scanner API",
    description="Post-Quantum Cryptography Scanner — CERT-In CBOM, NIST FIPS 203/204/205",
    version=__version__,
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# Wildcard origin cannot be combined with credentials (CORS spec). The frontend
# uses Bearer tokens, so credentials aren't needed in the wildcard case.
_wildcard_origins = settings.ALLOWED_ORIGINS == ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=not _wildcard_origins,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "X-2FA-Required"],
    max_age=3600,
)


# ── Security headers on our own responses + request logging ───────────────────
@app.middleware("http")
async def security_and_logging(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = (time.perf_counter() - start) * 1000

    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    # HSTS only meaningful over HTTPS; harmless otherwise and expected by scanners.
    response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

    logger.info("%s %s -> %s (%.1fms)", request.method, request.url.path,
                response.status_code, duration_ms)
    return response


# ── Global exception handler — log full trace, return generic message ─────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(health.router,              prefix="/api/v1", tags=["Health"])
app.include_router(auth_router.router,         tags=["Authentication"])
app.include_router(scanner.router,             prefix="/api/v1", tags=["Scanner"])
app.include_router(reports.router,             tags=["Reports"])
app.include_router(ai_router.router,           tags=["AI"])
app.include_router(api_scanner_router.router,  tags=["API Scanner"])


@app.get("/")
def root():
    return {"service": "QuantumShield PQC Scanner", "version": __version__,
            "status": "operational", "docs": "/docs"}
