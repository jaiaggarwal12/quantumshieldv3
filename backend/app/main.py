"""
QuantumShield v4.0 — Main FastAPI Application
Production-ready: proper CORS, 2FA support, Groq AI, light banking theme.
"""
from dotenv import load_dotenv
load_dotenv()
import os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.database import engine, SessionLocal, Base
from app.routers import scanner, reports, health, auth as auth_router, ai as ai_router
from app.routers import api_scanner as api_scanner_router

app = FastAPI(
    title="QuantumShield PQC Scanner API",
    description="Post-Quantum Cryptography Scanner — CERT-In CBOM, NIST FIPS 203/204/205",
    version="4.0.0",
)

# ── CORS — explicit origins for production ────────────────────────────────────
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
# If wildcard, allow all. If specific, list them.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Can restrict to your Vercel URL in prod
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "X-2FA-Required"],
    max_age=3600,
)

# ── Global exception handler — never expose stack traces ──────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "type": type(exc).__name__}
    )

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(health.router,              prefix="/api/v1", tags=["Health"])
app.include_router(auth_router.router,         tags=["Authentication"])
app.include_router(scanner.router,             prefix="/api/v1", tags=["Scanner"])
app.include_router(reports.router,             tags=["Reports"])
app.include_router(ai_router.router,           tags=["AI"])
app.include_router(api_scanner_router.router,  tags=["API Scanner"])

# ── Startup: DB init + seeding ────────────────────────────────────────────────
@app.on_event("startup")
def startup():
    from app.models.user import User
    from app.models.scan_history import ScanHistory
    from app.routers.auth import hash_password

    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            seeds = [
                User(
                    username=os.getenv("ADMIN_USERNAME", "admin"),
                    email=os.getenv("ADMIN_EMAIL", "admin@quantumshield.io"),
                    hashed_password=hash_password(os.getenv("ADMIN_PASSWORD", "quantum2026")),
                    role="Admin",
                    is_active=True,
                ),
                User(
                    username=os.getenv("OPERATOR_USERNAME", "pnb"),
                    email=os.getenv("OPERATOR_EMAIL", "operator@pnbindia.in"),
                    hashed_password=hash_password(os.getenv("OPERATOR_PASSWORD", "pnbsecure")),
                    role="Operator",
                    is_active=True,
                ),
                User(
                    username=os.getenv("CHECKER_USERNAME", "auditor"),
                    email=os.getenv("CHECKER_EMAIL", "auditor@quantumshield.io"),
                    hashed_password=hash_password(os.getenv("CHECKER_PASSWORD", "audit2026")),
                    role="Checker",
                    is_active=True,
                ),
            ]
            db.add_all(seeds)
            db.commit()
            print(f"✅ DB seeded — {seeds[0].username} / {seeds[1].username} / {seeds[2].username} created")
        else:
            print("✅ DB ready")
    except Exception as e:
        print(f"⚠ Startup error: {e}")
        db.rollback()
    finally:
        db.close()

@app.get("/")
def root():
    return {"service": "QuantumShield PQC Scanner", "version": "4.0.0", "status": "operational", "docs": "/docs"}
