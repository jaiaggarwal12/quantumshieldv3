# QuantumShield v3.0 — Post-Quantum Cryptography Scanner

PNB/PSB Cybersecurity Hackathon 2025-26 | NIST FIPS 203/204/205

## Quick Start (Local Dev)

```bash
# Backend
cd backend && pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Frontend
cd frontend && npm install && npm run dev
# → http://localhost:5173
```

## Docker
```bash
docker compose up -d
# Frontend: http://localhost:3000 | Backend: http://localhost:8000/docs
```

## Default Login Credentials
| Username | Password     | Role     |
|----------|-------------|----------|
| admin    | quantum2026 | Admin    |
| pnb      | pnbsecure   | Operator |
| auditor  | audit2026   | Checker  |

Change ADMIN_PASSWORD via environment variable in production.

## Environment Variables (Backend)
- `SECRET_KEY` — JWT signing key (CHANGE IN PRODUCTION)
- `ADMIN_PASSWORD` — Default admin password (CHANGE IN PRODUCTION)
- `DATABASE_URL` — SQLite (default) or PostgreSQL URL
- `TOKEN_EXPIRE_MINUTES` — JWT expiry (default 480 = 8 hours)

## Environment Variables (Frontend)
- `VITE_BACKEND_URL` — Backend URL (set in Vercel/Render dashboard)

## Deployment

### Backend → Render
- Build: `pip install -r requirements.txt`
- Start: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- Root: `backend`

### Frontend → Vercel
- Root: `frontend`
- Build: `npm run build`
- Output: `dist`
- Env: `VITE_BACKEND_URL=https://your-backend.onrender.com`

### Keep Backend Awake (Free Render Tier)
→ uptimerobot.com → New Monitor → HTTP → https://your-backend.onrender.com/api/v1/health → every 5 minutes

## Features
- 40+ parameter TLS/certificate/DNS/HTTP analysis
- PQC score 0–100 (NIST-aligned)
- CycloneDX v1.4 CBOM export
- 12-CVE vulnerability database
- JWT auth + RBAC (Admin/Operator/Checker)
- Scan history persisted to SQLite/PostgreSQL
- User management (Admin panel)
