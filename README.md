# QuantumShield — Post-Quantum Cryptography Scanner

NIST FIPS 203 / 204 / 205 · CycloneDX CBOM · active ML-KEM key-exchange detection

QuantumShield scans TLS endpoints, APIs, and VPN ports for post-quantum
readiness. It actively detects ML-KEM/Kyber key exchange via a raw TLS 1.3
handshake probe (something the standard `ssl` module cannot see), inspects
certificates, cross-references known vulnerabilities, and produces a 0–100 PQC
readiness score with a CERT-In-style CBOM.

## Quick Start (Local Dev)

```bash
# Backend
cd backend
python -m venv .venv && . .venv/bin/activate     # (Windows: .venv\Scripts\activate)
pip install -r requirements.txt
cp .env.example .env        # then edit .env — set SECRET_KEY and SMTP creds
alembic upgrade head        # create the schema
uvicorn app.main:app --reload --port 8000

# Frontend
cd frontend && npm install && npm run dev
# → http://localhost:5173   (API docs at http://localhost:8000/docs)
```

## Docker

```bash
cp backend/.env.example .env   # edit secrets, then:
docker compose up -d --build
# Frontend: http://localhost:3000 | Backend: http://localhost:8000/docs
```

## First Login

On first boot, if the users table is empty, three accounts are seeded from your
environment variables (`ADMIN_*`, `OPERATOR_*`, `CHECKER_*` in `.env`). **Set
strong, unique passwords there** — there are no hardcoded default credentials.
Login uses email OTP, so SMTP must be configured for those accounts to sign in.

### Public demo account (no OTP)

For a frictionless showcase, a real, fully-functional `demo` account is created
automatically and its credentials are shown right on the login page. It skips
the email-OTP step (one click to enter) but is **not** a mock — it runs real
scans against the live backend like any other account. Configure it with the
`DEMO_*` variables (`DEMO_ENABLED`, `DEMO_USERNAME`, `DEMO_PASSWORD`,
`DEMO_ROLE`); set `DEMO_ENABLED=false` to disable it entirely.

## AI Assistant

The AI explanations use Google Gemini. Set `GEMINI_API_KEY` (free at
aistudio.google.com). The app tries `GEMINI_MODEL` first and automatically falls
back across other free models on `503`/`429` errors, with retries — so a single
overloaded model won't break the feature. If no model responds, it falls back to
a built-in rule-based engine, so the assistant always answers.

## Configuration

All settings are environment variables — see `backend/.env.example` for the full
list. Key ones:

| Variable | Purpose |
|----------|---------|
| `SECRET_KEY` | JWT signing key (required, use a long random value) |
| `DATABASE_URL` | SQLite (default) or PostgreSQL connection string |
| `ALLOWED_ORIGINS` | CORS allow-list (comma-separated) for production |
| `ALLOW_PRIVATE_TARGETS` | `false` blocks scanning private/internal addresses (SSRF guard) |
| `SMTP_USER` / `SMTP_PASSWORD` | Email OTP delivery (required for login) |
| `GEMINI_API_KEY` | Optional — enables Gemini AI explanations (rule-based fallback otherwise) |

## Security Posture

- Email-OTP login with CSPRNG codes, hashed at rest; per-IP and per-account rate limiting.
- JWT access tokens with `jti` + server-side revocation (logout denylist).
- Role-based access control (Admin / Operator / Checker).
- Append-only audit log of auth, scan, and user-management events (`GET /api/v1/auth/audit`).
- SSRF protection: scan targets resolving to private/loopback/link-local/metadata ranges are rejected by default.
- Security headers on all responses; no scan results are ever fabricated — failed scans report honest errors.

## Testing

```bash
cd backend && pytest -q
```

## Database Migrations

Schema is managed by Alembic.

```bash
cd backend
alembic upgrade head                          # apply migrations
alembic revision --autogenerate -m "change"   # after editing models
```

## Deployment Notes

- Run behind HTTPS (terminate TLS at your proxy/load balancer).
- Set `ALLOWED_ORIGINS` to your real frontend origin(s).
- Use PostgreSQL via `DATABASE_URL` for multi-instance deployments.
- Frontend build arg `VITE_BACKEND_URL` points the SPA at the backend.

## Features

- TLS / certificate / DNS (real CAA, DNSSEC, MX, SPF, DMARC) / HTTP header analysis
- Active post-quantum key-exchange detection (ML-KEM / Kyber hybrids)
- Real OCSP revocation checking
- PQC readiness score (0–100, NIST-aligned)
- CycloneDX CBOM, CSV and CERT-In XML export
- Async batch / API / VPN scans (database-backed jobs)
- JWT auth + RBAC + audit logging + scan history
