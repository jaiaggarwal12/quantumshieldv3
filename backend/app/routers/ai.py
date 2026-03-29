"""
QuantumShield — AI Chat Router
Primary: Google Gemini (gemini-2.0-flash — free tier, generous limits)
Fallback: Rule-based engine (always works, no API needed)
No Ollama. No OpenAI dependency.
"""
import json, os, urllib.request, urllib.error
from typing import Optional, List
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from app.models.user import User
from app.routers.auth import get_current_user

router = APIRouter(prefix="/api/v1/ai", tags=["AI"])

GEMINI_KEY   = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
GEMINI_URL   = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"


# ── Schemas ───────────────────────────────────────────────────────────────────
class ChatMessage(BaseModel):
    role: str      # "user" | "assistant"
    content: str

class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    target: Optional[str] = None
    pqc_score: Optional[int] = None
    pqc_status: Optional[str] = None
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    key_exchange: Optional[str] = None
    cert_key_type: Optional[str] = None
    cert_key_bits: Optional[int] = None
    forward_secrecy: Optional[bool] = None
    days_until_expiry: Optional[int] = None
    vulnerabilities: Optional[list] = []

class ExplainRequest(BaseModel):
    target: str
    pqc_score: int
    pqc_status: str
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    key_exchange: Optional[str] = None
    cert_key_type: Optional[str] = None
    cert_key_bits: Optional[int] = None
    forward_secrecy: Optional[bool] = None
    days_until_expiry: Optional[int] = None
    vulnerabilities: Optional[list] = []
    top_issues: Optional[list] = []
    audience: str = "ceo"


# ── System prompt ─────────────────────────────────────────────────────────────
def _system_prompt(ctx: dict = None) -> str:
    base = (
        "You are QuantumShield AI — a post-quantum cryptography expert assistant "
        "built into a security scanner used by Indian banks. You understand NIST FIPS 203 "
        "(ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA). RSA and ECDSA are broken by "
        "Shor's Algorithm on quantum computers. HNDL = Harvest Now Decrypt Later — "
        "adversaries record encrypted traffic today to decrypt when quantum computers arrive. "
        "Python's ssl module cannot detect ML-KEM key exchange (it's in TLS 1.3 extensions). "
        "Be concise, technically accurate, and give exact algorithm names and FIPS numbers. "
        "Keep responses under 200 words unless asked for a detailed report."
    )
    if ctx and ctx.get("target"):
        vulns = ", ".join(v.get("name", "") for v in (ctx.get("vulnerabilities") or [])[:5]) or "none"
        base += (
            f" CURRENT SCAN: {ctx['target']} scored {ctx.get('pqc_score', '?')}/100 "
            f"({ctx.get('pqc_status', '?')}). TLS: {ctx.get('tls_version', '?')}. "
            f"Cert: {ctx.get('cert_key_type', '?')}-{ctx.get('cert_key_bits', '?')}. "
            f"KEX: {ctx.get('key_exchange', '?')}. "
            f"Forward secrecy: {'yes' if ctx.get('forward_secrecy') else 'no'}. "
            f"Cert expires in {ctx.get('days_until_expiry', '?')} days. "
            f"Vulnerabilities: {vulns}. "
            f"Answer questions in the context of this specific scan."
        )
    return base


# ── Gemini API call ───────────────────────────────────────────────────────────
def _gemini(messages: list, system: str) -> Optional[str]:
    """
    Call Google Gemini API.
    Gemini uses 'contents' array with 'parts' — different from OpenAI format.
    System prompt is passed as the first user turn with model ack.
    """
    if not GEMINI_KEY:
        return None

    # Build Gemini contents array
    # Gemini doesn't have a system role — prepend system as first user message
    contents = []

    # System context as first user message + model acknowledgement
    contents.append({
        "role": "user",
        "parts": [{"text": system + "\n\nAcknowledge that you understand your role and are ready to help."}]
    })
    contents.append({
        "role": "model",
        "parts": [{"text": "Understood. I am QuantumShield AI, ready to provide expert post-quantum cryptography guidance based on the scan context provided."}]
    })

    # Add conversation messages — map "assistant" to "model" for Gemini
    for m in messages:
        role = "model" if m["role"] == "assistant" else "user"
        contents.append({"role": role, "parts": [{"text": m["content"]}]})

    payload = json.dumps({
        "contents": contents,
        "generationConfig": {
            "temperature": 0.7,
            "maxOutputTokens": 600,
            "topP": 0.95,
        },
        "safetySettings": [
            {"category": "HARM_CATEGORY_HARASSMENT",        "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH",       "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
        ]
    }).encode("utf-8")

    url = f"{GEMINI_URL}?key={GEMINI_KEY}"
    try:
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=25) as r:
            data = json.loads(r.read().decode("utf-8"))
            # Extract text from response
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    return parts[0].get("text", "").strip()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        # Log but don't crash — fall through to rule-based
        print(f"Gemini HTTP error {e.code}: {body[:200]}")
    except Exception as e:
        print(f"Gemini error: {e}")

    return None


# ── Rule-based fallback ───────────────────────────────────────────────────────
def _rule(msg: str, ctx: dict) -> str:
    m   = msg.lower()
    t   = ctx.get("target", "this site")
    s   = ctx.get("pqc_score", 0)
    cert = f"{ctx.get('cert_key_type','?')}-{ctx.get('cert_key_bits','?')}"
    tls  = ctx.get("tls_version", "?")
    kex  = ctx.get("key_exchange", "?")
    vulns = [v.get("name", "") for v in (ctx.get("vulnerabilities") or [])]
    hndl = "HNDL" in vulns

    if any(w in m for w in ["hndl", "harvest", "record", "decrypt later"]):
        return (
            f"HNDL (Harvest Now Decrypt Later) means nation-state adversaries are already "
            f"recording {t}'s encrypted traffic today. With {cert} and {kex}, all recorded "
            f"sessions become decryptable once quantum computers arrive (~2030–2035). "
            f"Immediate fix: deploy ML-KEM-768 (FIPS 203) hybrid key exchange."
        )
    if any(w in m for w in ["score", "why", "rating", "how much", "63", "50", "79", str(s)]):
        return (
            f"{t} scored {s}/100. Main deductions: "
            f"{cert} certificate (quantum-vulnerable via Shor's Algorithm, ~-20pts), "
            f"{tls} protocol ({'-8pts' if '1.2' in tls else 'no penalty for TLS 1.3'}), "
            f"non-PQC key exchange (-8pts). "
            f"To improve: enforce TLS 1.3, deploy ML-KEM-768 KEX, replace cert with ML-DSA-65."
        )
    if any(w in m for w in ["fix", "action", "migrate", "remediat", "step", "how to"]):
        return (
            f"Priority actions for {t} ({s}/100):\n"
            f"1. [Now] Enforce TLS 1.3, add HSTS header\n"
            f"2. [3 months] Deploy X25519+ML-KEM-768 hybrid key exchange (FIPS 203)\n"
            f"3. [12 months] Replace {cert} certificate with ML-DSA-65 (FIPS 204)\n"
            f"4. [Ongoing] Re-scan quarterly with QuantumShield to track progress"
        )
    if any(w in m for w in ["ml-kem", "ml-dsa", "slh-dsa", "fips 203", "fips 204", "fips 205"]):
        return (
            "NIST PQC Standards (finalised August 2024):\n"
            "• ML-KEM (FIPS 203) — replaces RSA/ECDH key exchange. Use ML-KEM-768 (Level 3).\n"
            "• ML-DSA (FIPS 204) — replaces RSA/ECDSA certificates. Use ML-DSA-65 (Level 3).\n"
            "• SLH-DSA (FIPS 205) — hash-based signature, conservative ML-DSA alternative.\n"
            "All three are based on problems believed hard for quantum computers."
        )
    if any(w in m for w in ["oqs", "detect", "python ssl", "ml-kem detect", "quantum safe"]):
        return (
            "Python's ssl module cannot detect ML-KEM key exchange — it's negotiated in "
            "TLS 1.3 ClientHello extensions, not visible in the cipher suite string. "
            "QuantumShield detects it via cipher name pattern matching (works for Cloudflare "
            "X25519+Kyber768). For definitive detection: use OQS-OpenSSL or Wireshark."
        )
    if any(w in m for w in ["rsa", "ecdsa", "certificate", "cert"]):
        return (
            f"{t} uses a {cert} certificate. "
            f"{'RSA' if 'RSA' in cert else 'ECDSA'} is broken by Shor's Algorithm "
            f"regardless of key size — RSA-4096 is equally vulnerable as RSA-2048 against "
            f"a quantum computer. Migration: obtain an ML-DSA-65 certificate from a "
            f"PQC-ready Certificate Authority."
        )
    if any(w in m for w in ["tls", "protocol", "version"]):
        is12 = "1.2" in tls
        return (
            f"{t} uses {tls}. "
            + (
                "TLS 1.2 allows weaker cipher negotiation and is more exposed to HNDL attacks. "
                "Upgrade to TLS 1.3 — it mandates forward secrecy and removes all broken cipher suites."
                if is12 else
                f"TLS 1.3 is the current standard — good. The remaining gap is {kex}, "
                "which is still quantum-vulnerable and needs ML-KEM-768."
            )
        )

    # Generic response
    return (
        f"{t} scored {s}/100 ({ctx.get('pqc_status', 'UNKNOWN')}). "
        f"Running {tls} with {cert} certificate and {kex}. "
        f"{'⚠️ HNDL risk — traffic being recorded now. ' if hndl else ''}"
        f"Ask me about: HNDL risk, why it scored this way, how to fix it, "
        f"ML-KEM/ML-DSA migration, or what any crypto term means."
    )


def _rule_explain(req: ExplainRequest) -> str:
    cert = f"{req.cert_key_type}-{req.cert_key_bits}"
    hndl = any(v.get("name") == "HNDL" for v in (req.vulnerabilities or []))
    s    = req.pqc_score

    if req.audience == "ceo":
        return (
            f"Your website {req.target} scored {s}/100 on our Post-Quantum Cryptography assessment. "
            f"Think of it like a padlock — {cert} encryption is unbreakable today, but a quantum "
            f"computer would crack it in hours using Shor's Algorithm. "
            + (
                f"More urgently, adversaries are likely already recording your encrypted bank traffic "
                f"right now, waiting for quantum computers to decrypt it later — this is called "
                f"Harvest Now, Decrypt Later. "
                if hndl else ""
            ) +
            f"We recommend a 12–18 month migration to NIST-standardised algorithms (ML-KEM + ML-DSA), "
            f"with dedicated budget and CISO ownership."
        )
    elif req.audience == "board":
        risk = "critical" if s < 50 else "moderate"
        hndl_note = "HNDL risk confirmed — traffic being recorded now for future decryption.\n\n" if hndl else "\n\n"
        return (
            f"EXECUTIVE RISK SUMMARY\n{req.target} scores {s}/100 — {risk} quantum risk requiring board action.\n\n"
            f"THREAT LANDSCAPE\nQuantum computers (est. 2030–2035) will break {cert} encryption in hours. {hndl_note}"
            f"REGULATORY EXPOSURE\nRBI Cybersecurity Framework, CERT-In guidelines, and DPDP Act 2023 "
            f"require adequate cryptographic controls. Non-compliance post-2026 creates audit liability.\n\n"
            f"FINANCIAL IMPACT\nCost of migration: 12–24 months engineering effort. "
            f"Cost of inaction: decryption of all historical encrypted communications.\n\n"
            f"BOARD RESOLUTION REQUIRED\nApprove PQC migration programme. Assign CISO ownership. "
            f"Mandate quarterly QuantumShield readiness reporting."
        )
    else:  # technical
        return (
            f"FINDINGS: {req.tls_version} | {req.cipher_suite} | {cert} | {req.pqc_score}/100\n\n"
            f"ROOT CAUSE: {cert} is broken by Shor's Algorithm in O(n³) polynomial time. "
            f"Key size is irrelevant — RSA-4096 = RSA-2048 quantumly. "
            f"Key exchange ({req.key_exchange}) is also quantum-vulnerable via discrete log problem.\n\n"
            f"REMEDIATION (priority order):\n"
            f"1. [0–30 days] Enforce TLS 1.3, disable TLS 1.0/1.1/1.2\n"
            f"2. [0–30 days] Deploy X25519+ML-KEM-768 hybrid KEX (RFC 9180 + FIPS 203)\n"
            f"3. [3–6 months] Replace {cert} cert with ML-DSA-65 (FIPS 204) from PQC-ready CA\n"
            f"4. [12–24 months] Full NIST SP 800-208 compliance across all endpoints\n\n"
            f"TIMELINE: HNDL threat is active today — start steps 1–2 immediately."
        )


# ── Endpoints ─────────────────────────────────────────────────────────────────
@router.post("/chat")
async def chat(req: ChatRequest, _: Optional[User] = Depends(get_current_user)):
    """Conversational AI chat. Gemini primary, rule-based fallback."""
    ctx = {k: getattr(req, k, None) for k in [
        "target", "pqc_score", "pqc_status", "tls_version", "cipher_suite",
        "key_exchange", "cert_key_type", "cert_key_bits", "forward_secrecy",
        "days_until_expiry", "vulnerabilities"
    ]}
    system = _system_prompt(ctx)
    msgs = [{"role": m.role, "content": m.content} for m in req.messages]

    resp = _gemini(msgs, system)
    src  = "gemini"

    if not resp:
        last = next((m["content"] for m in reversed(msgs) if m["role"] == "user"), "")
        resp = _rule(last, ctx)
        src  = "rule-based"

    return {"response": resp, "source": src, "model": GEMINI_MODEL if src == "gemini" else None}


@router.post("/explain")
async def explain(req: ExplainRequest, _: Optional[User] = Depends(get_current_user)):
    """One-shot explanation for CEO / Board / Technical audience."""
    cert = f"{req.cert_key_type}-{req.cert_key_bits}"
    hndl = any(v.get("name") == "HNDL" for v in (req.vulnerabilities or []))

    audience_prompts = {
        "ceo": (
            f"Write a 3-paragraph CEO briefing — plain English only, no jargon, no bullet points.\n"
            f"Para 1: {req.target} scored {req.pqc_score}/100. Use a padlock analogy for {cert} encryption.\n"
            f"Para 2: {'HNDL — explain adversaries are recording encrypted bank traffic TODAY to decrypt when quantum computers arrive in ~2030.' if hndl else f'Why {req.pqc_score}/100 is a risk for a bank.'}\n"
            f"Para 3: 2–3 specific business actions with timeline. Tone: calm, trusted advisor."
        ),
        "board": (
            f"Write a formal CISO board briefing for {req.target} (score {req.pqc_score}/100, {cert}, {req.tls_version}).\n"
            f"Use exactly these section headers: EXECUTIVE RISK SUMMARY / THREAT LANDSCAPE / "
            f"REGULATORY EXPOSURE (mention RBI Framework, DPDP Act 2023, CERT-In) / "
            f"FINANCIAL IMPACT / BOARD RESOLUTION REQUIRED.\n"
            f"2–3 sentences per section. Formal governance tone."
        ),
        "technical": (
            f"Write a technical security briefing. Be precise and terse.\n"
            f"FINDINGS: TLS={req.tls_version} | Cipher={req.cipher_suite} | KEX={req.key_exchange} | Cert={cert} | Score={req.pqc_score}/100\n"
            f"Include sections: ROOT CAUSE (explain Shor's Algorithm vs Grover's, why key size doesn't matter) | "
            f"REMEDIATION (exact FIPS names and config steps, priority order) | "
            f"TIMELINE (0–30 days / 3–6 months / 12–24 months)"
        )
    }

    prompt = audience_prompts.get(req.audience, audience_prompts["ceo"])
    system = _system_prompt()
    msgs   = [{"role": "user", "content": prompt}]

    resp = _gemini(msgs, system)
    src  = "gemini"

    if not resp:
        resp = _rule_explain(req)
        src  = "rule-based"

    return {"explanation": resp, "source": src, "model": GEMINI_MODEL if src == "gemini" else None}


@router.get("/status")
async def ai_status():
    """Check which AI backend is live."""
    gemini_ok = False
    if GEMINI_KEY:
        try:
            # Quick test call with minimal tokens
            test_payload = json.dumps({
                "contents": [{"role": "user", "parts": [{"text": "ping"}]}],
                "generationConfig": {"maxOutputTokens": 5}
            }).encode()
            req = urllib.request.Request(
                f"{GEMINI_URL}?key={GEMINI_KEY}",
                data=test_payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                gemini_ok = r.status == 200
        except Exception:
            pass

    return {
        "gemini": {
            "available": gemini_ok,
            "model": GEMINI_MODEL,
            "key_configured": bool(GEMINI_KEY)
        },
        "fallback": {
            "available": True,
            "type": "rule-based (always works)"
        },
        "active": "gemini" if gemini_ok else "rule-based"
    }
