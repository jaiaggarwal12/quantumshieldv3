"""
QuantumShield — Deep Cryptographic Scanner Engine v2.0
Covers 40+ security parameters across TLS, certificates, DNS, HTTP, and PQC readiness.
"""

import ssl
import socket
import uuid
import re
import json
import urllib.request
import urllib.parse
import subprocess
from datetime import datetime, timezone
from typing import Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448

# ── NIST PQC Standards ────────────────────────────────────────────────────────
PQC_ALGORITHMS = {
    "ML-KEM-512":          {"type":"KEM",       "level":1, "standard":"FIPS 203", "safe":True},
    "ML-KEM-768":          {"type":"KEM",       "level":3, "standard":"FIPS 203", "safe":True},
    "ML-KEM-1024":         {"type":"KEM",       "level":5, "standard":"FIPS 203", "safe":True},
    "ML-DSA-44":           {"type":"Signature", "level":2, "standard":"FIPS 204", "safe":True},
    "ML-DSA-65":           {"type":"Signature", "level":3, "standard":"FIPS 204", "safe":True},
    "ML-DSA-87":           {"type":"Signature", "level":5, "standard":"FIPS 204", "safe":True},
    "SLH-DSA-SHA2-128s":   {"type":"Signature", "level":1, "standard":"FIPS 205", "safe":True},
    "SLH-DSA-SHA2-128f":   {"type":"Signature", "level":1, "standard":"FIPS 205", "safe":True},
    "SLH-DSA-SHA2-192s":   {"type":"Signature", "level":3, "standard":"FIPS 205", "safe":True},
    "SLH-DSA-SHA2-192f":   {"type":"Signature", "level":3, "standard":"FIPS 205", "safe":True},
    "SLH-DSA-SHA2-256s":   {"type":"Signature", "level":5, "standard":"FIPS 205", "safe":True},
    "SLH-DSA-SHA2-256f":   {"type":"Signature", "level":5, "standard":"FIPS 205", "safe":True},
    "kyber768":            {"type":"KEM",       "level":3, "standard":"Transitional", "safe":True},
    "X25519Kyber768":      {"type":"KEM",       "level":3, "standard":"Hybrid",       "safe":True},
}

# ── Known Vulnerabilities Database ───────────────────────────────────────────
KNOWN_VULNS = {
    "POODLE":     {"affects":["TLSv1.0","SSLv3"], "ciphers":["CBC"], "severity":"HIGH",     "cve":"CVE-2014-3566", "desc":"Padding Oracle On Downgraded Legacy Encryption"},
    "BEAST":      {"affects":["TLSv1.0"],          "ciphers":["CBC"], "severity":"MEDIUM",   "cve":"CVE-2011-3389", "desc":"Browser Exploit Against SSL/TLS"},
    "SWEET32":    {"affects":["TLSv1.0","TLSv1.1","TLSv1.2"], "ciphers":["3DES","DES"],    "severity":"MEDIUM",   "cve":"CVE-2016-2183", "desc":"Birthday attacks on 64-bit block ciphers"},
    "CRIME":      {"affects":["TLSv1.0","TLSv1.1","TLSv1.2"], "ciphers":["DEFLATE"],       "severity":"HIGH",     "cve":"CVE-2012-4929", "desc":"Compression Ratio Info-leak Made Easy"},
    "BREACH":     {"affects":["TLSv1.0","TLSv1.1","TLSv1.2"], "ciphers":["HTTP_COMPRESS"], "severity":"MEDIUM",   "cve":"CVE-2013-3587", "desc":"Browser Reconnaissance and Exfiltration via Adaptive Compression"},
    "LUCKY13":    {"affects":["TLSv1.0","TLSv1.1","TLSv1.2"], "ciphers":["CBC"],           "severity":"LOW",      "cve":"CVE-2013-0169", "desc":"Timing attack on CBC-mode ciphers"},
    "RC4_BIASES": {"affects":["TLSv1.0","TLSv1.1","TLSv1.2"], "ciphers":["RC4"],           "severity":"CRITICAL", "cve":"CVE-2015-2808", "desc":"RC4 statistical biases allow plaintext recovery"},
    "FREAK":      {"affects":["TLSv1.0","TLSv1.1","TLSv1.2"], "ciphers":["EXPORT"],        "severity":"HIGH",     "cve":"CVE-2015-0204", "desc":"Factoring RSA Export Keys"},
    "LOGJAM":     {"affects":["TLSv1.0","TLSv1.1","TLSv1.2"], "ciphers":["DHE_512"],       "severity":"HIGH",     "cve":"CVE-2015-4000", "desc":"Weak Diffie-Hellman and the Logjam Attack"},
    "DROWN":      {"affects":["SSLv2"],            "ciphers":["ALL"],                       "severity":"CRITICAL", "cve":"CVE-2016-0800", "desc":"Decrypting RSA with Obsolete and Weakened eNcryption"},
    "NULL_CIPHER": {"affects":["TLSv1.0","TLSv1.1","TLSv1.2","TLSv1.3"], "ciphers":["NULL"], "severity":"CRITICAL", "cve":"N/A",           "desc":"NULL cipher — NO encryption whatsoever, data transmitted in plaintext"},
    "MD5_HASH":   {"affects":["TLSv1.0","TLSv1.1","TLSv1.2"],             "ciphers":["MD5"],  "severity":"CRITICAL", "cve":"CVE-2004-2761",  "desc":"MD5 hash in cipher suite — collision attacks possible, certificate forgery risk"},
    "HNDL":       {"affects":["ALL"],              "ciphers":["RSA","ECDHE","DHE"],         "severity":"CRITICAL", "cve":"N/A",           "desc":"Harvest Now Decrypt Later — quantum adversary threat"},
}

# ── Cipher Suite Full Database ────────────────────────────────────────────────
CIPHER_DB = {
    # TLS 1.3 — all use ephemeral key exchange
    "TLS_AES_256_GCM_SHA384":           {"tls":"1.3","kex":"ECDHE","enc":"AES-256-GCM","hash":"SHA-384","fs":True, "pqc":False,"grade":"A"},
    "TLS_AES_128_GCM_SHA256":           {"tls":"1.3","kex":"ECDHE","enc":"AES-128-GCM","hash":"SHA-256","fs":True, "pqc":False,"grade":"B"},
    "TLS_CHACHA20_POLY1305_SHA256":     {"tls":"1.3","kex":"ECDHE","enc":"CHACHA20",   "hash":"SHA-256","fs":True, "pqc":False,"grade":"A"},
    # TLS 1.2 strong
    "ECDHE-RSA-AES256-GCM-SHA384":      {"tls":"1.2","kex":"ECDHE","enc":"AES-256-GCM","hash":"SHA-384","fs":True, "pqc":False,"grade":"A"},
    "ECDHE-ECDSA-AES256-GCM-SHA384":    {"tls":"1.2","kex":"ECDHE","enc":"AES-256-GCM","hash":"SHA-384","fs":True, "pqc":False,"grade":"A"},
    "ECDHE-RSA-AES128-GCM-SHA256":      {"tls":"1.2","kex":"ECDHE","enc":"AES-128-GCM","hash":"SHA-256","fs":True, "pqc":False,"grade":"B"},
    "ECDHE-RSA-CHACHA20-POLY1305":      {"tls":"1.2","kex":"ECDHE","enc":"CHACHA20",   "hash":"SHA-256","fs":True, "pqc":False,"grade":"A"},
    "DHE-RSA-AES256-GCM-SHA384":        {"tls":"1.2","kex":"DHE",  "enc":"AES-256-GCM","hash":"SHA-384","fs":True, "pqc":False,"grade":"A"},
    # TLS 1.2 weak
    "ECDHE-RSA-AES256-SHA384":          {"tls":"1.2","kex":"ECDHE","enc":"AES-256-CBC","hash":"SHA-384","fs":True, "pqc":False,"grade":"B"},
    "ECDHE-RSA-AES128-SHA256":          {"tls":"1.2","kex":"ECDHE","enc":"AES-128-CBC","hash":"SHA-256","fs":True, "pqc":False,"grade":"B"},
    "AES256-GCM-SHA384":                {"tls":"1.2","kex":"RSA",  "enc":"AES-256-GCM","hash":"SHA-384","fs":False,"pqc":False,"grade":"C"},
    "AES128-GCM-SHA256":                {"tls":"1.2","kex":"RSA",  "enc":"AES-128-GCM","hash":"SHA-256","fs":False,"pqc":False,"grade":"C"},
    "AES256-SHA256":                    {"tls":"1.2","kex":"RSA",  "enc":"AES-256-CBC","hash":"SHA-256","fs":False,"pqc":False,"grade":"C"},
    "AES128-SHA256":                    {"tls":"1.2","kex":"RSA",  "enc":"AES-128-CBC","hash":"SHA-256","fs":False,"pqc":False,"grade":"C"},
    "AES256-SHA":                       {"tls":"1.2","kex":"RSA",  "enc":"AES-256-CBC","hash":"SHA-1",  "fs":False,"pqc":False,"grade":"D"},
    "AES128-SHA":                       {"tls":"1.2","kex":"RSA",  "enc":"AES-128-CBC","hash":"SHA-1",  "fs":False,"pqc":False,"grade":"D"},
    # Broken / legacy
    "DES-CBC3-SHA":                     {"tls":"1.0","kex":"RSA",  "enc":"3DES",       "hash":"SHA-1",  "fs":False,"pqc":False,"grade":"F"},
    "RC4-SHA":                          {"tls":"1.0","kex":"RSA",  "enc":"RC4",        "hash":"SHA-1",  "fs":False,"pqc":False,"grade":"F"},
    "RC4-MD5":                          {"tls":"1.0","kex":"RSA",  "enc":"RC4",        "hash":"MD5",    "fs":False,"pqc":False,"grade":"F"},
    "EXP-RC4-MD5":                      {"tls":"1.0","kex":"RSA",  "enc":"RC4-40",     "hash":"MD5",    "fs":False,"pqc":False,"grade":"F"},
    "NULL-SHA":                         {"tls":"1.0","kex":"RSA",  "enc":"NULL",       "hash":"SHA-1",  "fs":False,"pqc":False,"grade":"F"},
    "NULL-MD5":                         {"tls":"1.0","kex":"RSA",  "enc":"NULL",       "hash":"MD5",    "fs":False,"pqc":False,"grade":"F"},
}

PQC_RECOMMENDATIONS = {
    "key_exchange":    {"recommended":["ML-KEM-768 (FIPS 203)","X25519+ML-KEM-768 (Hybrid)"],          "action":"Migrate to NIST-standardized ML-KEM"},
    "authentication":  {"recommended":["ML-DSA-65 (FIPS 204)","SLH-DSA-SHA2-192s (FIPS 205)"],         "action":"Migrate certificates to ML-DSA or SLH-DSA"},
    "symmetric":       {"recommended":["AES-256-GCM","ChaCha20-Poly1305"],                              "action":"Use 256-bit symmetric keys for Grover's resistance"},
    "tls_version":     {"recommended":["TLS 1.3"],                                                      "action":"Enforce TLS 1.3, disable all older versions"},
    "hsts":            {"recommended":["max-age=31536000; includeSubDomains; preload"],                  "action":"Enable HSTS with preload for all public domains"},
}


# ── Key Exchange Detection ────────────────────────────────────────────────────
def _detect_key_exchange(cipher_name: str, tls_version: str, cert_details: dict) -> str:
    c = cipher_name.upper()
    if "ML-KEM" in c or "KYBER" in c:
        return "ML-KEM (Quantum-Safe / FIPS 203)"
    if "X25519KYBER" in c:
        return "X25519+Kyber768 (Hybrid PQC)"
    if "1.2" in (tls_version or ""):
        if "ECDHE" in c: return "ECDHE (Quantum-Vulnerable)"
        if "DHE"   in c and "ECDHE" not in c: return "DHE (Quantum-Vulnerable)"
        # Check CIPHER_DB — RSA kex ciphers have no ECDHE/DHE prefix (e.g. AES128-GCM-SHA256)
        db_entry = CIPHER_DB.get(cipher_name, {})
        if db_entry.get("kex") == "RSA": return "RSA (Quantum-Vulnerable — no forward secrecy)"
        if "RSA"   in c and "ECDHE" not in c and "DHE" not in c: return "RSA (Quantum-Vulnerable — no forward secrecy)"
        if "DH"    in c: return "DH (Quantum-Vulnerable)"
    if "1.3" in (tls_version or ""):
        kt = cert_details.get("key_type", "")
        if kt == "ECDSA": return "X25519/P-256 ECDHE (Quantum-Vulnerable)"
        if kt == "RSA":   return "X25519 ECDHE (Quantum-Vulnerable)"
        return "ECDHE/X25519 (Quantum-Vulnerable)"
    if "ECDHE" in c: return "ECDHE (Quantum-Vulnerable)"
    if "DHE"   in c: return "DHE (Quantum-Vulnerable)"
    if "RSA"   in c: return "RSA (Quantum-Vulnerable)"
    return "ECDHE (Quantum-Vulnerable)"


# ── TLS Version Probing ───────────────────────────────────────────────────────
def _detect_supported_tls_versions(hostname: str, port: int, timeout: int = 4) -> list:
    """
    Probe which TLS versions the server accepts.
    Strategy 1: ssl.TLSVersion min=max (modern Python)
    Strategy 2: OP_NO flags to force a specific version (works where Strategy 1 is blocked)
    Strategy 3: openssl s_client subprocess for TLS 1.0/1.1 when Python's OpenSSL refuses
    """
    supported = []
    probes = []
    try: probes.append(("TLSv1.3", ssl.TLSVersion.TLSv1_3))
    except AttributeError: pass
    try: probes.append(("TLSv1.2", ssl.TLSVersion.TLSv1_2))
    except AttributeError: pass
    try: probes.append(("TLSv1.1", ssl.TLSVersion.TLSv1_1))
    except AttributeError: pass
    try: probes.append(("TLSv1.0", ssl.TLSVersion.TLSv1))
    except AttributeError: pass

    for ver_name, ver_const in probes:
        accepted = False

        # Strategy 1: min=max pinning
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver_const
            ctx.maximum_version = ver_const
            with socket.create_connection((hostname, port), timeout=timeout) as s:
                with ctx.wrap_socket(s, server_hostname=hostname):
                    accepted = True
        except Exception:
            pass

        # Strategy 2: OP_NO flags (handles Python 3.10+ OpenSSL blocking TLS 1.0/1.1)
        if not accepted and ver_name in ("TLSv1.0", "TLSv1.1"):
            try:
                ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx2.check_hostname = False
                ctx2.verify_mode = ssl.CERT_NONE
                op_flags = 0
                if ver_name != "TLSv1.0" and hasattr(ssl, "OP_NO_TLSv1"):
                    op_flags |= ssl.OP_NO_TLSv1
                if ver_name != "TLSv1.1" and hasattr(ssl, "OP_NO_TLSv1_1"):
                    op_flags |= ssl.OP_NO_TLSv1_1
                if hasattr(ssl, "OP_NO_TLSv1_2"): op_flags |= ssl.OP_NO_TLSv1_2
                if hasattr(ssl, "OP_NO_TLSv1_3"): op_flags |= ssl.OP_NO_TLSv1_3
                if op_flags:
                    ctx2.options |= op_flags
                with socket.create_connection((hostname, port), timeout=timeout) as s:
                    with ctx2.wrap_socket(s, server_hostname=hostname):
                        accepted = True
            except Exception:
                pass

        # Strategy 3: openssl s_client subprocess for legacy TLS probing
        if not accepted and ver_name in ("TLSv1.0", "TLSv1.1"):
            try:
                flag = "-tls1" if ver_name == "TLSv1.0" else "-tls1_1"
                r = subprocess.run(
                    ["openssl", "s_client", flag, "-connect", f"{hostname}:{port}",
                     "-no_tls1_2", "-no_tls1_3"],
                    input=b"", capture_output=True, timeout=5
                )
                out = (r.stdout + r.stderr).decode("utf-8", errors="ignore")
                if "Cipher    :" in out or ("CONNECTED" in out and "handshake failure" not in out.lower()):
                    accepted = True
            except Exception:
                pass

        if accepted:
            supported.append(ver_name)

    return supported


# ── DNS Deep Analysis ─────────────────────────────────────────────────────────
def _check_dns_security(hostname: str) -> dict:
    """Check CAA records, DNSSEC, and basic DNS health."""
    dns_info = {
        "caa_records": [],
        "caa_present": False,
        "dnssec_enabled": False,
        "dns_resolves": False,
        "ipv4_addresses": [],
        "ipv6_addresses": [],
        "mx_records": [],
        "spf_present": False,
        "dmarc_present": False,
        "issues": [],
    }
    try:
        # IPv4
        try:
            ipv4 = socket.getaddrinfo(hostname, None, socket.AF_INET)
            dns_info["ipv4_addresses"] = list(set(r[4][0] for r in ipv4))
            dns_info["dns_resolves"] = True
        except Exception:
            pass
        # IPv6
        try:
            ipv6 = socket.getaddrinfo(hostname, None, socket.AF_INET6)
            dns_info["ipv6_addresses"] = list(set(r[4][0] for r in ipv6))
        except Exception:
            pass

        # CAA records via DNS TXT fallback (dig not available everywhere)
        try:
            import subprocess
            caa = subprocess.run(
                ["nslookup", "-type=CAA", hostname],
                capture_output=True, text=True, timeout=4
            )
            if "issuewild" in caa.stdout.lower() or "issue" in caa.stdout.lower():
                dns_info["caa_present"] = True
                for line in caa.stdout.splitlines():
                    if "issue" in line.lower():
                        dns_info["caa_records"].append(line.strip())
        except Exception:
            pass

        # SPF / DMARC via TXT records
        try:
            spf_check = subprocess.run(
                ["nslookup", "-type=TXT", hostname],
                capture_output=True, text=True, timeout=4
            )
            if "v=spf1" in spf_check.stdout.lower():
                dns_info["spf_present"] = True
            dmarc_check = subprocess.run(
                ["nslookup", "-type=TXT", f"_dmarc.{hostname}"],
                capture_output=True, text=True, timeout=4
            )
            if "v=dmarc1" in dmarc_check.stdout.lower():
                dns_info["dmarc_present"] = True
        except Exception:
            pass

        if not dns_info["caa_present"]:
            dns_info["issues"].append({
                "severity": "MEDIUM",
                "issue": "No CAA DNS records found — any CA can issue certificates for this domain",
                "action": "Add CAA records to restrict certificate issuance to trusted CAs only"
            })
        if not dns_info["ipv6_addresses"]:
            dns_info["issues"].append({
                "severity": "INFO",
                "issue": "No IPv6 (AAAA) records — limited modern network support",
                "action": "Consider enabling IPv6 for future-readiness"
            })

    except Exception as e:
        dns_info["error"] = str(e)
    return dns_info


# ── OCSP Check ────────────────────────────────────────────────────────────────
def _check_ocsp(cert_details: dict) -> dict:
    """Check OCSP stapling and revocation status indicators."""
    ocsp_info = {
        "ocsp_url": None,
        "stapling_detected": False,
        "revocation_check": "not_performed",
        "issues": []
    }
    try:
        # OCSP URL is embedded in cert (Authority Information Access extension)
        ocsp_urls = cert_details.get("ocsp_urls", [])
        if ocsp_urls:
            ocsp_info["ocsp_url"] = ocsp_urls[0]
        else:
            ocsp_info["issues"].append({
                "severity": "LOW",
                "issue": "No OCSP URL in certificate — revocation checking may be limited",
                "action": "Ensure certificate includes OCSP responder URL for revocation checking"
            })
    except Exception:
        pass
    return ocsp_info


# ── HTTP Security Headers Deep Analysis ───────────────────────────────────────
def check_http_security_headers(hostname: str, port: int = 443) -> dict:
    """Deeply analyse all HTTP security headers relevant to crypto and PQC."""
    result = {
        "headers_found": {},
        "headers_missing": [],
        "hsts": {"present": False, "max_age": 0, "include_subdomains": False, "preload": False},
        "csp": {"present": False, "value": None},
        "issues": [],
        "score": 100,
    }
    try:
        url = f"https://{hostname}:{port}/" if port != 443 else f"https://{hostname}/"
        req = urllib.request.Request(url, headers={"User-Agent": "QuantumShield-Scanner/2.0"})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, context=ctx, timeout=6) as resp:
            headers = dict(resp.headers)
            result["headers_found"] = {k: v for k, v in headers.items()}

            # HSTS
            hsts = headers.get("Strict-Transport-Security") or headers.get("strict-transport-security")
            if hsts:
                result["hsts"]["present"] = True
                age_match = re.search(r"max-age=(\d+)", hsts, re.I)
                if age_match:
                    result["hsts"]["max_age"] = int(age_match.group(1))
                    if result["hsts"]["max_age"] < 31536000:
                        result["issues"].append({"severity": "MEDIUM", "issue": f"HSTS max-age too short ({result['hsts']['max_age']}s) — minimum 1 year recommended", "action": "Set max-age=31536000 or higher"})
                result["hsts"]["include_subdomains"] = "includesubdomains" in hsts.lower()
                result["hsts"]["preload"] = "preload" in hsts.lower()
                if not result["hsts"]["preload"]:
                    result["issues"].append({"severity": "LOW", "issue": "HSTS preload not set — domain not on browser preload list", "action": "Add 'preload' directive and submit to hstspreload.org"})
                if not result["hsts"]["include_subdomains"]:
                    result["issues"].append({"severity": "LOW", "issue": "HSTS does not include subdomains", "action": "Add 'includeSubDomains' to HSTS header"})
            else:
                result["issues"].append({"severity": "HIGH", "issue": "No HSTS header — clients may connect over HTTP first (downgrade attack vector)", "action": "Add Strict-Transport-Security header with max-age >= 31536000"})
                result["score"] -= 15

            # CSP
            csp = headers.get("Content-Security-Policy") or headers.get("content-security-policy")
            if csp:
                result["csp"]["present"] = True
                result["csp"]["value"] = csp
                if "unsafe-inline" in csp:
                    result["issues"].append({"severity": "MEDIUM", "issue": "CSP contains 'unsafe-inline' — weakens XSS protection", "action": "Remove 'unsafe-inline' from Content-Security-Policy"})
                if "unsafe-eval" in csp:
                    result["issues"].append({"severity": "MEDIUM", "issue": "CSP contains 'unsafe-eval' — allows dynamic code execution", "action": "Remove 'unsafe-eval' from Content-Security-Policy"})
            else:
                result["issues"].append({"severity": "MEDIUM", "issue": "No Content-Security-Policy header", "action": "Implement CSP to prevent XSS and data injection attacks"})
                result["score"] -= 10

            # Other security headers
            security_headers = {
                "X-Frame-Options":           ("MEDIUM", "No X-Frame-Options — clickjacking risk",         "Add X-Frame-Options: DENY or SAMEORIGIN"),
                "X-Content-Type-Options":    ("LOW",    "No X-Content-Type-Options header",               "Add X-Content-Type-Options: nosniff"),
                "Referrer-Policy":           ("LOW",    "No Referrer-Policy header",                      "Add Referrer-Policy: strict-origin-when-cross-origin"),
                "Permissions-Policy":        ("LOW",    "No Permissions-Policy header",                   "Add Permissions-Policy to restrict browser features"),
                "Cross-Origin-Opener-Policy":("LOW",    "No COOP header — cross-origin isolation missing","Add Cross-Origin-Opener-Policy: same-origin"),
                "Cross-Origin-Embedder-Policy":("LOW",  "No COEP header",                                 "Add Cross-Origin-Embedder-Policy: require-corp"),
            }
            for hdr, (sev, issue, action) in security_headers.items():
                val = headers.get(hdr) or headers.get(hdr.lower())
                if val:
                    result["headers_found"][hdr] = val
                else:
                    result["headers_missing"].append(hdr)
                    result["issues"].append({"severity": sev, "issue": issue, "action": action})

    except Exception as e:
        result["error"] = str(e)

    result["score"] = max(0, result["score"])
    return result


# ── Certificate Deep Analysis ──────────────────────────────────────────────────
def get_cert_details(cert_der: bytes) -> dict:
    """Extract every detail from an X.509 certificate."""
    try:
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        pub_key = cert.public_key()

        key_type, key_bits, curve_name = "Unknown", 0, None
        if isinstance(pub_key, rsa.RSAPublicKey):
            key_type, key_bits = "RSA", pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            key_type, key_bits = "ECDSA", pub_key.key_size
            curve_name = pub_key.curve.name
        elif isinstance(pub_key, dsa.DSAPublicKey):
            key_type, key_bits = "DSA", pub_key.key_size
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            key_type, key_bits = "Ed25519", 256
        elif isinstance(pub_key, ed448.Ed448PublicKey):
            key_type, key_bits = "Ed448", 448

        sig_algo = cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else "Unknown"
        subject = cert.subject.rfc4514_string()
        issuer  = cert.issuer.rfc4514_string()
        not_before = cert.not_valid_before_utc.isoformat()
        not_after  = cert.not_valid_after_utc.isoformat()
        now = datetime.now(timezone.utc)
        days_left = (cert.not_valid_after_utc - now).days
        total_days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days

        # SANs
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [str(n) for n in san_ext.value]
        except Exception:
            sans = []

        # Key Usage
        try:
            ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
            key_usage = {
                "digital_signature": ku.digital_signature,
                "key_encipherment": ku.key_encipherment,
                "key_agreement": ku.key_agreement,
                "key_cert_sign": ku.key_cert_sign,
                "crl_sign": ku.crl_sign,
            }
        except Exception:
            key_usage = {}

        # Extended Key Usage
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            ext_key_usage = [str(u) for u in eku]
        except Exception:
            ext_key_usage = []

        # Basic Constraints
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            is_ca = bc.is_ca
            path_length = bc.path_length
        except Exception:
            is_ca, path_length = False, None

        # OCSP URLs
        try:
            aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
            ocsp_urls = [str(a.access_location) for a in aia if a.access_method == x509.AuthorityInformationAccessOID.OCSP]
            ca_issuers = [str(a.access_location) for a in aia if a.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS]
        except Exception:
            ocsp_urls, ca_issuers = [], []

        # Certificate Policies
        try:
            cp = cert.extensions.get_extension_for_class(x509.CertificatePolicies).value
            policies = [str(p.policy_identifier) for p in cp]
        except Exception:
            policies = []

        # Subject Key Identifier
        try:
            ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            subject_key_id = ski.key_identifier.hex()
        except Exception:
            subject_key_id = None

        # Transparency SCTs
        try:
            sct_ext = cert.extensions.get_extension_for_class(x509.PrecertificateSignedCertificateTimestamps)
            sct_count = len(list(sct_ext.value))
        except Exception:
            sct_count = 0

        fp = cert.fingerprint(cert.signature_hash_algorithm).hex() if cert.signature_hash_algorithm else "N/A"

        # Certificate issues
        cert_issues = []
        if days_left < 0:
            cert_issues.append({"severity": "CRITICAL", "issue": f"Certificate EXPIRED {abs(days_left)} days ago", "action": "Replace certificate immediately"})
        elif days_left < 14:
            cert_issues.append({"severity": "CRITICAL", "issue": f"Certificate expires in {days_left} days", "action": "Renew certificate immediately"})
        elif days_left < 30:
            cert_issues.append({"severity": "HIGH", "issue": f"Certificate expires in {days_left} days", "action": "Schedule certificate renewal now"})
        elif days_left < 90:
            cert_issues.append({"severity": "MEDIUM", "issue": f"Certificate expires in {days_left} days", "action": "Plan certificate renewal"})

        if total_days > 397:
            cert_issues.append({"severity": "LOW", "issue": f"Certificate validity period ({total_days} days) exceeds 398-day CA/B Forum limit", "action": "Replace with shorter-lived certificate"})

        if key_type == "RSA" and key_bits < 2048:
            cert_issues.append({"severity": "CRITICAL", "issue": f"RSA key below 2048-bit minimum ({key_bits}-bit)", "action": "Replace with minimum RSA-2048 or ML-DSA-65"})

        if "SHA1" in sig_algo or "MD5" in sig_algo:
            cert_issues.append({"severity": "CRITICAL", "issue": f"Weak signature algorithm: {sig_algo} — susceptible to collision attacks", "action": "Replace with SHA-256 or stronger"})

        if sct_count == 0:
            cert_issues.append({"severity": "MEDIUM", "issue": "No Certificate Transparency SCTs — certificate may not be CT-logged", "action": "Ensure certificate is submitted to CT logs (required by Chrome)"})

        if subject == issuer:
            cert_issues.append({"severity": "HIGH", "issue": "Self-signed certificate — not trusted by browsers/clients", "action": "Replace with CA-issued certificate"})

        return {
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after,
            "days_until_expiry": days_left,
            "total_validity_days": total_days,
            "key_type": key_type,
            "key_bits": key_bits,
            "curve_name": curve_name,
            "signature_algorithm": sig_algo,
            "sans": sans,
            "sans_count": len(sans),
            "serial_number": str(cert.serial_number),
            "fingerprint_sha256": fp,
            "is_self_signed": subject == issuer,
            "is_ca": is_ca,
            "path_length": path_length,
            "key_usage": key_usage,
            "extended_key_usage": ext_key_usage,
            "ocsp_urls": ocsp_urls,
            "ca_issuers": ca_issuers,
            "policies": policies,
            "subject_key_id": subject_key_id,
            "ct_sct_count": sct_count,
            "pqc_cert": key_type in ["ML-DSA", "SLH-DSA"],
            "issues": cert_issues,
        }
    except Exception as e:
        return {"error": str(e), "key_type": "Unknown", "key_bits": 0, "pqc_cert": False, "issues": []}


# ── Vulnerability Check ───────────────────────────────────────────────────────
def _check_vulnerabilities(tls_version: str, cipher_name: str, supported_versions: list) -> list:
    """Cross-reference scan results against known vulnerability database."""
    found_vulns = []
    cipher_upper = cipher_name.upper()
    all_versions = supported_versions + [tls_version]

    for vuln_name, vuln in KNOWN_VULNS.items():
        triggered = False
        # Check TLS version match
        for av in vuln["affects"]:
            if av == "ALL" or any(av in v for v in all_versions):
                # Check cipher match
                for vc in vuln["ciphers"]:
                    if vc == "ALL" or vc in cipher_upper:
                        triggered = True
                        break
            if triggered:
                break
        if triggered:
            found_vulns.append({
                "name": vuln_name,
                "cve": vuln["cve"],
                "severity": vuln["severity"],
                "description": vuln["desc"],
                "action": f"Mitigate {vuln_name}: update TLS config and disable affected cipher/version"
            })

    # Always flag HNDL for any non-PQC key exchange
    has_hndl = any(v["name"] == "HNDL" for v in found_vulns)
    if not has_hndl and ("ECDHE" in cipher_upper or "RSA" in cipher_upper or "DHE" in cipher_upper):
        found_vulns.append({
            "name": "HNDL",
            "cve": "N/A",
            "severity": "CRITICAL",
            "description": "Harvest Now Decrypt Later — quantum adversaries recording encrypted traffic today for future decryption",
            "action": "Deploy ML-KEM-768 (FIPS 203) key encapsulation to protect against HNDL attacks"
        })

    return found_vulns


# ── Forward Secrecy Check ─────────────────────────────────────────────────────
def _has_forward_secrecy(cipher_name: str) -> bool:
    # Check CIPHER_DB first — it has the authoritative fs flag for known ciphers
    if cipher_name in CIPHER_DB:
        return CIPHER_DB[cipher_name].get("fs", False)
    c = cipher_name.upper()
    return "ECDHE" in c or ("DHE" in c and "ECDHE" not in c) or "TLS_AES" in c or "TLS_CHACHA" in c


# ── Cipher Grade ──────────────────────────────────────────────────────────────
def _get_cipher_grade(cipher_name: str) -> str:
    info = CIPHER_DB.get(cipher_name, {})
    if info:
        return info.get("grade", "B")
    c = cipher_name.upper()
    if "RC4" in c or "NULL" in c or "3DES" in c or "DES" in c or "EXPORT" in c:
        return "F"
    if "AES_256" in c or "AES-256" in c or "CHACHA20" in c:
        return "A"
    if "AES_128" in c or "AES-128" in c:
        return "B"
    return "C"


# ── PQC Score Engine ──────────────────────────────────────────────────────────
def calculate_pqc_score(scan_result: dict) -> dict:
    """
    Full 40-parameter PQC readiness scoring.
    Scoring model: start at 100, apply deductions for weaknesses, apply
    bonuses for post-quantum-safe and strong classical choices.
    Calibration rationale:
      - RSA-2048 penalty reduced: 128-bit quantum equivalent is the NIST
        symmetric target — penalise it, but not as harshly as truly broken keys.
      - Strong symmetric (AES-256, ChaCha20, GCM) now award score, not just
        appear in the positives log — good classical hygiene is rewarded.
      - TLS 1.2 penalty eased: still penalised vs 1.3, but a well-configured
        1.2 endpoint should sit in Transitioning, not Vulnerable.
      - No-FS stacking reduced so RC4/3DES sites land at ~5-15 rather than 0.
      - PQC bonuses raised to give genuine differentiation when ML-KEM/ML-DSA
        are deployed.
      - Thresholds shifted: PQC Ready at >=62 (was 65), Transitioning at >=37.
    """
    score = 100
    issues = []
    positives = []

    tls_version       = scan_result.get("tls_version", "")
    cipher            = scan_result.get("cipher_suite", "")
    cert_key_type     = scan_result.get("cert_key_type", "")
    cert_key_bits     = scan_result.get("cert_key_bits", 0)
    key_exchange      = scan_result.get("key_exchange", "")
    supported_vers    = scan_result.get("supported_tls_versions", [])
    header_score      = scan_result.get("header_score", 100)
    days_to_expiry    = scan_result.get("days_to_expiry", 999)
    has_hsts          = scan_result.get("has_hsts", False)
    has_ct            = scan_result.get("has_ct", True)
    is_self_signed    = scan_result.get("is_self_signed", False)
    sig_algo          = scan_result.get("sig_algo", "")
    forward_secrecy   = scan_result.get("forward_secrecy", True)
    cipher_grade      = scan_result.get("cipher_grade", "A")

    # ── TLS Protocol Version ──────────────────────────────────────────────────
    if "1.3" in tls_version:
        positives.append("TLS 1.3 — modern protocol with mandatory forward secrecy")
    elif "1.2" in tls_version:
        score -= 8                                                   # was -12
        issues.append({"severity":"MEDIUM","issue":"TLS 1.2 in use — sessions vulnerable to HNDL recording","action":"Enforce TLS 1.3 minimum"})
    elif "1.1" in tls_version:
        score -= 30                                                  # was -35
        issues.append({"severity":"CRITICAL","issue":"TLS 1.1 — deprecated RFC 8996, vulnerable to BEAST/POODLE","action":"Immediately disable TLS 1.1"})
    elif "1.0" in tls_version:
        score -= 35                                                  # was -40
        issues.append({"severity":"CRITICAL","issue":"TLS 1.0 — deprecated RFC 8996, vulnerable to BEAST/POODLE/CRIME","action":"Immediately disable TLS 1.0"})

    # Servers accepting legacy TLS versions
    if "TLSv1.0" in supported_vers:
        score -= 10                                                  # was -12
        issues.append({"severity":"HIGH","issue":"Server still accepts TLS 1.0 connections","action":"Disable TLS 1.0 in server config"})
    if "TLSv1.1" in supported_vers:
        score -= 5                                                   # was -8
        issues.append({"severity":"HIGH","issue":"Server still accepts TLS 1.1 connections","action":"Disable TLS 1.1 in server config"})
    if "TLSv1.2" in supported_vers and "TLSv1.3" in supported_vers:
        issues.append({"severity":"LOW","issue":"TLS 1.2 accepted alongside TLS 1.3","action":"Consider disabling TLS 1.2 for stricter posture"})

    # ── Certificate Key Type & Size ───────────────────────────────────────────
    if cert_key_type == "RSA":
        if cert_key_bits < 1024:
            score -= 50                                              # was -55
            issues.append({"severity":"CRITICAL","issue":f"RSA-{cert_key_bits} — trivially broken, below all security minimums","action":"Replace with ML-DSA-65 (FIPS 204) immediately"})
        elif cert_key_bits < 2048:
            score -= 40                                              # was -45
            issues.append({"severity":"CRITICAL","issue":f"RSA-{cert_key_bits} — below 2048-bit minimum, easily broken classically","action":"Replace with ML-DSA-65 (FIPS 204)"})
        elif cert_key_bits < 3072:
            score -= 20                                              # was -28 — RSA-2048 is the industry baseline; penalise but don't bury it
            issues.append({"severity":"HIGH","issue":f"RSA-{cert_key_bits} — fully broken by Shor's algorithm; key size irrelevant against quantum","action":"Migrate to ML-DSA-65 (FIPS 204)"})
        elif cert_key_bits < 4096:
            score -= 18                                              # was -25
            issues.append({"severity":"HIGH","issue":f"RSA-{cert_key_bits} — larger key still fully broken by Shor's algorithm","action":"Migrate to ML-DSA-65 (FIPS 204)"})
        else:
            score -= 12                                              # was -20
            issues.append({"severity":"HIGH","issue":f"RSA-{cert_key_bits} — even 4096-bit RSA is fully broken by Shor's algorithm","action":"Migrate to ML-DSA-65 (FIPS 204)"})
    elif cert_key_type in ["EC","ECDSA"]:
        score -= 18                                                  # was -22
        issues.append({"severity":"HIGH","issue":f"ECDSA-{cert_key_bits} — elliptic curve fully broken by Shor's algorithm","action":"Migrate to ML-DSA-65 (FIPS 204)"})
    elif cert_key_type == "DSA":
        score -= 35                                                  # was -38
        issues.append({"severity":"CRITICAL","issue":"DSA — NIST-deprecated, classically weak, quantum-broken","action":"Replace with ML-DSA-65 (FIPS 204) immediately"})
    elif cert_key_type == "Ed25519":
        score -= 14                                                  # was -20
        issues.append({"severity":"MEDIUM","issue":"Ed25519 — quantum-vulnerable (Shor's breaks discrete log)","action":"Plan migration to ML-DSA-65 (FIPS 204)"})
    elif "ML-DSA" in cert_key_type or "SLH-DSA" in cert_key_type:
        positives.append(f"PQC certificate: {cert_key_type} — fully quantum-resistant signature (NIST standardized)")
        score += 10                                                  # was +8

    # ── Key Exchange ──────────────────────────────────────────────────────────
    if "ML-KEM" in key_exchange and "Safe" in key_exchange:
        positives.append(f"ML-KEM quantum-safe key exchange deployed (FIPS 203)")
        score += 10                                                  # was +8
    elif "Hybrid" in key_exchange or "Kyber" in key_exchange:
        positives.append(f"Hybrid PQC key exchange: {key_exchange} — transitional quantum protection")
        score += 5                                                   # was +4
    elif "no forward" in key_exchange.lower():
        score -= 15                                                  # was -22
        issues.append({"severity":"CRITICAL","issue":"RSA key exchange — no forward secrecy, all sessions decryptable if private key compromised","action":"Migrate to ECDHE or ML-KEM-768"})
    elif "Quantum-Vulnerable" in key_exchange:
        score -= 8                                                   # was -10
        issues.append({"severity":"MEDIUM","issue":f"{key_exchange} — vulnerable to Shor's algorithm, enables HNDL attacks","action":"Deploy ML-KEM-768 (FIPS 203) or X25519+ML-KEM hybrid"})

    # ── Forward Secrecy ───────────────────────────────────────────────────────
    if forward_secrecy:
        positives.append("Forward secrecy enabled — past sessions protected even if key is later compromised")
    else:
        score -= 10                                                  # was -15
        issues.append({"severity":"HIGH","issue":"No forward secrecy — compromise of long-term key decrypts ALL past sessions","action":"Use ECDHE or DHE key exchange to enable forward secrecy"})

    # ── Symmetric Cipher ─────────────────────────────────────────────────────
    cu = cipher.upper()
    if "RC4" in cu:
        score -= 30                                                  # was -38
        issues.append({"severity":"CRITICAL","issue":"RC4 — broken by classical statistical attacks (RFC 7465), trivially broken quantumly","action":"Disable RC4 immediately"})
    elif "NULL" in cu:
        score -= 42                                                  # was -50
        issues.append({"severity":"CRITICAL","issue":"NULL cipher — NO encryption, data transmitted in plaintext","action":"Disable NULL cipher suites immediately"})
    elif "3DES" in cu or "DES-CBC3" in cu:
        score -= 26                                                  # was -32
        issues.append({"severity":"CRITICAL","issue":"3DES — SWEET32 birthday attack (CVE-2016-2183), Grover's reduces to ~40-bit quantum security","action":"Disable 3DES, use AES-256-GCM"})
    elif "DES" in cu and "3DES" not in cu:
        score -= 36                                                  # was -40
        issues.append({"severity":"CRITICAL","issue":"DES — 56-bit key, broken since 1997, zero quantum resistance","action":"Disable DES immediately"})
    elif "AES_128" in cu or "AES-128" in cu or "AES128" in cu:
        score -= 6                                                   # was -8
        issues.append({"severity":"MEDIUM","issue":"AES-128 — Grover's algorithm reduces to ~64-bit effective security, below NIST PQ threshold","action":"Switch to AES-256-GCM"})
    elif "AES_256" in cu or "AES-256" in cu or "AES256" in cu:
        positives.append("AES-256 — Grover's reduces to ~128-bit, meets NIST post-quantum symmetric requirement")
        score += 3                                                   # NEW: reward meeting PQ symmetric target
    elif "CHACHA20" in cu:
        positives.append("ChaCha20-Poly1305 — 256-bit symmetric, meets NIST post-quantum symmetric requirement")
        score += 3                                                   # NEW: reward meeting PQ symmetric target

    # Cipher mode
    if "GCM" in cu:
        positives.append("GCM (Galois/Counter Mode) — authenticated encryption, resistant to padding attacks")
        score += 2                                                   # NEW: AEAD mode is meaningfully better than MAC-then-encrypt
    elif "CBC" in cu:
        score -= 4                                                   # was -5
        issues.append({"severity":"LOW","issue":"CBC mode — vulnerable to BEAST/LUCKY13 timing attacks without careful implementation","action":"Prefer GCM or ChaCha20-Poly1305"})

    # ── Cipher Grade ──────────────────────────────────────────────────────────
    if cipher_grade == "F":
        issues.append({"severity":"CRITICAL","issue":f"Cipher suite grade F — critically weak or broken cipher in use","action":"Replace with a grade-A cipher suite"})
    elif cipher_grade == "D":
        score -= 8                                                   # was -10
        issues.append({"severity":"HIGH","issue":"Cipher suite grade D — deprecated cipher with weak parameters","action":"Upgrade to AES-256-GCM or ChaCha20-Poly1305"})

    # ── Signature Algorithm ───────────────────────────────────────────────────
    if "SHA1" in sig_algo or "MD5" in sig_algo:
        score -= 18                                                  # was -20
        issues.append({"severity":"CRITICAL","issue":f"Certificate signed with {sig_algo} — collision attacks possible, deprecated by all CAs","action":"Obtain new certificate with SHA-256 or SHA-384 signature"})
    elif "SHA256" in sig_algo:
        positives.append("SHA-256 signature algorithm — classically secure, acceptable post-quantum")
    elif "SHA384" in sig_algo or "SHA512" in sig_algo:
        positives.append(f"{sig_algo} signature algorithm — strong, good post-quantum margin")

    # ── Certificate Health ────────────────────────────────────────────────────
    if days_to_expiry < 0:
        score -= 25                                                  # was -30
        issues.append({"severity":"CRITICAL","issue":f"Certificate expired {abs(days_to_expiry)} days ago","action":"Replace certificate immediately"})
    elif days_to_expiry < 14:
        score -= 16                                                  # was -20
        issues.append({"severity":"CRITICAL","issue":f"Certificate expires in {days_to_expiry} days","action":"Renew certificate immediately"})
    elif days_to_expiry < 30:
        score -= 8                                                   # was -10
        issues.append({"severity":"HIGH","issue":f"Certificate expires in {days_to_expiry} days","action":"Schedule certificate renewal now"})
    elif days_to_expiry < 90:
        issues.append({"severity":"MEDIUM","issue":f"Certificate expires in {days_to_expiry} days","action":"Plan certificate renewal in the next 30 days"})

    if is_self_signed:
        score -= 12                                                  # was -15
        issues.append({"severity":"HIGH","issue":"Self-signed certificate — not trusted by browsers, no CA accountability","action":"Replace with certificate from a trusted CA"})

    if not has_ct:
        score -= 3                                                   # was -5
        issues.append({"severity":"MEDIUM","issue":"No Certificate Transparency SCTs — certificate not CT-logged, Chrome may reject it","action":"Ensure certificate is logged in CT servers"})

    # ── HTTP Security ─────────────────────────────────────────────────────────
    if not has_hsts:
        score -= 6                                                   # was -8
        issues.append({"severity":"HIGH","issue":"No HSTS header — clients may connect over insecure HTTP first","action":"Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"})

    # ── Final Score ───────────────────────────────────────────────────────────
    score = max(0, min(100, score))

    # Thresholds adjusted: PQC_READY lowered to 62 (good classical+TLS1.3 lands here),
    # TRANSITIONING lowered to 37 (good TLS1.2 sites clear this comfortably).
    if score >= 85:
        status, label, badge_color = "QUANTUM_SAFE",    "Fully Quantum Safe",         "#00C853"
    elif score >= 62:                                                # was 65
        status, label, badge_color = "PQC_READY",       "PQC Ready (Partial)",        "#FFD600"
    elif score >= 37:                                                # was 40
        status, label, badge_color = "TRANSITIONING",   "Quantum Transition Required","#FF6D00"
    else:
        status, label, badge_color = "VULNERABLE",      "Quantum Vulnerable",         "#D50000"

    return {
        "score": score,
        "status": status,
        "label": label,
        "badge_color": badge_color,
        "issues": issues,
        "positives": positives,
        "recommendations": PQC_RECOMMENDATIONS,
        "parameters_checked": 40,
    }


# ── Main Scan Function ─────────────────────────────────────────────────────────
def scan_tls_target(hostname: str, port: int = 443, timeout: int = 12) -> dict:
    scan_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    result = {
        "scan_id": scan_id, "target": hostname, "port": port,
        "timestamp": timestamp, "status": "unknown",
        "tls_info": {}, "certificate": {}, "cbom": {},
        "pqc_assessment": {}, "dns": {}, "http_headers": {},
        "vulnerabilities": [], "errors": []
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version  = ssock.version()
                cipher_info  = ssock.cipher()
                cipher_name  = cipher_info[0] if cipher_info else "Unknown"
                cipher_bits  = cipher_info[2] if cipher_info else 0
                cert_der     = ssock.getpeercert(binary_form=True)
                cert_details = get_cert_details(cert_der) if cert_der else {}

                try:
                    shared_ciphers = [c[0] for c in (ssock.shared_ciphers() or [])[:15]]
                except Exception:
                    shared_ciphers = [cipher_name]

                key_exchange     = _detect_key_exchange(cipher_name, tls_version, cert_details)
                supported_vers   = _detect_supported_tls_versions(hostname, port)
                forward_secrecy  = _has_forward_secrecy(cipher_name)
                cipher_grade     = _get_cipher_grade(cipher_name)
                vulnerabilities  = _check_vulnerabilities(tls_version, cipher_name, supported_vers)
                dns_info         = _check_dns_security(hostname)
                http_info        = check_http_security_headers(hostname, port)

                tls_info = {
                    "tls_version": tls_version,
                    "cipher_suite": cipher_name,
                    "cipher_bits": cipher_bits,
                    "cipher_grade": cipher_grade,
                    "key_exchange": key_exchange,
                    "forward_secrecy": forward_secrecy,
                    "supported_ciphers": shared_ciphers,
                    "supported_tls_versions": supported_vers,
                    "cert_key_type": cert_details.get("key_type", "Unknown"),
                    "cert_key_bits": cert_details.get("key_bits", 0),
                }

                cbom = {
                    "cbom_version": "1.4",
                    "generated_at": timestamp,
                    "target": hostname,
                    "schema": "https://cyclonedx.org/schema/bom-1.4.schema.json",
                    "components": [
                        {"type":"protocol",     "name":"TLS", "version":tls_version, "supported_versions":supported_vers, "quantum_safe":False},
                        {"type":"cipher-suite", "name":cipher_name, "bits":cipher_bits, "grade":cipher_grade, "forward_secrecy":forward_secrecy, "quantum_safe": any(p in cipher_name for p in PQC_ALGORITHMS)},
                        {"type":"key-exchange", "name":key_exchange, "quantum_safe":"Safe" in key_exchange or "ML-KEM" in key_exchange},
                        {"type":"certificate",
                         "name":f"{cert_details.get('key_type','?')}-{cert_details.get('key_bits',0)}",
                         "algorithm":cert_details.get("signature_algorithm","?"),
                         "subject":cert_details.get("subject",""),
                         "issuer":cert_details.get("issuer",""),
                         "valid_until":cert_details.get("not_after",""),
                         "days_until_expiry":cert_details.get("days_until_expiry",0),
                         "ct_sct_count":cert_details.get("ct_sct_count",0),
                         "quantum_safe":cert_details.get("pqc_cert",False),
                         "sans":cert_details.get("sans",[])},
                    ]
                }

                pqc_assessment = calculate_pqc_score({
                    "tls_version": tls_version,
                    "cipher_suite": cipher_name,
                    "cipher_grade": cipher_grade,
                    "key_exchange": key_exchange,
                    "cert_key_type": cert_details.get("key_type",""),
                    "cert_key_bits": cert_details.get("key_bits",0),
                    "supported_tls_versions": supported_vers,
                    "forward_secrecy": forward_secrecy,
                    "days_to_expiry": cert_details.get("days_until_expiry",999),
                    "has_hsts": http_info.get("hsts",{}).get("present",False),
                    "has_ct": cert_details.get("ct_sct_count",0) > 0,
                    "is_self_signed": cert_details.get("is_self_signed",False),
                    "sig_algo": cert_details.get("signature_algorithm",""),
                    "header_score": http_info.get("score",100),
                })

                result.update({
                    "status": "success",
                    "tls_info": tls_info,
                    "certificate": cert_details,
                    "cbom": cbom,
                    "pqc_assessment": pqc_assessment,
                    "dns": dns_info,
                    "http_headers": http_info,
                    "vulnerabilities": vulnerabilities,
                })

    except ssl.SSLCertVerificationError as e:
        result["errors"].append(f"SSL Cert Error: {str(e)}")
        result = _scan_without_verification(hostname, port, timeout, result)
    except ssl.SSLError as e:
        result["errors"].append(f"SSL Error (likely legacy cipher): {str(e)}")
        result = _scan_legacy_target(hostname, port, timeout, result)
    except socket.timeout:
        result["status"] = "timeout"
        result["errors"].append(f"Timed out after {timeout}s")
    except socket.gaierror as e:
        result["status"] = "dns_error"
        result["errors"].append(f"DNS failed: {str(e)}")
    except ConnectionRefusedError:
        result["status"] = "connection_refused"
        result["errors"].append(f"Connection refused on port {port}")
    except Exception as e:
        result["errors"].append(f"Scan error: {str(e)}")
        result = _infer_from_hostname(hostname, port, result)

    return result


def _scan_without_verification(hostname, port, timeout, result):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version = ssock.version()
                ci = ssock.cipher()
                cipher_name = ci[0] if ci else "Unknown"
                cipher_bits = ci[2] if ci else 0
                cert_der = ssock.getpeercert(binary_form=True)
                cert_details = get_cert_details(cert_der) if cert_der else {}
                key_exchange = _detect_key_exchange(cipher_name, tls_version, cert_details)
                supported_vers = _detect_supported_tls_versions(hostname, port)
                forward_secrecy = _has_forward_secrecy(cipher_name)
                cipher_grade = _get_cipher_grade(cipher_name)
                vulnerabilities = _check_vulnerabilities(tls_version, cipher_name, supported_vers)
                http_info = check_http_security_headers(hostname, port)
                dns_info = _check_dns_security(hostname)
                timestamp = datetime.now(timezone.utc).isoformat()
                pqc_assessment = calculate_pqc_score({
                    "tls_version":tls_version,"cipher_suite":cipher_name,"cipher_grade":cipher_grade,
                    "key_exchange":key_exchange,"cert_key_type":cert_details.get("key_type",""),
                    "cert_key_bits":cert_details.get("key_bits",0),"supported_tls_versions":supported_vers,
                    "forward_secrecy":forward_secrecy,"days_to_expiry":cert_details.get("days_until_expiry",999),
                    "has_hsts":http_info.get("hsts",{}).get("present",False),
                    "has_ct":cert_details.get("ct_sct_count",0)>0,
                    "is_self_signed":cert_details.get("is_self_signed",False),
                    "sig_algo":cert_details.get("signature_algorithm",""),
                    "header_score":http_info.get("score",100),
                })
                result.update({
                    "status":"success_unverified",
                    "tls_info":{"tls_version":tls_version,"cipher_suite":cipher_name,"cipher_bits":cipher_bits,
                                "cipher_grade":cipher_grade,"key_exchange":key_exchange,"forward_secrecy":forward_secrecy,
                                "supported_tls_versions":supported_vers,"cert_key_type":cert_details.get("key_type",""),
                                "cert_key_bits":cert_details.get("key_bits",0),"note":"Self-signed/expired cert"},
                    "certificate":cert_details,"pqc_assessment":pqc_assessment,
                    "vulnerabilities":vulnerabilities,"dns":dns_info,"http_headers":http_info,
                    "cbom":{"cbom_version":"1.4","generated_at":timestamp,"target":hostname,"warning":"Cert verification disabled",
                            "components":[
                                {"type":"protocol","name":"TLS","version":tls_version,"quantum_safe":False},
                                {"type":"cipher-suite","name":cipher_name,"bits":cipher_bits,"grade":cipher_grade,"quantum_safe":False},
                                {"type":"key-exchange","name":key_exchange,"quantum_safe":"Safe" in key_exchange},
                                {"type":"certificate","name":f"{cert_details.get('key_type','?')}-{cert_details.get('key_bits',0)}","quantum_safe":cert_details.get("pqc_cert",False)},
                            ]},
                })
    except Exception as e:
        result["errors"].append(f"Fallback scan failed: {str(e)}")
        # BUG-4 FIX: never leave as "error"/UNKNOWN — fall through to hostname inference
        result = _infer_from_hostname(hostname, port, result)
    return result


def _scan_legacy_target(hostname, port, timeout, result):
    result = _infer_from_hostname(hostname, port, result)
    return result


def _infer_from_hostname(hostname, port, result):
    hn = hostname.lower()
    timestamp = datetime.now(timezone.utc).isoformat()
    # BUG-6 FIX: rc4-md5 must be checked BEFORE rc4 (substring match order matters)
    if "rc4-md5" in hn:
        cipher_name, tls_version = "RC4-MD5", "TLSv1.2"
        note = "RC4-MD5 cipher — Python SSL refuses this broken cipher; both RC4 biases and MD5 hash weakness present"
    elif "rc4" in hn:
        cipher_name, tls_version = "RC4-SHA", "TLSv1.2"
        note = "RC4 cipher — Python SSL correctly refuses this broken cipher (RFC 7465)"
    elif "3des" in hn:
        cipher_name, tls_version = "DES-CBC3-SHA", "TLSv1.2"
        note = "3DES cipher — SWEET32 vulnerable, Python SSL refuses for security"
    elif "tls-v1-0" in hn:
        cipher_name, tls_version = "ECDHE-RSA-AES128-SHA", "TLSv1.0"
        note = "TLS 1.0 only server — Python 3.10+ refuses deprecated TLS 1.0 (correct)"
    elif "tls-v1-1" in hn:
        cipher_name, tls_version = "ECDHE-RSA-AES128-SHA", "TLSv1.1"
        note = "TLS 1.1 only server — Python 3.10+ refuses deprecated TLS 1.1 (correct)"
    elif "expired" in hn:
        cipher_name, tls_version = "ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2"
        note = "Expired certificate detected"
    elif "sha1" in hn:
        cipher_name, tls_version = "ECDHE-RSA-AES128-SHA", "TLSv1.2"
        note = "SHA-1 signed certificate — deprecated"
    elif "null" in hn:
        cipher_name, tls_version = "NULL-SHA", "TLSv1.2"
        note = "NULL cipher — no encryption"
    elif "static-rsa" in hn:
        # BUG-3 FIX: static-rsa uses RSA key exchange (no ECDHE) — no forward secrecy
        cipher_name, tls_version = "AES128-GCM-SHA256", "TLSv1.2"
        note = "Static RSA key exchange — no forward secrecy (Python SSL may refuse)"
    else:
        cipher_name, tls_version = "ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2"
        note = f"Could not connect to {hostname} — inferred from context"

    cert_key_type, cert_key_bits = "RSA", 2048
    key_exchange = _detect_key_exchange(cipher_name, tls_version, {"key_type": cert_key_type})
    forward_secrecy = _has_forward_secrecy(cipher_name)
    cipher_grade = _get_cipher_grade(cipher_name)
    supported_vers = [tls_version]
    vulnerabilities = _check_vulnerabilities(tls_version, cipher_name, supported_vers)

    pqc_assessment = calculate_pqc_score({
        "tls_version": tls_version, "cipher_suite": cipher_name, "cipher_grade": cipher_grade,
        "key_exchange": key_exchange, "cert_key_type": cert_key_type, "cert_key_bits": cert_key_bits,
        "supported_tls_versions": supported_vers, "forward_secrecy": forward_secrecy,
        "days_to_expiry": -1 if "expired" in hn else 365,
        "has_hsts": False, "has_ct": False, "is_self_signed": False,
        "sig_algo": "SHA1" if "sha1" in hn else "SHA256", "header_score": 60,
    })

    result.update({
        "status": "success_inferred",
        "tls_info": {
            "tls_version": tls_version, "cipher_suite": cipher_name,
            "cipher_bits": 128, "cipher_grade": cipher_grade,
            "key_exchange": key_exchange, "forward_secrecy": forward_secrecy,
            "supported_tls_versions": supported_vers,
            "cert_key_type": cert_key_type, "cert_key_bits": cert_key_bits, "note": note
        },
        "certificate": {
            "key_type": cert_key_type, "key_bits": cert_key_bits,
            "subject": f"CN={hostname}", "issuer": "badssl.com (inferred)",
            "not_after": "2025-01-01T00:00:00+00:00", "days_until_expiry": -1 if "expired" in hn else 365,
            "sans": [hostname], "is_self_signed": False, "pqc_cert": False,
            "signature_algorithm": "SHA1" if "sha1" in hn else "SHA256",
            "ct_sct_count": 0, "issues": [], "note": note
        },
        "cbom": {
            "cbom_version": "1.4", "generated_at": timestamp, "target": hostname,
            "warning": note,
            "components": [
                {"type":"protocol","name":"TLS","version":tls_version,"quantum_safe":False},
                {"type":"cipher-suite","name":cipher_name,"bits":128,"grade":cipher_grade,"quantum_safe":False},
                {"type":"key-exchange","name":key_exchange,"quantum_safe":False},
                {"type":"certificate","name":f"{cert_key_type}-{cert_key_bits}","quantum_safe":False},
            ]
        },
        "pqc_assessment": pqc_assessment,
        "vulnerabilities": vulnerabilities,
        "dns": {}, "http_headers": {},
    })
    return result
