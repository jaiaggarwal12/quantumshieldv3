"""
QuantumShield — API & VPN Scanner
Covers the two gaps from the PNB problem statement:
  1. API endpoint discovery + TLS scan per endpoint
  2. TLS-based VPN port probe (IKEv2 UDP 500/4500, OpenVPN TCP 443/1194)
"""

import ssl
import socket
import urllib.request
import urllib.parse
import json
import re
from datetime import datetime, timezone
from typing import Optional

from app.services.scanner_service import scan_tls_target, _get_cipher_grade, _has_forward_secrecy


# ── Common API paths to probe ─────────────────────────────────────────────────
API_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/v1",
    "/v2",
    "/rest",
    "/graphql",
    "/swagger",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/docs",
    "/health",
    "/status",
    "/ping",
    "/actuator",
    "/actuator/health",
    "/api/health",
    "/api/status",
    "/.well-known/openid-configuration",
    "/oauth/token",
    "/auth/token",
    "/login",
    "/api/login",
]


def _quick_tls_check(hostname: str, port: int = 443, path: str = "/", timeout: int = 6) -> dict:
    """Fast TLS check for a single endpoint — returns key crypto facts."""
    result = {
        "endpoint": f"https://{hostname}:{port}{path}",
        "hostname": hostname,
        "port": port,
        "path": path,
        "reachable": False,
        "tls_version": None,
        "cipher_suite": None,
        "cipher_grade": None,
        "forward_secrecy": None,
        "cert_type": None,
        "cert_bits": None,
        "quantum_safe": False,
        "status_code": None,
        "content_type": None,
        "error": None,
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["tls_version"] = ssock.version()
                ci = ssock.cipher()
                if ci:
                    result["cipher_suite"] = ci[0]
                    result["cipher_grade"] = _get_cipher_grade(ci[0])
                    result["forward_secrecy"] = _has_forward_secrecy(ci[0])

                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der:
                    try:
                        from cryptography import x509 as cx509
                        from cryptography.hazmat.backends import default_backend
                        from cryptography.hazmat.primitives.asymmetric import rsa, ec
                        cert = cx509.load_der_x509_certificate(cert_der, default_backend())
                        pub = cert.public_key()
                        if isinstance(pub, rsa.RSAPublicKey):
                            result["cert_type"] = "RSA"
                            result["cert_bits"] = pub.key_size
                        elif isinstance(pub, ec.EllipticCurvePublicKey):
                            result["cert_type"] = "ECDSA"
                            result["cert_bits"] = pub.key_size
                        result["quantum_safe"] = result["cert_type"] in ("ML-DSA", "SLH-DSA")
                    except Exception:
                        pass

        # Now do an HTTP request to check reachability + content-type
        try:
            url = f"https://{hostname}:{port}{path}" if port != 443 else f"https://{hostname}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "QuantumShield-APIScanner/3.0"})
            tls_ctx = ssl.create_default_context()
            tls_ctx.check_hostname = False
            tls_ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=tls_ctx, timeout=timeout) as resp:
                result["reachable"] = True
                result["status_code"] = resp.status
                ct = resp.headers.get("Content-Type", "")
                result["content_type"] = ct.split(";")[0].strip()
        except urllib.error.HTTPError as e:
            result["reachable"] = True  # 401/403/404 still means server answered
            result["status_code"] = e.code
        except Exception:
            result["reachable"] = True  # TLS worked, HTTP just failed

    except Exception as e:
        result["error"] = str(e)[:100]

    return result


def scan_api_endpoints(base_url: str, timeout: int = 6) -> dict:
    """
    Discover and scan API endpoints on a target.
    base_url can be a hostname or full URL like https://api.example.com
    """
    # Parse hostname and port
    if not base_url.startswith("http"):
        base_url = "https://" + base_url
    parsed = urllib.parse.urlparse(base_url)
    hostname = parsed.hostname or base_url.replace("https://", "").split("/")[0]
    port = parsed.port or (80 if parsed.scheme == "http" else 443)
    base_path = parsed.path or "/"

    timestamp = datetime.now(timezone.utc).isoformat()

    result = {
        "target": hostname,
        "base_url": base_url,
        "scan_type": "api",
        "timestamp": timestamp,
        "endpoints_discovered": [],
        "endpoints_reachable": [],
        "api_tls_summary": {},
        "pqc_issues": [],
        "cert_in_cbom": [],
        "scan_status": "completed",
    }

    # First do a base TLS scan to get certificate etc.
    try:
        base_scan = _quick_tls_check(hostname, port, base_path or "/")
        result["base_tls"] = base_scan
    except Exception:
        result["base_tls"] = {}

    # Probe each API path
    reachable = []
    for path in API_PATHS:
        ep = _quick_tls_check(hostname, port, path, timeout=4)
        result["endpoints_discovered"].append(ep)
        if ep["reachable"] and ep["status_code"] and ep["status_code"] not in (404,):
            reachable.append(ep)

    result["endpoints_reachable"] = reachable

    # Build TLS summary across all reachable endpoints
    if reachable:
        tls_versions = list(set(e["tls_version"] for e in reachable if e["tls_version"]))
        ciphers = list(set(e["cipher_suite"] for e in reachable if e["cipher_suite"]))
        grades = [e["cipher_grade"] for e in reachable if e["cipher_grade"]]
        worst_grade = sorted(grades, key=lambda g: ["A","B","C","D","F"].index(g) if g in ["A","B","C","D","F"] else 5)[-1] if grades else "?"
        all_fs = all(e["forward_secrecy"] for e in reachable if e["forward_secrecy"] is not None)
        any_quantum_safe = any(e["quantum_safe"] for e in reachable)

        result["api_tls_summary"] = {
            "total_endpoints_discovered": len(API_PATHS),
            "total_reachable": len(reachable),
            "tls_versions": tls_versions,
            "cipher_suites": ciphers[:10],
            "worst_cipher_grade": worst_grade,
            "forward_secrecy_consistent": all_fs,
            "any_pqc_endpoint": any_quantum_safe,
        }

        # PQC issues for API layer
        if not any_quantum_safe:
            result["pqc_issues"].append({
                "severity": "CRITICAL",
                "issue": f"None of the {len(reachable)} discovered API endpoints use quantum-safe cryptography",
                "action": "Deploy ML-KEM-768 (FIPS 203) key exchange and ML-DSA-65 (FIPS 204) certificates on all API endpoints"
            })
        if any(e["tls_version"] and "1.2" in e["tls_version"] for e in reachable):
            result["pqc_issues"].append({
                "severity": "HIGH",
                "issue": "API endpoints accepting TLS 1.2 — sessions vulnerable to HNDL recording",
                "action": "Enforce TLS 1.3 minimum on all API endpoints"
            })
        if worst_grade in ("D", "F"):
            result["pqc_issues"].append({
                "severity": "CRITICAL",
                "issue": f"API endpoint cipher grade {worst_grade} — critically weak cipher suite",
                "action": "Replace with AES-256-GCM or ChaCha20-Poly1305"
            })

        # CERT-In CBOM elements for API layer
        for ep in reachable:
            if ep["tls_version"]:
                result["cert_in_cbom"].append({
                    "component_type": "API Endpoint",
                    "endpoint": ep["endpoint"],
                    "protocol": ep["tls_version"],
                    "cipher_suite": ep["cipher_suite"] or "Unknown",
                    "cipher_grade": ep["cipher_grade"] or "?",
                    "forward_secrecy": ep["forward_secrecy"],
                    "cert_algorithm": f"{ep['cert_type'] or '?'}-{ep['cert_bits'] or 0}",
                    "quantum_safe": ep["quantum_safe"],
                    "status_code": ep["status_code"],
                    "content_type": ep["content_type"],
                })

    return result


# ── VPN Probe ─────────────────────────────────────────────────────────────────
VPN_PORTS = [
    {"port": 500,  "proto": "UDP", "type": "IKEv2/IPsec",    "description": "IKEv2 Internet Key Exchange (IPsec VPN)"},
    {"port": 4500, "proto": "UDP", "type": "IKEv2 NAT-T",    "description": "IKEv2 NAT Traversal (IPsec VPN behind NAT)"},
    {"port": 1194, "proto": "UDP", "type": "OpenVPN UDP",     "description": "OpenVPN default UDP port"},
    {"port": 1194, "proto": "TCP", "type": "OpenVPN TCP",     "description": "OpenVPN over TCP"},
    {"port": 443,  "proto": "TCP", "type": "SSL-VPN/443",     "description": "SSL VPN over HTTPS port (Fortinet, Palo Alto, Cisco AnyConnect)"},
    {"port": 1723, "proto": "TCP", "type": "PPTP",            "description": "Point-to-Point Tunneling Protocol (legacy, insecure)"},
    {"port": 1701, "proto": "UDP", "type": "L2TP",            "description": "Layer 2 Tunneling Protocol"},
    {"port": 51820, "proto": "UDP", "type": "WireGuard",      "description": "WireGuard VPN (modern, ChaCha20-Poly1305)"},
    {"port": 4433, "proto": "TCP", "type": "SSL-VPN/4433",    "description": "Alternative SSL VPN port"},
    {"port": 8443, "proto": "TCP", "type": "SSL-VPN/8443",    "description": "Alternative SSL VPN port"},
]

def _probe_tcp_port(hostname: str, port: int, timeout: float = 2.5) -> dict:
    """Try TCP connect + optional TLS handshake."""
    probe = {"open": False, "tls": False, "tls_version": None, "cipher": None, "banner": None}
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            probe["open"] = True
            # Try TLS on top
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    probe["tls"] = True
                    probe["tls_version"] = ssock.version()
                    ci = ssock.cipher()
                    if ci:
                        probe["cipher"] = ci[0]
            except Exception:
                # Not TLS — try banner grab
                try:
                    sock.settimeout(1)
                    banner = sock.recv(256)
                    probe["banner"] = banner[:64].hex()
                except Exception:
                    pass
    except Exception:
        pass
    return probe


def _probe_udp_port(hostname: str, port: int, timeout: float = 2.0) -> dict:
    """UDP port probe — send empty datagram, check for response."""
    probe = {"open": False, "responded": False}
    try:
        ip = socket.gethostbyname(hostname)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            # IKE-style probe for port 500/4500
            if port in (500, 4500):
                # Minimal IKEv2 SA_INIT packet (8 bytes initiator SPI + header)
                ike_probe = bytes([
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  # initiator SPI
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  # responder SPI
                    0x21,  # next payload = SA
                    0x20,  # version 2.0
                    0x22,  # exchange type = IKE_SA_INIT
                    0x08,  # flags
                    0x00,0x00,0x00,0x00,  # message ID
                    0x00,0x00,0x00,0x1c,  # length
                ])
                sock.sendto(ike_probe, (ip, port))
            else:
                sock.sendto(b"\x00" * 4, (ip, port))
            try:
                data, _ = sock.recvfrom(256)
                probe["responded"] = True
                probe["open"] = True
                probe["response_bytes"] = len(data)
            except socket.timeout:
                # No response — could be filtered or truly closed
                probe["open"] = False
    except Exception:
        pass
    return probe


def scan_vpn_endpoints(hostname: str, timeout: float = 2.5) -> dict:
    """
    Probe common VPN ports on a target hostname.
    Returns discovered VPN endpoints with TLS info where applicable.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    results = {
        "target": hostname,
        "scan_type": "vpn",
        "timestamp": timestamp,
        "ports_probed": len(VPN_PORTS),
        "vpn_endpoints": [],
        "open_ports": [],
        "tls_vpn_found": False,
        "pqc_issues": [],
        "cert_in_cbom": [],
        "summary": {},
    }

    open_count = 0
    tls_vpn_count = 0

    for vp in VPN_PORTS:
        port = vp["port"]
        proto = vp["proto"]
        vpn_type = vp["type"]

        if proto == "UDP":
            probe = _probe_udp_port(hostname, port, timeout)
        else:
            probe = _probe_tcp_port(hostname, port, timeout)

        endpoint = {
            "port": port,
            "protocol": proto,
            "vpn_type": vpn_type,
            "description": vp["description"],
            "open": probe.get("open", False),
            "tls_detected": probe.get("tls", False),
            "tls_version": probe.get("tls_version"),
            "cipher_suite": probe.get("cipher"),
            "quantum_safe": False,
            "pqc_assessment": "NOT_ASSESSED",
        }

        if probe.get("open"):
            open_count += 1
            results["open_ports"].append(f"{proto}/{port} ({vpn_type})")

            if probe.get("tls"):
                tls_vpn_count += 1
                results["tls_vpn_found"] = True
                cipher = probe.get("cipher", "")
                tls_ver = probe.get("tls_version", "")
                quantum_safe = False

                # Assess quantum safety
                if "ML-KEM" in (cipher or "") or "kyber" in (cipher or "").lower():
                    endpoint["pqc_assessment"] = "QUANTUM_SAFE"
                    quantum_safe = True
                elif tls_ver and "1.3" in tls_ver:
                    endpoint["pqc_assessment"] = "PQC_READY"
                elif tls_ver and "1.2" in tls_ver:
                    endpoint["pqc_assessment"] = "TRANSITIONING"
                else:
                    endpoint["pqc_assessment"] = "VULNERABLE"

                endpoint["quantum_safe"] = quantum_safe

                # CERT-In CBOM entry
                results["cert_in_cbom"].append({
                    "component_type": "TLS-VPN Endpoint",
                    "endpoint": f"{proto}/{port} ({vpn_type}) on {hostname}",
                    "protocol": tls_ver or "Unknown TLS",
                    "cipher_suite": cipher or "Unknown",
                    "quantum_safe": quantum_safe,
                    "vpn_type": vpn_type,
                })

            # Special case: WireGuard uses ChaCha20 (quantum-resistant symmetric)
            if "WireGuard" in vpn_type and probe.get("open"):
                endpoint["pqc_assessment"] = "PQC_READY"
                endpoint["notes"] = "WireGuard uses ChaCha20-Poly1305 — quantum-resistant symmetric. No asymmetric PQC KEX yet."

            # PPTP is critically weak
            if "PPTP" in vpn_type and probe.get("open"):
                results["pqc_issues"].append({
                    "severity": "CRITICAL",
                    "issue": f"PPTP VPN detected on {hostname}:{port} — MS-CHAPv2 is classically broken, zero quantum resistance",
                    "action": "Immediately replace PPTP with WireGuard, IKEv2/IPsec, or OpenVPN with TLS 1.3"
                })

        results["vpn_endpoints"].append(endpoint)

    # Generate PQC issues for TLS VPNs
    if tls_vpn_count > 0:
        non_pqc = [e for e in results["vpn_endpoints"]
                   if e["open"] and e["tls_detected"] and e["pqc_assessment"] not in ("QUANTUM_SAFE",)]
        if non_pqc:
            results["pqc_issues"].append({
                "severity": "HIGH",
                "issue": f"{len(non_pqc)} TLS-based VPN endpoint(s) use quantum-vulnerable key exchange",
                "action": "Migrate VPN to IKEv2 with ML-KEM extensions (NIST SP 800-208) or WireGuard with PQ extensions"
            })

    if open_count == 0:
        results["pqc_issues"].append({
            "severity": "INFO",
            "issue": f"No VPN ports detected open on {hostname} — either no VPN or firewall blocking probe",
            "action": "If VPN exists, verify firewall rules permit IKEv2 (UDP 500/4500) and ensure TLS 1.3 is enforced"
        })

    results["summary"] = {
        "ports_open": open_count,
        "tls_vpn_count": tls_vpn_count,
        "vpn_detected": open_count > 0,
        "tls_vpn_found": results["tls_vpn_found"],
        "pqc_issues_count": len(results["pqc_issues"]),
    }

    return results
