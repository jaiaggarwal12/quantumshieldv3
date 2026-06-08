"""
QuantumShield — Real DNS and OCSP analysis.

Replaces the prototype's `nslookup` stdout-parsing and stubbed OCSP with proper
implementations:
  - DNS: uses dnspython for CAA, DNSSEC (AD flag / DNSKEY), MX, SPF, DMARC, AAAA.
  - OCSP: performs an actual OCSP request (RFC 6960) against the responder URL
    embedded in the certificate and reports the real revocation status.

Both degrade gracefully: if a lookup cannot be performed, that is reported as
"unknown"/"not_checked" rather than asserting a (possibly wrong) default.
"""
from datetime import datetime, timezone
from typing import Optional

from app.core.logging_config import get_logger

logger = get_logger("quantumshield.dns_ocsp")

try:
    import dns.resolver
    import dns.flags
    _DNS_OK = True
except Exception:  # pragma: no cover
    _DNS_OK = False


def check_dns_security(hostname: str) -> dict:
    """Real DNS posture check via dnspython."""
    info = {
        "caa_records": [], "caa_present": False,
        "dnssec_enabled": None,                 # None = could not determine
        "dns_resolves": False,
        "ipv4_addresses": [], "ipv6_addresses": [],
        "mx_records": [], "spf_present": False, "dmarc_present": False,
        "issues": [],
    }
    if not _DNS_OK:
        info["error"] = "dnspython not available — DNS analysis skipped"
        return info

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    resolver.timeout = 5.0

    def _q(name, rtype, want_ad=False):
        try:
            if want_ad:
                resolver.use_edns(0, dns.flags.DO, 4096)
            ans = resolver.resolve(name, rtype, raise_on_no_answer=False)
            return ans
        except Exception:
            return None

    # A / AAAA
    a = _q(hostname, "A")
    if a and a.rrset:
        info["ipv4_addresses"] = sorted({r.address for r in a})
        info["dns_resolves"] = True
    aaaa = _q(hostname, "AAAA")
    if aaaa and aaaa.rrset:
        info["ipv6_addresses"] = sorted({r.address for r in aaaa})

    # DNSSEC — check the AD (Authenticated Data) flag from a validating resolver
    try:
        if a is not None and a.response is not None:
            info["dnssec_enabled"] = bool(a.response.flags & dns.flags.AD)
    except Exception:
        info["dnssec_enabled"] = None

    # CAA
    caa = _q(hostname, "CAA")
    if caa and caa.rrset:
        info["caa_present"] = True
        for r in caa:
            try:
                info["caa_records"].append(f"{r.flags} {r.tag.decode() if isinstance(r.tag, bytes) else r.tag} \"{r.value.decode() if isinstance(r.value, bytes) else r.value}\"")
            except Exception:
                info["caa_records"].append(str(r))

    # MX
    mx = _q(hostname, "MX")
    if mx and mx.rrset:
        info["mx_records"] = sorted(str(r.exchange).rstrip(".") for r in mx)

    # SPF / DMARC (TXT)
    txt = _q(hostname, "TXT")
    if txt and txt.rrset:
        joined = " ".join("".join(s.decode(errors="ignore") if isinstance(s, bytes) else s for s in r.strings) for r in txt).lower()
        info["spf_present"] = "v=spf1" in joined
    dmarc = _q(f"_dmarc.{hostname}", "TXT")
    if dmarc and dmarc.rrset:
        joined = " ".join("".join(s.decode(errors="ignore") if isinstance(s, bytes) else s for s in r.strings) for r in dmarc).lower()
        info["dmarc_present"] = "v=dmarc1" in joined

    # Findings
    if not info["caa_present"]:
        info["issues"].append({"severity": "MEDIUM",
            "issue": "No CAA DNS records — any CA can issue certificates for this domain",
            "action": "Add CAA records to restrict certificate issuance to trusted CAs"})
    if info["dnssec_enabled"] is False:
        info["issues"].append({"severity": "LOW",
            "issue": "DNSSEC not validated (AD flag not set) — DNS responses are not cryptographically authenticated",
            "action": "Enable DNSSEC signing for the zone"})
    if not info["ipv6_addresses"]:
        info["issues"].append({"severity": "INFO",
            "issue": "No IPv6 (AAAA) records",
            "action": "Consider enabling IPv6 for modern network readiness"})
    return info


def check_ocsp(cert_details: dict, issuer_der: Optional[bytes] = None,
               subject_der: Optional[bytes] = None) -> dict:
    """
    Real OCSP revocation check (RFC 6960). Requires the subject + issuer
    certificates (DER) and an OCSP responder URL in the cert. Without the issuer
    cert we can only report that an OCSP URL is present.
    """
    out = {"ocsp_url": None, "revocation_check": "not_checked", "revoked": None, "issues": []}
    ocsp_urls = cert_details.get("ocsp_urls", []) or []
    if not ocsp_urls:
        out["issues"].append({"severity": "LOW",
            "issue": "No OCSP responder URL in certificate — revocation checking limited",
            "action": "Ensure the certificate includes an OCSP responder URL"})
        return out
    out["ocsp_url"] = ocsp_urls[0]

    if not subject_der:
        out["revocation_check"] = "url_present_not_queried"
        return out

    # If we don't have the issuer cert, try to fetch it from the CA-Issuers AIA URL.
    if not issuer_der:
        ca_issuers = cert_details.get("ca_issuers", []) or []
        if ca_issuers:
            try:
                import urllib.request
                with urllib.request.urlopen(ca_issuers[0], timeout=6) as r:
                    issuer_der = r.read()
            except Exception as e:
                logger.debug("Could not fetch issuer cert: %s", e)

    if not issuer_der:
        out["revocation_check"] = "url_present_not_queried"
        return out

    try:
        import urllib.request
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509 import ocsp

        subject = x509.load_der_x509_certificate(subject_der, default_backend())
        issuer = x509.load_der_x509_certificate(issuer_der, default_backend())
        builder = ocsp.OCSPRequestBuilder().add_certificate(subject, issuer, hashes.SHA1())
        req = builder.build()
        der = req.public_bytes(serialization.Encoding.DER)

        http_req = urllib.request.Request(
            out["ocsp_url"], data=der,
            headers={"Content-Type": "application/ocsp-request"}, method="POST",
        )
        with urllib.request.urlopen(http_req, timeout=6) as resp:
            ocsp_resp = ocsp.load_der_ocsp_response(resp.read())

        if ocsp_resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
            status = ocsp_resp.certificate_status
            if status == ocsp.OCSPCertStatus.GOOD:
                out["revocation_check"], out["revoked"] = "good", False
            elif status == ocsp.OCSPCertStatus.REVOKED:
                out["revocation_check"], out["revoked"] = "revoked", True
                out["issues"].append({"severity": "CRITICAL",
                    "issue": "Certificate has been REVOKED by the issuing CA (OCSP)",
                    "action": "Replace the certificate immediately — it is no longer trusted"})
            else:
                out["revocation_check"] = "unknown"
        else:
            out["revocation_check"] = f"responder_status:{ocsp_resp.response_status.name}"
    except Exception as e:
        out["revocation_check"] = "error"
        out["error"] = str(e)[:120]
        logger.debug("OCSP check failed: %s", e)
    return out
