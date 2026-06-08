"""
QuantumShield — Scan target validation (SSRF protection).

A scanner that connects to any host:port a user supplies can be abused as an
SSRF / internal port-scanning proxy (cloud metadata, localhost, RFC1918, etc.).
This module resolves a target and rejects it if any resolved address is private,
loopback, link-local, reserved, or the cloud metadata endpoint — unless
ALLOW_PRIVATE_TARGETS is explicitly enabled for trusted internal use.
"""
import ipaddress
import socket
from typing import Tuple

from app.core.config import settings

# Cloud instance metadata endpoints that must never be reachable via the scanner.
_METADATA_ADDRESSES = {
    "169.254.169.254",   # AWS / GCP / Azure IMDS
    "100.100.100.200",   # Alibaba Cloud
    "fd00:ec2::254",     # AWS IMDSv6
}

_MAX_HOSTNAME_LEN = 253


def _ip_is_blocked(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable — block
    if str(addr) in _METADATA_ADDRESSES:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def validate_target(hostname: str, port: int = 443) -> Tuple[bool, str]:
    """
    Returns (ok, reason). When ALLOW_PRIVATE_TARGETS is set, only basic sanity
    checks apply. Otherwise the host is resolved and all addresses are checked.
    """
    host = (hostname or "").strip()
    if not host:
        return False, "Empty target"
    if len(host) > _MAX_HOSTNAME_LEN:
        return False, "Hostname too long"
    if not (0 < port <= 65535):
        return False, f"Invalid port: {port}"

    if settings.ALLOW_PRIVATE_TARGETS:
        return True, "ok (private targets allowed)"

    # Resolve every address the host maps to (IPv4 + IPv6) and check each.
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False, f"Could not resolve host: {host}"
    except Exception as e:  # pragma: no cover — defensive
        return False, f"Resolution error: {str(e)[:80]}"

    resolved = {info[4][0] for info in infos}
    if not resolved:
        return False, "Host did not resolve to any address"

    for ip in resolved:
        if _ip_is_blocked(ip):
            return False, (
                f"Target '{host}' resolves to a non-public address ({ip}). "
                f"Scanning private/loopback/link-local/metadata ranges is blocked. "
                f"Set ALLOW_PRIVATE_TARGETS=true for trusted internal deployments."
            )
    return True, "ok"
