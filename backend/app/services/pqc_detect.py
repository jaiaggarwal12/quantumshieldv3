"""
QuantumShield — Active Post-Quantum Key Exchange Detection
===========================================================

Python's `ssl` module exposes the negotiated cipher suite but NOT the TLS 1.3
named group (key exchange), which is where post-quantum ML-KEM lives. This
module fills that gap with a dependency-free active probe.

How it works
------------
We craft a raw TLS 1.3 ClientHello that advertises the PQC hybrid groups in
`supported_groups`, ordered PQC-first, and sends an EMPTY `key_share`. Per
RFC 8446 §4.1.4, a server that supports one of the offered groups responds with
a HelloRetryRequest (HRR) whose `key_share` extension names the group it
selected — revealing exactly what it would negotiate with a real client. No
post-quantum keypair generation, no OQS/liboqs, no Wireshark needed.

A second, narrower probe (PQC groups only) distinguishes "supported but not
preferred" from "not supported at all".

References
----------
- RFC 8446 (TLS 1.3): ClientHello / HelloRetryRequest / key_share
- IANA TLS Supported Groups registry (named group code points)
"""
import os
import socket
import ssl  # noqa: F401  (kept for callers/type parity)
import struct
from typing import Optional

# ── IANA TLS Supported Groups ────────────────────────────────────────────────
NAMED_GROUPS = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
    # Post-quantum hybrid groups — finalised (ML-KEM / FIPS 203)
    0x11EC: "X25519MLKEM768",
    0x11EB: "SecP256r1MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
    # Post-quantum hybrid groups — pre-standard drafts (Kyber)
    0x6399: "X25519Kyber768Draft00",
    0x639A: "SecP256r1Kyber768Draft00",
}

# Code point -> rich metadata for post-quantum groups.
PQC_GROUPS = {
    0x11EC: {"name": "X25519MLKEM768",          "kem": "ML-KEM-768",  "standard": "FIPS 203", "hybrid": True, "classical": "X25519", "draft": False},
    0x11EB: {"name": "SecP256r1MLKEM768",       "kem": "ML-KEM-768",  "standard": "FIPS 203", "hybrid": True, "classical": "P-256",  "draft": False},
    0x11ED: {"name": "SecP384r1MLKEM1024",      "kem": "ML-KEM-1024", "standard": "FIPS 203", "hybrid": True, "classical": "P-384",  "draft": False},
    0x6399: {"name": "X25519Kyber768Draft00",   "kem": "Kyber-768",   "standard": "Draft (pre-FIPS)", "hybrid": True, "classical": "X25519", "draft": True},
    0x639A: {"name": "SecP256r1Kyber768Draft00","kem": "Kyber-768",   "standard": "Draft (pre-FIPS)", "hybrid": True, "classical": "P-256",  "draft": True},
}

# Advertise PQC first so a PQC-preferring server selects one in its HRR.
_ALL_GROUPS = [
    0x11EC, 0x11EB, 0x11ED,            # ML-KEM hybrids (final)
    0x6399, 0x639A,                    # Kyber hybrids (draft)
    0x001D, 0x0017, 0x0018, 0x0019, 0x001E,  # classical
]
_PQC_ONLY_GROUPS = [0x11EC, 0x11EB, 0x11ED, 0x6399, 0x639A]

# SHA-256("HelloRetryRequest") — the magic ServerHello.random that marks an HRR.
_HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)

_TLS13 = 0x0304


# ── ClientHello construction ──────────────────────────────────────────────────
def _is_ip_literal(host: str) -> bool:
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, host)
            return True
        except OSError:
            continue
    return False


def _ext(ext_type: int, data: bytes) -> bytes:
    return struct.pack(">HH", ext_type, len(data)) + data


def _build_client_hello(hostname: str, groups: list) -> bytes:
    body = b"\x03\x03"               # legacy_version = TLS 1.2
    body += os.urandom(32)           # random
    sid = os.urandom(32)             # session id (middlebox-compat mode)
    body += bytes([len(sid)]) + sid

    # cipher suites: the three TLS 1.3 suites
    suites = struct.pack(">HHH", 0x1301, 0x1302, 0x1303)
    body += struct.pack(">H", len(suites)) + suites

    body += b"\x01\x00"              # compression: 1 method = null

    ext = b""

    # SNI (skip for IP literals)
    if hostname and not _is_ip_literal(hostname):
        try:
            host_b = hostname.encode("idna")
        except Exception:
            host_b = hostname.encode("utf-8", "ignore")
        entry = b"\x00" + struct.pack(">H", len(host_b)) + host_b
        ext += _ext(0x0000, struct.pack(">H", len(entry)) + entry)

    # supported_versions: TLS 1.3 only
    ext += _ext(0x002B, b"\x02" + struct.pack(">H", _TLS13))

    # supported_groups
    grp_bytes = b"".join(struct.pack(">H", g) for g in groups)
    ext += _ext(0x000A, struct.pack(">H", len(grp_bytes)) + grp_bytes)

    # signature_algorithms (required by spec; covers RSA-PSS, ECDSA, PKCS1)
    sigs = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203]
    sig_bytes = b"".join(struct.pack(">H", s) for s in sigs)
    ext += _ext(0x000D, struct.pack(">H", len(sig_bytes)) + sig_bytes)

    # key_share: EMPTY -> forces HelloRetryRequest revealing the chosen group
    ext += _ext(0x0033, struct.pack(">H", 0))

    # psk_key_exchange_modes: psk_dhe_ke (helps with strict servers)
    ext += _ext(0x002D, b"\x01\x01")

    body += struct.pack(">H", len(ext)) + ext

    # handshake header: ClientHello (1) + 3-byte length
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    # record header: handshake (0x16), legacy 0x0301
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


# ── Response parsing ──────────────────────────────────────────────────────────
def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _read_record(sock: socket.socket):
    hdr = _recv_exact(sock, 5)
    if len(hdr) < 5:
        return None
    ctype = hdr[0]
    length = struct.unpack(">H", hdr[3:5])[0]
    return ctype, _recv_exact(sock, length)


def _parse_server_hello(msg: bytes) -> dict:
    """Parse a ServerHello / HelloRetryRequest handshake body."""
    out = {"is_hrr": False, "selected_group": None, "negotiated_version": None, "cipher_suite": None}
    try:
        p = 0
        p += 2                                   # legacy_version
        rnd = msg[p:p + 32]; p += 32
        out["is_hrr"] = rnd == _HRR_RANDOM
        sid_len = msg[p]; p += 1
        p += sid_len                             # session_id echo
        out["cipher_suite"] = int.from_bytes(msg[p:p + 2], "big"); p += 2
        p += 1                                   # compression method
        if p + 2 > len(msg):
            return out
        ext_len = int.from_bytes(msg[p:p + 2], "big"); p += 2
        end = min(p + ext_len, len(msg))
        while p + 4 <= end:
            etype = int.from_bytes(msg[p:p + 2], "big"); p += 2
            elen = int.from_bytes(msg[p:p + 2], "big"); p += 2
            edata = msg[p:p + elen]; p += elen
            if etype == 0x0033 and len(edata) >= 2:        # key_share
                out["selected_group"] = int.from_bytes(edata[0:2], "big")
            elif etype == 0x002B and len(edata) >= 2:      # supported_versions
                out["negotiated_version"] = int.from_bytes(edata[0:2], "big")
    except Exception:
        pass
    return out


def _probe(hostname: str, port: int, groups: list, timeout: float) -> dict:
    """Send one ClientHello and parse the first ServerHello/HRR (or alert)."""
    ch = _build_client_hello(hostname, groups)
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(ch)
        for _ in range(6):
            rec = _read_record(sock)
            if rec is None:
                return {"error": "no_response"}
            ctype, body = rec
            if ctype == 0x15:                               # alert
                desc = body[1] if len(body) >= 2 else None
                return {"alert": desc}
            if ctype == 0x14:                               # change_cipher_spec
                continue
            if ctype == 0x16:                               # handshake
                if len(body) < 4:
                    continue
                if body[0] == 0x02:                          # ServerHello / HRR
                    return _parse_server_hello(body[4:])
                continue
    return {"error": "no_server_hello"}


# ── Public API ────────────────────────────────────────────────────────────────
def detect_key_exchange_group(hostname: str, port: int = 443, timeout: float = 7.0) -> dict:
    """
    Actively detect the TLS 1.3 key-exchange group a server negotiates,
    including post-quantum hybrid groups (ML-KEM / Kyber).

    Returns a dict describing the result. Never raises — failures are reported
    in the `error` field so callers can fall back to heuristics.
    """
    result = {
        "method": "active-tls13-probe",
        "tls13_supported": False,
        "selected_group_code": None,
        "selected_group": None,
        "is_pqc": False,
        "preferred_is_pqc": False,
        "pqc_supported": False,
        "kem": None,
        "standard": None,
        "hybrid": None,
        "is_draft": None,
        "summary": None,
        "error": None,
    }

    try:
        primary = _probe(hostname, port, _ALL_GROUPS, timeout)
    except (socket.timeout, OSError) as e:
        result["error"] = f"connect_failed: {str(e)[:80]}"
        return result
    except Exception as e:  # pragma: no cover — defensive
        result["error"] = str(e)[:100]
        return result

    if primary.get("alert") is not None:
        result["error"] = f"tls_alert:{primary['alert']}"
        return result
    if primary.get("error"):
        result["error"] = primary["error"]
        return result

    sel = primary.get("selected_group")
    ver = primary.get("negotiated_version")

    # TLS 1.3 confirmed if we got a selected group or negotiated_version == 1.3
    result["tls13_supported"] = bool(sel) or ver == _TLS13
    if sel:
        result["selected_group_code"] = sel
        result["selected_group"] = NAMED_GROUPS.get(sel, f"0x{sel:04X}")

    if sel in PQC_GROUPS:
        meta = PQC_GROUPS[sel]
        result.update({
            "is_pqc": True,
            "preferred_is_pqc": True,
            "pqc_supported": True,
            "kem": meta["kem"],
            "standard": meta["standard"],
            "hybrid": meta["hybrid"],
            "is_draft": meta["draft"],
            "summary": f"Server negotiates {meta['name']} — hybrid {meta['kem']} ({meta['standard']}).",
        })
        return result

    # Server preferred a classical group. Probe again with PQC-only to see if it
    # supports any PQC group at a lower preference.
    if result["tls13_supported"]:
        try:
            secondary = _probe(hostname, port, _PQC_ONLY_GROUPS, timeout)
            sel2 = secondary.get("selected_group")
            if sel2 in PQC_GROUPS:
                meta = PQC_GROUPS[sel2]
                result.update({
                    "pqc_supported": True,
                    "kem": meta["kem"],
                    "standard": meta["standard"],
                    "hybrid": meta["hybrid"],
                    "is_draft": meta["draft"],
                    "summary": (
                        f"Server supports {meta['name']} ({meta['kem']}, {meta['standard']}) "
                        f"but prefers classical {result['selected_group']}."
                    ),
                })
                return result
        except Exception:
            pass

    if result["tls13_supported"]:
        result["summary"] = (
            f"No post-quantum key exchange — server negotiates classical "
            f"{result['selected_group'] or 'group'} (quantum-vulnerable)."
        )
    else:
        result["summary"] = "Server does not support TLS 1.3 — no PQC key exchange possible."
    return result
