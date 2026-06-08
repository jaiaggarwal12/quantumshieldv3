"""PQC scoring engine tests (offline)."""
from app.services.scanner_service import calculate_pqc_score


def _base(**over):
    d = dict(
        tls_version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384", cipher_grade="A",
        key_exchange="x25519 ECDHE (Quantum-Vulnerable)", cert_key_type="ECDSA", cert_key_bits=256,
        supported_tls_versions=["TLSv1.3"], forward_secrecy=True, days_to_expiry=200,
        has_hsts=True, has_ct=True, is_self_signed=False, sig_algo="SHA256",
    )
    d.update(over)
    return d


def test_classical_ecdsa_is_not_quantum_safe():
    r = calculate_pqc_score(_base())
    assert r["status"] in ("PQC_READY", "TRANSITIONING", "VULNERABLE")
    assert r["status"] != "QUANTUM_SAFE"


def test_rsa1024_is_critical():
    r = calculate_pqc_score(_base(cert_key_type="RSA", cert_key_bits=1024))
    assert r["score"] < 62


def test_detected_pqc_kex_boosts_score():
    classical = calculate_pqc_score(_base())
    pqc = calculate_pqc_score(_base(
        key_exchange="X25519MLKEM768 — Hybrid PQC key exchange (ML-KEM-768, FIPS 203), actively negotiated",
        pqc_kex_detected=True,
    ))
    assert pqc["score"] > classical["score"]


def test_pqc_kex_with_classical_cert_caps_at_pqc_ready():
    r = calculate_pqc_score(_base(
        key_exchange="X25519MLKEM768 — Hybrid PQC key exchange (ML-KEM-768, FIPS 203), actively negotiated",
        pqc_kex_detected=True, cert_key_type="ECDSA",
    ))
    # Even with a perfect score, a classical cert prevents "Fully Quantum Safe".
    assert r["status"] == "PQC_READY"


def test_full_pqc_can_be_quantum_safe():
    r = calculate_pqc_score(_base(
        key_exchange="ML-KEM-768 Safe", pqc_kex_detected=True,
        cert_key_type="ML-DSA", cert_key_bits=0, sig_algo="ML-DSA",
    ))
    assert r["status"] == "QUANTUM_SAFE"
