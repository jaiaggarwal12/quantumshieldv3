"""Active PQC key-exchange detection — offline unit tests for the protocol logic."""
from app.services import pqc_detect as p


def test_client_hello_is_well_formed():
    ch = p._build_client_hello("example.com", p._ALL_GROUPS)
    assert ch[0] == 0x16          # handshake record
    assert ch[5] == 0x01          # ClientHello
    assert len(ch) > 40


def test_named_groups_cover_pqc_codepoints():
    assert p.NAMED_GROUPS[0x11EC] == "X25519MLKEM768"
    assert 0x11EC in p.PQC_GROUPS
    assert p.PQC_GROUPS[0x11EC]["standard"] == "FIPS 203"


def test_parse_hrr_selecting_pqc_group():
    # Minimal HelloRetryRequest body: legacy_version + HRR random + empty sid +
    # cipher + compression + extensions(key_share -> selected_group 0x11EC).
    body = b"\x03\x03" + p._HRR_RANDOM + b"\x00" + b"\x13\x01" + b"\x00"
    ext = b"\x00\x33\x00\x02\x11\xec"          # key_share, len 2, group 0x11EC
    body += len(ext).to_bytes(2, "big") + ext
    parsed = p._parse_server_hello(body)
    assert parsed["is_hrr"] is True
    assert parsed["selected_group"] == 0x11EC


def test_detect_handles_unresolvable_host_gracefully():
    res = p.detect_key_exchange_group("nonexistent.invalid.tld.example", 443, timeout=2)
    assert res["is_pqc"] is False
    assert res["error"] is not None
