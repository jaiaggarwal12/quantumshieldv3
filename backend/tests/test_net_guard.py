"""SSRF target-validation tests (offline — uses IP literals)."""
from app.core.net_guard import validate_target, _ip_is_blocked


def test_blocks_private_and_special_ranges():
    for ip in ["10.0.0.5", "192.168.1.1", "172.16.0.1", "127.0.0.1", "::1",
               "169.254.169.254", "0.0.0.0", "224.0.0.1"]:
        assert _ip_is_blocked(ip) is True, ip


def test_allows_public_addresses():
    for ip in ["8.8.8.8", "1.1.1.1", "93.184.216.34"]:
        assert _ip_is_blocked(ip) is False, ip


def test_validate_target_rejects_private_ip_literal():
    ok, reason = validate_target("10.0.0.1", 443)
    assert ok is False
    assert "non-public" in reason


def test_validate_target_rejects_metadata():
    ok, _ = validate_target("169.254.169.254", 80)
    assert ok is False


def test_validate_target_bad_port():
    ok, _ = validate_target("8.8.8.8", 99999)
    assert ok is False


def test_validate_target_allows_public_ip_literal():
    ok, reason = validate_target("8.8.8.8", 443)
    assert ok is True, reason
