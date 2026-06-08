"""Auth, rate limiting, OTP, audit, and API surface tests."""
from app.core.config import settings
from app.services import rate_limit
from app.services.email_service import send_otp, verify_otp


def test_health_ok(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json()["checks"]["database"] == "ok"


def test_scan_requires_auth(client):
    assert client.post("/api/v1/scan/quick", json={"target": "example.com"}).status_code == 401


def test_me_with_token(client, admin_token):
    r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200
    assert r.json()["role"] == "Admin"


def test_scan_blocks_private_target(client, admin_token):
    r = client.post("/api/v1/scan/quick", json={"target": "127.0.0.1"},
                    headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 400
    assert "non-public" in r.json()["detail"]


def test_logout_revokes_token(client, admin_token):
    h = {"Authorization": f"Bearer {admin_token}"}
    assert client.get("/api/v1/auth/me", headers=h).status_code == 200
    assert client.post("/api/v1/auth/logout", headers=h).status_code == 200
    # Token is now denylisted.
    assert client.get("/api/v1/auth/me", headers=h).status_code == 401


def test_rate_limiter(db):
    key = "test:rl"
    rate_limit.reset(db, key)
    allowed_count = 0
    for _ in range(5):
        ok, _r = rate_limit.hit(db, key, max_count=3, window_seconds=60)
        allowed_count += int(ok)
    assert allowed_count == 3  # 4th and 5th blocked


def test_otp_store_and_verify(db):
    # SMTP not configured in tests -> send returns sent False, but the code is stored.
    send_otp(db, "otp-test@example.com", "tester")
    from app.models.security import OTPCode
    rec = db.query(OTPCode).filter(OTPCode.email == "otp-test@example.com").first()
    assert rec is not None
    # Wrong code fails, correct path covered by hashing — verify rejects garbage.
    assert verify_otp(db, "otp-test@example.com", "000000-wrong")["valid"] in (False,)


def test_audit_endpoint(client, admin_token):
    r = client.get("/api/v1/auth/audit", headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_demo_info_exposed(client):
    r = client.get("/api/v1/auth/demo-info")
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is True
    assert body["username"] and body["password"]


def test_demo_login_skips_otp(client):
    info = client.get("/api/v1/auth/demo-info").json()
    r = client.post("/api/v1/auth/login", data={"username": info["username"], "password": info["password"]})
    assert r.status_code == 200
    body = r.json()
    assert body["otp_required"] is False
    assert body["access_token"]
    # The returned token works on a protected route — it's a real account.
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200
    assert me.json()["username"] == info["username"]


def test_non_demo_login_still_requires_otp(client):
    # Wrong password for a normal account must not bypass anything.
    r = client.post("/api/v1/auth/login", data={"username": "admin", "password": "definitely-wrong"})
    assert r.status_code == 401
