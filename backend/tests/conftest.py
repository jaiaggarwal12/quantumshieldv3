"""
Pytest fixtures. Points the app at an isolated temp SQLite database and a fixed
test secret BEFORE importing the app, so tests never touch the dev database.
"""
import os
import tempfile

# Must be set before importing app.* (config/database read env at import time).
_TMP_DB = os.path.join(tempfile.gettempdir(), "qs_test.db")
if os.path.exists(_TMP_DB):
    try:
        os.remove(_TMP_DB)
    except OSError:
        pass
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP_DB}"
os.environ["SECRET_KEY"] = "test-secret-key-which-is-long-enough-1234567890"
os.environ["ALLOW_PRIVATE_TARGETS"] = "false"

import pytest
from fastapi.testclient import TestClient

from app.main import app, _seed_database
from app.database import SessionLocal


@pytest.fixture(scope="session", autouse=True)
def _init_db():
    _seed_database()
    yield


@pytest.fixture()
def db():
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def admin_token():
    """Mint a valid JWT for the seeded admin without going through email OTP."""
    from app.routers.auth import create_access_token
    return create_access_token({"sub": os.getenv("ADMIN_USERNAME", "admin"), "role": "Admin"})
