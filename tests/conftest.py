from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

TEST_ROOT = Path(tempfile.mkdtemp(prefix="selfhosted-vault-tests-"))

os.environ["ENVIRONMENT"] = "development"
os.environ["APP_SECRET_KEY"] = "test-app-secret-key-with-enough-length-123456789"
os.environ["JWT_SECRET"] = "test-jwt-secret-key-with-enough-length-987654321"
os.environ["DATA_DIR"] = str(TEST_ROOT / "data")
os.environ["BACKUP_DIR"] = str(TEST_ROOT / "backups")
os.environ["DATABASE_PATH"] = str(TEST_ROOT / "data" / "vault.sqlite3")
os.environ["KDF_ITERATIONS"] = "200000"
os.environ["SECURE_COOKIES"] = "false"
os.environ["TRUSTED_HOSTS"] = "testserver,localhost,127.0.0.1"

from app.config import settings  # noqa: E402
from app.db import init_db  # noqa: E402
from app.main import app, auth_limiter  # noqa: E402


def _remove_database() -> None:
    for suffix in ("", "-wal", "-shm"):
        Path(f"{settings.database_path}{suffix}").unlink(missing_ok=True)


@pytest.fixture(autouse=True)
def fresh_database():
    _remove_database()
    init_db()
    auth_limiter._hits.clear()
    yield
    _remove_database()


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        test_client.get("/api/config")
        yield test_client


@pytest.fixture()
def make_client():
    clients: list[TestClient] = []

    def factory() -> TestClient:
        test_client = TestClient(app)
        test_client.__enter__()
        test_client.get("/api/config")
        clients.append(test_client)
        return test_client

    yield factory

    for test_client in reversed(clients):
        test_client.__exit__(None, None, None)


def pytest_sessionfinish(session, exitstatus):  # noqa: ARG001
    shutil.rmtree(TEST_ROOT, ignore_errors=True)
