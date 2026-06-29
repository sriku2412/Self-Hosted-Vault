from __future__ import annotations

import pytest

from app.config import load_settings


def _valid_production_env(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("APP_SECRET_KEY", "A" * 48)
    monkeypatch.setenv("JWT_SECRET", "B" * 48)
    monkeypatch.setenv("SECURE_COOKIES", "true")
    monkeypatch.setenv("TRUSTED_HOSTS", "vault.example.com")
    monkeypatch.setenv("KDF_ITERATIONS", "600000")
    monkeypatch.setenv("MAX_LOGIN_ATTEMPTS_PER_MINUTE", "8")


def test_production_rejects_placeholder_secrets(monkeypatch):
    _valid_production_env(monkeypatch)
    monkeypatch.setenv("APP_SECRET_KEY", "replace-with-a-long-random-secret")

    with pytest.raises(RuntimeError, match="placeholder"):
        load_settings()


def test_production_rejects_equal_session_and_app_secrets(monkeypatch):
    _valid_production_env(monkeypatch)
    monkeypatch.setenv("APP_SECRET_KEY", "A" * 48)
    monkeypatch.setenv("JWT_SECRET", "A" * 48)

    with pytest.raises(RuntimeError, match="must be different"):
        load_settings()


def test_production_rejects_insecure_cookie_setting(monkeypatch):
    _valid_production_env(monkeypatch)
    monkeypatch.setenv("SECURE_COOKIES", "false")

    with pytest.raises(RuntimeError, match="SECURE_COOKIES"):
        load_settings()
