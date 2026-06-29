from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

MIN_PRODUCTION_SECRET_LENGTH = 32
PLACEHOLDER_MARKERS = {
    "change-me",
    "changeme",
    "replace-me",
    "replace_with",
    "replace-with",
}


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _csv_env(name: str, default: str) -> list[str]:
    raw = os.getenv(name, default)
    return [part.strip() for part in raw.split(",") if part.strip()]


def _int_env(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value < minimum or value > maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


def _validate_production_secret(name: str, value: str) -> None:
    normalized = value.strip().lower()
    if len(value.strip()) < MIN_PRODUCTION_SECRET_LENGTH:
        raise RuntimeError(f"{name} must be at least {MIN_PRODUCTION_SECRET_LENGTH} characters in production")
    if normalized in {"password", "secret"} or any(marker in normalized for marker in PLACEHOLDER_MARKERS):
        raise RuntimeError(f"{name} must not use a placeholder value in production")


def _validate_production_settings(
    *,
    app_secret_key: str,
    jwt_secret: str,
    secure_cookies: bool,
    trusted_hosts: list[str],
) -> None:
    _validate_production_secret("APP_SECRET_KEY", app_secret_key)
    _validate_production_secret("JWT_SECRET", jwt_secret)
    if secrets.compare_digest(app_secret_key, jwt_secret):
        raise RuntimeError("APP_SECRET_KEY and JWT_SECRET must be different in production")
    if not secure_cookies:
        raise RuntimeError("SECURE_COOKIES must be true in production")
    if not trusted_hosts:
        raise RuntimeError("TRUSTED_HOSTS must contain at least one host in production")
    if "*" in trusted_hosts:
        raise RuntimeError("TRUSTED_HOSTS must not contain '*' in production")


@dataclass(frozen=True)
class Settings:
    app_name: str
    environment: str
    data_dir: Path
    backup_dir: Path
    database_path: Path
    app_secret_key: str
    jwt_secret: str
    session_cookie_name: str
    secure_cookies: bool
    trusted_hosts: list[str]
    force_https: bool
    kdf_iterations: int
    registration_enabled_default: bool
    max_login_attempts_per_minute: int

    @property
    def fernet_key(self) -> bytes:
        digest = hashlib.sha256(self.app_secret_key.encode("utf-8")).digest()
        import base64

        return base64.urlsafe_b64encode(digest)


def load_settings() -> Settings:
    data_dir = Path(os.getenv("DATA_DIR", "/data")).resolve()
    backup_dir = Path(os.getenv("BACKUP_DIR", "/backups")).resolve()
    database_path = Path(os.getenv("DATABASE_PATH", str(data_dir / "vault.sqlite3"))).resolve()
    environment = os.getenv("ENVIRONMENT", "production").strip().lower()

    app_secret_key = os.getenv("APP_SECRET_KEY", "")
    jwt_secret = os.getenv("JWT_SECRET", "")
    if not app_secret_key:
        if environment == "production":
            raise RuntimeError("APP_SECRET_KEY is required in production")
        app_secret_key = secrets.token_urlsafe(48)
    if not jwt_secret:
        if environment == "production":
            raise RuntimeError("JWT_SECRET is required in production")
        jwt_secret = secrets.token_urlsafe(48)

    secure_cookies = _bool_env("SECURE_COOKIES", environment == "production")
    trusted_hosts = _csv_env("TRUSTED_HOSTS", "localhost,127.0.0.1")
    kdf_iterations = _int_env("KDF_ITERATIONS", 600_000, minimum=200_000, maximum=2_000_000)
    max_login_attempts_per_minute = _int_env("MAX_LOGIN_ATTEMPTS_PER_MINUTE", 8, minimum=1, maximum=120)

    if environment == "production":
        _validate_production_settings(
            app_secret_key=app_secret_key,
            jwt_secret=jwt_secret,
            secure_cookies=secure_cookies,
            trusted_hosts=trusted_hosts,
        )

    return Settings(
        app_name=os.getenv("APP_NAME", "Selfhosted Vault"),
        environment=environment,
        data_dir=data_dir,
        backup_dir=backup_dir,
        database_path=database_path,
        app_secret_key=app_secret_key,
        jwt_secret=jwt_secret,
        session_cookie_name=os.getenv("SESSION_COOKIE_NAME", "sv_session"),
        secure_cookies=secure_cookies,
        trusted_hosts=trusted_hosts,
        force_https=_bool_env("FORCE_HTTPS", False),
        kdf_iterations=kdf_iterations,
        registration_enabled_default=_bool_env("REGISTRATION_ENABLED", True),
        max_login_attempts_per_minute=max_login_attempts_per_minute,
    )


settings = load_settings()
