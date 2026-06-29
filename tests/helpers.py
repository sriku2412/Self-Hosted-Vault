from __future__ import annotations

import base64
import hashlib
import os
from typing import Any


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def csrf_headers(client) -> dict[str, str]:
    token = client.cookies.get("sv_csrf")
    if not token:
        client.get("/api/config")
        token = client.cookies.get("sv_csrf")
    return {"X-CSRF-Token": token}


def encrypted_blob() -> dict[str, Any]:
    return {
        "v": 1,
        "alg": "AES-GCM",
        "iv": b64url(os.urandom(12)),
        "ct": b64url(os.urandom(32)),
    }


def derive_auth_hash(password: str, salt_b64: str, iterations: int) -> str:
    bits = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        b64url_decode(salt_b64),
        iterations,
        dklen=64,
    )
    digest = hashlib.sha256(b"selfhosted-vault-auth-v1" + bits[32:64]).digest()
    return b64url(digest)


def registration_payload(email: str, password: str = "correct horse battery staple") -> dict[str, Any]:
    salt = b64url(os.urandom(16))
    iterations = 200_000
    return {
        "email": email,
        "displayName": email.split("@")[0],
        "authHash": derive_auth_hash(password, salt, iterations),
        "kdfSalt": salt,
        "kdfIterations": iterations,
        "publicKey": b64url(os.urandom(96)),
        "encryptedPrivateKey": encrypted_blob(),
    }


def register_user(client, email: str, password: str = "correct horse battery staple"):
    return client.post(
        "/api/auth/register",
        headers=csrf_headers(client),
        json=registration_payload(email, password),
    )


def login_user(client, email: str, password: str = "correct horse battery staple"):
    prelogin = client.get("/api/auth/prelogin", params={"email": email})
    assert prelogin.status_code == 200
    data = prelogin.json()
    return client.post(
        "/api/auth/login",
        headers=csrf_headers(client),
        json={
            "email": email,
            "authHash": derive_auth_hash(password, data["kdfSalt"], data["kdfIterations"]),
        },
    )
