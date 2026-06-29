from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken

from .config import settings

password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
fernet = Fernet(settings.fernet_key)


def hash_auth_secret(secret: str) -> str:
    return password_hasher.hash(secret)


def verify_auth_secret(verifier: str, secret: str) -> bool:
    try:
        return password_hasher.verify(verifier, secret)
    except VerifyMismatchError:
        return False


def create_session_token(user_id: int, session_version: int) -> str:
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "sv": int(session_version),
        "iat": now,
        "exp": now + 60 * 60 * 12,
        "type": "session",
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def decode_session_token(token: str) -> Optional[dict[str, Any]]:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    if payload.get("type") != "session":
        return None
    return payload


def encrypt_server_secret(value: str) -> str:
    return fernet.encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_server_secret(value: str) -> Optional[str]:
    try:
        return fernet.decrypt(value.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return None


@dataclass
class RateLimitResult:
    allowed: bool
    retry_after_seconds: int


class SlidingWindowRateLimiter:
    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> RateLimitResult:
        now = time.time()
        hits = self._hits[key]
        while hits and hits[0] <= now - self.window_seconds:
            hits.popleft()
        if len(hits) >= self.limit:
            retry = max(1, int(self.window_seconds - (now - hits[0])))
            return RateLimitResult(False, retry)
        hits.append(now)
        return RateLimitResult(True, 0)
