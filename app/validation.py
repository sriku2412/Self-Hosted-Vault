from __future__ import annotations

import json
import re
from typing import Any

from fastapi import HTTPException

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(email: str) -> str:
    normalized = email.strip().lower()
    if not EMAIL_RE.match(normalized) or len(normalized) > 254:
        raise HTTPException(status_code=422, detail="Invalid email address")
    return normalized


def compact_json(value: Any) -> str:
    if not isinstance(value, dict):
        raise HTTPException(status_code=422, detail="Encrypted payload must be an object")
    if value.get("alg") != "AES-GCM" or not value.get("iv") or not value.get("ct"):
        raise HTTPException(status_code=422, detail="Encrypted payload is missing required fields")
    encoded = json.dumps(value, separators=(",", ":"))
    if len(encoded) > 128_000:
        raise HTTPException(status_code=413, detail="Encrypted payload is too large")
    return encoded


def read_compact_json(value: str) -> Any:
    return json.loads(value)

