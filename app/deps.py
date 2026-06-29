from __future__ import annotations

import sqlite3
from typing import Any, Optional

from fastapi import Depends, HTTPException, Request

from .config import settings
from .db import db_session
from .repositories.audit import record_audit_event
from .repositories.users import get_user_by_id
from .security import decode_session_token


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def audit(
    conn: sqlite3.Connection,
    request: Request,
    user_id: Optional[int],
    action: str,
    detail: Optional[dict[str, Any]] = None,
) -> None:
    record_audit_event(conn, user_id, action, client_ip(request), detail)


def current_user(request: Request) -> dict[str, Any]:
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    payload = decode_session_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid session")

    with db_session() as conn:
        row = get_user_by_id(conn, payload["sub"])
        if row is None or row["is_disabled"]:
            raise HTTPException(status_code=401, detail="Account unavailable")
        try:
            token_session_version = int(payload["sv"])
        except (KeyError, TypeError, ValueError):
            raise HTTPException(status_code=401, detail="Session expired") from None
        if int(row["session_version"]) != token_session_version:
            raise HTTPException(status_code=401, detail="Session expired")
        return dict(row)


def admin_user(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user
