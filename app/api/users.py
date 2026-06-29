from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from ..db import db_session
from ..deps import current_user
from ..repositories.users import lookup_active_user
from ..serializers import lookup_user as serialize_lookup_user
from ..validation import normalize_email

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("/lookup")
def lookup_user(email: str, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    normalized = normalize_email(email)
    with db_session() as conn:
        row = lookup_active_user(conn, normalized)
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
    return {"user": serialize_lookup_user(row)}

