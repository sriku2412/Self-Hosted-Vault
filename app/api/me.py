from __future__ import annotations

from typing import Any

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request

from ..config import settings
from ..db import db_session
from ..deps import audit, current_user
from ..repositories.users import (
    disable_totp,
    enable_totp,
    get_totp_pending_ciphertext,
    get_totp_secret_ciphertext,
    set_totp_pending_ciphertext,
)
from ..schemas import TotpConfirmRequest
from ..security import decrypt_server_secret, encrypt_server_secret
from ..serializers import public_user

router = APIRouter(prefix="/api/me", tags=["me"])


@router.get("")
def me(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return {"user": public_user(user)}


@router.post("/totp/setup")
def setup_totp(request: Request, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    secret = pyotp.random_base32()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user["email"], issuer_name=settings.app_name)
    with db_session() as conn:
        set_totp_pending_ciphertext(conn, user["id"], encrypt_server_secret(secret))
        audit(conn, request, user["id"], "totp.setup_started")
    return {"secret": secret, "provisioningUri": uri}


@router.post("/totp/confirm")
def confirm_totp(
    payload: TotpConfirmRequest,
    request: Request,
    user: dict[str, Any] = Depends(current_user),
) -> dict[str, Any]:
    with db_session() as conn:
        pending_ciphertext = get_totp_pending_ciphertext(conn, user["id"])
        secret = decrypt_server_secret(pending_ciphertext or "") if pending_ciphertext else None
        if not secret or not pyotp.TOTP(secret).verify(payload.code.replace(" ", ""), valid_window=1):
            raise HTTPException(status_code=400, detail="Invalid TOTP code")
        enable_totp(conn, user["id"])
        audit(conn, request, user["id"], "totp.enabled")
    return {"ok": True}


@router.post("/totp/disable")
def disable_totp_route(
    payload: TotpConfirmRequest,
    request: Request,
    user: dict[str, Any] = Depends(current_user),
) -> dict[str, Any]:
    with db_session() as conn:
        secret_ciphertext = get_totp_secret_ciphertext(conn, user["id"])
        secret = decrypt_server_secret(secret_ciphertext or "") if secret_ciphertext else None
        if not secret or not pyotp.TOTP(secret).verify(payload.code.replace(" ", ""), valid_window=1):
            raise HTTPException(status_code=400, detail="Invalid TOTP code")
        disable_totp(conn, user["id"])
        audit(conn, request, user["id"], "totp.disabled")
    return {"ok": True}
