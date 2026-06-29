from __future__ import annotations

import base64
import hashlib
from typing import Any

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from ..config import settings
from ..db import db_session
from ..deps import audit, current_user
from ..repositories.settings import get_registration_enabled
from ..repositories.users import (
    bump_session_version,
    count_users,
    create_user,
    find_user_by_email,
    get_user_by_id,
    update_last_login,
)
from ..schemas import LoginRequest, RegisterRequest
from ..security import create_session_token, decrypt_server_secret, hash_auth_secret, verify_auth_secret
from ..serializers import public_user
from ..validation import compact_json, normalize_email

router = APIRouter(prefix="/api/auth", tags=["auth"])


def fake_prelogin(email: str) -> dict[str, Any]:
    seed = hashlib.sha256(f"{settings.app_secret_key}:prelogin:{email}".encode("utf-8")).digest()
    return {
        "exists": False,
        "kdfSalt": base64.urlsafe_b64encode(seed[:16]).decode("utf-8").rstrip("="),
        "kdfIterations": settings.kdf_iterations,
        "totpEnabled": False,
    }


@router.get("/prelogin")
def prelogin(email: str = Query(...)) -> dict[str, Any]:
    normalized = normalize_email(email)
    with db_session() as conn:
        row = find_user_by_email(conn, normalized)
        if not row:
            return fake_prelogin(normalized)
        return {
            "exists": True,
            "kdfSalt": row["kdf_salt"],
            "kdfIterations": row["kdf_iterations"],
            "totpEnabled": bool(row["totp_enabled"]),
        }


@router.post("/register", status_code=201)
def register(payload: RegisterRequest, request: Request) -> dict[str, Any]:
    email = normalize_email(payload.email)
    private_key_cipher = compact_json(payload.encryptedPrivateKey)
    with db_session() as conn:
        is_first_user = count_users(conn) == 0
        if not is_first_user and not get_registration_enabled(conn):
            raise HTTPException(status_code=403, detail="Registration is disabled")
        if find_user_by_email(conn, email):
            raise HTTPException(status_code=409, detail="Account already exists")

        user_id = create_user(
            conn,
            email=email,
            display_name=payload.displayName.strip() or email,
            auth_verifier=hash_auth_secret(payload.authHash),
            kdf_salt=payload.kdfSalt,
            kdf_iterations=payload.kdfIterations,
            public_key=payload.publicKey,
            encrypted_private_key=private_key_cipher,
            is_admin=is_first_user,
        )
        audit(conn, request, user_id, "auth.register", {"email": email, "first_user": is_first_user})
    return {"ok": True, "isAdmin": is_first_user}


@router.post("/login")
def login(payload: LoginRequest, request: Request, response: Response) -> dict[str, Any]:
    email = normalize_email(payload.email)
    with db_session() as conn:
        row = find_user_by_email(conn, email)
        if row is None or row["is_disabled"] or not verify_auth_secret(row["auth_verifier"], payload.authHash):
            audit(conn, request, row["id"] if row else None, "auth.login_failed", {"email": email})
            raise HTTPException(status_code=401, detail="Invalid email, password, or TOTP code")

        if row["totp_enabled"]:
            secret = decrypt_server_secret(row["totp_secret_ciphertext"] or "")
            if not secret:
                raise HTTPException(status_code=500, detail="TOTP configuration is invalid")
            if not payload.totpCode:
                return {"requiresTotp": True}
            if not pyotp.TOTP(secret).verify(payload.totpCode.replace(" ", ""), valid_window=1):
                audit(conn, request, row["id"], "auth.totp_failed", {"email": email})
                raise HTTPException(status_code=401, detail="Invalid email, password, or TOTP code")

        token = create_session_token(row["id"], row["session_version"])
        response.set_cookie(
            settings.session_cookie_name,
            token,
            max_age=60 * 60 * 12,
            httponly=True,
            secure=settings.secure_cookies,
            samesite="strict",
            path="/",
        )
        update_last_login(conn, row["id"])
        audit(conn, request, row["id"], "auth.login")
        fresh = get_user_by_id(conn, row["id"])
    return {"ok": True, "requiresTotp": False, "user": public_user(fresh)}


@router.post("/logout")
def logout(request: Request, response: Response, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    with db_session() as conn:
        bump_session_version(conn, user["id"])
        audit(conn, request, user["id"], "auth.logout")
    response.delete_cookie(settings.session_cookie_name, path="/")
    return {"ok": True, "userId": user["id"]}
