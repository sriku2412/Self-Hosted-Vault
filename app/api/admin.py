from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from ..config import settings
from ..db import db_session
from ..deps import admin_user, audit
from ..maintenance import create_backup, verify_backup
from ..repositories.admin import get_stats
from ..repositories.audit import list_audit_events
from ..repositories.settings import get_registration_enabled, set_registration_enabled
from ..repositories.users import list_admin_users, update_admin_flags
from ..schemas import AdminUserPatch, SettingsPatch
from ..serializers import admin_user as serialize_admin_user
from ..serializers import audit_event as serialize_audit_event

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/stats")
def admin_stats(user: dict[str, Any] = Depends(admin_user)) -> dict[str, Any]:
    with db_session() as conn:
        stats = get_stats(conn)
    return {"stats": stats, "adminUserId": user["id"]}


@router.get("/users")
def admin_users(user: dict[str, Any] = Depends(admin_user)) -> dict[str, Any]:
    with db_session() as conn:
        rows = list_admin_users(conn)
    return {"users": [serialize_admin_user(row) for row in rows]}


@router.patch("/users/{target_user_id}")
def admin_patch_user(
    target_user_id: int,
    payload: AdminUserPatch,
    request: Request,
    user: dict[str, Any] = Depends(admin_user),
) -> dict[str, Any]:
    if target_user_id == user["id"] and (payload.isAdmin is False or payload.isDisabled is True):
        raise HTTPException(status_code=422, detail="You cannot remove or disable your own admin access")
    if payload.isAdmin is None and payload.isDisabled is None:
        return {"ok": True}

    with db_session() as conn:
        row_count = update_admin_flags(
            conn,
            target_user_id,
            is_admin=payload.isAdmin,
            is_disabled=payload.isDisabled,
        )
        if row_count == 0:
            raise HTTPException(status_code=404, detail="User not found")
        audit(
            conn,
            request,
            user["id"],
            "admin.user_update",
            {"target_user_id": target_user_id, "is_admin": payload.isAdmin, "is_disabled": payload.isDisabled},
        )
    return {"ok": True}


@router.get("/settings")
def admin_get_settings(user: dict[str, Any] = Depends(admin_user)) -> dict[str, Any]:
    with db_session() as conn:
        registration_enabled = get_registration_enabled(conn)
    return {"settings": {"registrationEnabled": registration_enabled}, "adminUserId": user["id"]}


@router.put("/settings")
def admin_update_settings(
    payload: SettingsPatch,
    request: Request,
    user: dict[str, Any] = Depends(admin_user),
) -> dict[str, Any]:
    with db_session() as conn:
        set_registration_enabled(conn, payload.registrationEnabled)
        audit(conn, request, user["id"], "admin.settings_update", {"registration_enabled": payload.registrationEnabled})
    return {"ok": True}


@router.get("/audit")
def admin_audit(user: dict[str, Any] = Depends(admin_user)) -> dict[str, Any]:
    with db_session() as conn:
        rows = list_audit_events(conn)
    return {"events": [serialize_audit_event(row) for row in rows], "adminUserId": user["id"]}


@router.get("/backups")
def list_backups(user: dict[str, Any] = Depends(admin_user)) -> dict[str, Any]:
    files = sorted(settings.backup_dir.glob("*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
    return {
        "backups": [
            {"name": path.name, "size": path.stat().st_size, "modifiedAt": path.stat().st_mtime}
            for path in files[:50]
        ],
        "adminUserId": user["id"],
    }


@router.post("/backups", status_code=201)
def make_backup(request: Request, user: dict[str, Any] = Depends(admin_user)) -> dict[str, Any]:
    archive = create_backup()
    verification = verify_backup(archive)
    with db_session() as conn:
        audit(conn, request, user["id"], "admin.backup_create", {"archive": archive.name, "verified": verification["ok"]})
    return {"backup": {"name": archive.name, "size": archive.stat().st_size}, "verification": verification}
