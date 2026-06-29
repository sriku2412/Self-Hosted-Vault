from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from ..db import db_session
from ..deps import audit, current_user
from ..repositories.folders import (
    clear_folder_items,
    create_folder as repo_create_folder,
    delete_folder as repo_delete_folder,
    get_user_folder,
    list_user_folders,
    update_folder as repo_update_folder,
)
from ..schemas import FolderRequest
from ..serializers import folder as serialize_folder
from ..validation import compact_json

router = APIRouter(prefix="/api/folders", tags=["folders"])


@router.get("")
def list_folders(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    with db_session() as conn:
        rows = list_user_folders(conn, user["id"])
    return {"folders": [serialize_folder(row) for row in rows]}


@router.post("", status_code=201)
def create_folder(payload: FolderRequest, request: Request, user: dict[str, Any] = Depends(current_user)):
    encrypted_name = compact_json(payload.encryptedName)
    with db_session() as conn:
        folder_id = repo_create_folder(conn, user["id"], encrypted_name)
        audit(conn, request, user["id"], "folder.create", {"folder_id": folder_id})
    return {"id": folder_id}


@router.patch("/{folder_id}")
def update_folder(
    folder_id: int,
    payload: FolderRequest,
    request: Request,
    user: dict[str, Any] = Depends(current_user),
):
    encrypted_name = compact_json(payload.encryptedName)
    with db_session() as conn:
        row_count = repo_update_folder(conn, folder_id, user["id"], encrypted_name)
        if row_count == 0:
            raise HTTPException(status_code=404, detail="Folder not found")
        audit(conn, request, user["id"], "folder.update", {"folder_id": folder_id})
    return {"ok": True}


@router.delete("/{folder_id}")
def delete_folder(folder_id: int, request: Request, user: dict[str, Any] = Depends(current_user)):
    with db_session() as conn:
        if not get_user_folder(conn, folder_id, user["id"]):
            raise HTTPException(status_code=404, detail="Folder not found")
        clear_folder_items(conn, folder_id, user["id"])
        repo_delete_folder(conn, folder_id, user["id"])
        audit(conn, request, user["id"], "folder.delete", {"folder_id": folder_id})
    return {"ok": True}
