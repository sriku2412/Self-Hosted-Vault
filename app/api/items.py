from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from ..db import db_session
from ..deps import audit, current_user
from ..permissions import require_collection_write
from ..repositories.folders import get_user_folder
from ..repositories.items import (
    create_item as repo_create_item,
    get_active_item,
    list_accessible_items,
    soft_delete_item,
    update_item as repo_update_item,
)
from ..schemas import ItemRequest
from ..serializers import item as serialize_item
from ..validation import compact_json

router = APIRouter(prefix="/api/items", tags=["items"])


@router.get("")
def list_items(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    with db_session() as conn:
        rows = list_accessible_items(conn, user["id"])
    return {"items": [serialize_item(row) for row in rows]}


@router.post("", status_code=201)
def create_item(payload: ItemRequest, request: Request, user: dict[str, Any] = Depends(current_user)):
    encrypted_payload = compact_json(payload.encryptedPayload)
    with db_session() as conn:
        if payload.collectionId is not None:
            require_collection_write(conn, payload.collectionId, user["id"])
            folder_id = None
        else:
            folder_id = payload.folderId
            if folder_id is not None and not get_user_folder(conn, folder_id, user["id"]):
                raise HTTPException(status_code=422, detail="Folder not found")

        item_id = repo_create_item(
            conn,
            owner_user_id=user["id"],
            folder_id=folder_id,
            collection_id=payload.collectionId,
            encrypted_payload=encrypted_payload,
        )
        audit(conn, request, user["id"], "item.create", {"item_id": item_id, "collection_id": payload.collectionId})
    return {"id": item_id}


@router.patch("/{item_id}")
def update_item(
    item_id: int,
    payload: ItemRequest,
    request: Request,
    user: dict[str, Any] = Depends(current_user),
) -> dict[str, Any]:
    encrypted_payload = compact_json(payload.encryptedPayload)
    with db_session() as conn:
        row = get_active_item(conn, item_id)
        if not row:
            raise HTTPException(status_code=404, detail="Item not found")
        if row["collection_id"] is None:
            if row["owner_user_id"] != user["id"]:
                raise HTTPException(status_code=403, detail="Item access denied")
            folder_id = payload.folderId
            if folder_id is not None and not get_user_folder(conn, folder_id, user["id"]):
                raise HTTPException(status_code=422, detail="Folder not found")
        else:
            require_collection_write(conn, row["collection_id"], user["id"])
            folder_id = None

        repo_update_item(conn, item_id=item_id, folder_id=folder_id, encrypted_payload=encrypted_payload)
        audit(conn, request, user["id"], "item.update", {"item_id": item_id})
    return {"ok": True}


@router.delete("/{item_id}")
def delete_item(item_id: int, request: Request, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    with db_session() as conn:
        row = get_active_item(conn, item_id)
        if not row:
            raise HTTPException(status_code=404, detail="Item not found")
        if row["collection_id"] is None:
            if row["owner_user_id"] != user["id"]:
                raise HTTPException(status_code=403, detail="Item access denied")
        else:
            require_collection_write(conn, row["collection_id"], user["id"])

        soft_delete_item(conn, item_id)
        audit(conn, request, user["id"], "item.delete", {"item_id": item_id})
    return {"ok": True}
