from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from ..db import db_session
from ..deps import audit, current_user
from ..permissions import require_collection_admin
from ..repositories.collections import (
    count_owners,
    create_collection as repo_create_collection,
    get_collection_role,
    list_collection_members,
    list_user_collections,
    remove_member,
    upsert_member,
)
from ..repositories.users import find_active_user_by_email
from ..schemas import CollectionRequest, MemberRequest
from ..serializers import collection as serialize_collection
from ..validation import compact_json, normalize_email

router = APIRouter(prefix="/api/collections", tags=["collections"])


@router.get("")
def list_collections(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    with db_session() as conn:
        rows = list_user_collections(conn, user["id"])
        collections = [
            serialize_collection(row, list_collection_members(conn, row["id"]))
            for row in rows
        ]
    return {"collections": collections}


@router.post("", status_code=201)
def create_collection(
    payload: CollectionRequest,
    request: Request,
    user: dict[str, Any] = Depends(current_user),
) -> dict[str, Any]:
    encrypted_name = compact_json(payload.encryptedName)
    with db_session() as conn:
        collection_id = repo_create_collection(conn, user["id"], encrypted_name)
        upsert_member(
            conn,
            collection_id=collection_id,
            user_id=user["id"],
            role="owner",
            encrypted_collection_key=payload.encryptedCollectionKey,
        )
        audit(conn, request, user["id"], "collection.create", {"collection_id": collection_id})
    return {"id": collection_id}


@router.post("/{collection_id}/members", status_code=201)
def add_collection_member(
    collection_id: int,
    payload: MemberRequest,
    request: Request,
    user: dict[str, Any] = Depends(current_user),
) -> dict[str, Any]:
    email = normalize_email(payload.email)
    with db_session() as conn:
        require_collection_admin(conn, collection_id, user["id"])
        target = find_active_user_by_email(conn, email)
        if not target:
            raise HTTPException(status_code=404, detail="User not found")
        upsert_member(
            conn,
            collection_id=collection_id,
            user_id=target["id"],
            role=payload.role,
            encrypted_collection_key=payload.encryptedCollectionKey,
        )
        audit(
            conn,
            request,
            user["id"],
            "collection.member_upsert",
            {"collection_id": collection_id, "member_user_id": target["id"], "role": payload.role},
        )
    return {"ok": True}


@router.delete("/{collection_id}/members/{member_user_id}")
def remove_collection_member(
    collection_id: int,
    member_user_id: int,
    request: Request,
    user: dict[str, Any] = Depends(current_user),
) -> dict[str, Any]:
    with db_session() as conn:
        role = require_collection_admin(conn, collection_id, user["id"])
        member_role = get_collection_role(conn, collection_id, member_user_id)
        if not member_role:
            raise HTTPException(status_code=404, detail="Member not found")
        if member_role == "owner" and role != "owner":
            raise HTTPException(status_code=403, detail="Only an owner can remove another owner")
        if member_role == "owner" and count_owners(conn, collection_id) <= 1:
            raise HTTPException(status_code=422, detail="Cannot remove the last owner")

        remove_member(conn, collection_id, member_user_id)
        audit(
            conn,
            request,
            user["id"],
            "collection.member_remove",
            {"collection_id": collection_id, "member_user_id": member_user_id},
        )
    return {"ok": True}
