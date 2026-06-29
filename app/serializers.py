from __future__ import annotations

import json
from typing import Any

from .validation import read_compact_json


def public_user(row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "email": row["email"],
        "displayName": row["display_name"],
        "isAdmin": bool(row["is_admin"]),
        "totpEnabled": bool(row["totp_enabled"]),
        "kdfSalt": row["kdf_salt"],
        "kdfIterations": row["kdf_iterations"],
        "publicKey": row["public_key"],
        "encryptedPrivateKey": read_compact_json(row["encrypted_private_key"]),
    }


def folder(row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "encryptedName": read_compact_json(row["encrypted_name"]),
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }


def item(row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "folderId": row["folder_id"],
        "collectionId": row["collection_id"],
        "ownerUserId": row["owner_user_id"],
        "encryptedPayload": read_compact_json(row["encrypted_payload"]),
        "version": row["version"],
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }


def collection(row, members) -> dict[str, Any]:
    return {
        "id": row["id"],
        "ownerUserId": row["owner_user_id"],
        "encryptedName": read_compact_json(row["encrypted_name"]),
        "role": row["role"],
        "encryptedCollectionKey": row["encrypted_collection_key"],
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
        "members": [collection_member(member) for member in members],
    }


def collection_member(row) -> dict[str, Any]:
    return {
        "userId": row["user_id"],
        "email": row["email"],
        "displayName": row["display_name"],
        "role": row["role"],
    }


def lookup_user(row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "email": row["email"],
        "displayName": row["display_name"],
        "publicKey": row["public_key"],
    }


def admin_user(row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "email": row["email"],
        "displayName": row["display_name"],
        "isAdmin": bool(row["is_admin"]),
        "isDisabled": bool(row["is_disabled"]),
        "totpEnabled": bool(row["totp_enabled"]),
        "createdAt": row["created_at"],
        "lastLoginAt": row["last_login_at"],
    }


def audit_event(row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "userId": row["user_id"],
        "email": row["email"],
        "action": row["action"],
        "ip": row["ip"],
        "detail": json.loads(row["detail"] or "{}"),
        "createdAt": row["created_at"],
    }

