from __future__ import annotations

import sqlite3

from fastapi import HTTPException

from .repositories.collections import get_collection_role


def require_collection_write(conn: sqlite3.Connection, collection_id: int, user_id: int) -> str:
    role = get_collection_role(conn, collection_id, user_id)
    if role not in {"owner", "admin", "member"}:
        raise HTTPException(status_code=403, detail="Collection write access required")
    return role


def require_collection_admin(conn: sqlite3.Connection, collection_id: int, user_id: int) -> str:
    role = get_collection_role(conn, collection_id, user_id)
    if role not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Collection admin access required")
    return role

