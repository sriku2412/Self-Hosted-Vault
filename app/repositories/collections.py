from __future__ import annotations

import sqlite3
from typing import Optional


def get_collection_role(conn: sqlite3.Connection, collection_id: int, user_id: int) -> Optional[str]:
    row = conn.execute(
        "SELECT role FROM collection_members WHERE collection_id = ? AND user_id = ?",
        (collection_id, user_id),
    ).fetchone()
    return row["role"] if row else None


def list_user_collections(conn: sqlite3.Connection, user_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT c.*, cm.role, cm.encrypted_collection_key
        FROM collections c
        JOIN collection_members cm ON cm.collection_id = c.id
        WHERE cm.user_id = ?
        ORDER BY c.updated_at DESC, c.id DESC
        """,
        (user_id,),
    ).fetchall()


def list_collection_members(conn: sqlite3.Connection, collection_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT cm.user_id, cm.role, u.email, u.display_name
        FROM collection_members cm
        JOIN users u ON u.id = cm.user_id
        WHERE cm.collection_id = ?
        ORDER BY cm.role, u.email
        """,
        (collection_id,),
    ).fetchall()


def create_collection(conn: sqlite3.Connection, owner_user_id: int, encrypted_name: str) -> int:
    cursor = conn.execute(
        "INSERT INTO collections(owner_user_id, encrypted_name) VALUES(?, ?)",
        (owner_user_id, encrypted_name),
    )
    return int(cursor.lastrowid)


def upsert_member(
    conn: sqlite3.Connection,
    *,
    collection_id: int,
    user_id: int,
    role: str,
    encrypted_collection_key: str,
) -> None:
    conn.execute(
        """
        INSERT INTO collection_members(collection_id, user_id, role, encrypted_collection_key)
        VALUES(?, ?, ?, ?)
        ON CONFLICT(collection_id, user_id)
        DO UPDATE SET role = excluded.role,
                      encrypted_collection_key = excluded.encrypted_collection_key,
                      updated_at = CURRENT_TIMESTAMP
        """,
        (collection_id, user_id, role, encrypted_collection_key),
    )


def count_owners(conn: sqlite3.Connection, collection_id: int) -> int:
    return int(
        conn.execute(
            "SELECT COUNT(*) FROM collection_members WHERE collection_id = ? AND role = 'owner'",
            (collection_id,),
        ).fetchone()[0]
    )


def remove_member(conn: sqlite3.Connection, collection_id: int, user_id: int) -> None:
    conn.execute(
        "DELETE FROM collection_members WHERE collection_id = ? AND user_id = ?",
        (collection_id, user_id),
    )
