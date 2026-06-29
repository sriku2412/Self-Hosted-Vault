from __future__ import annotations

import sqlite3
from typing import Optional


def list_accessible_items(conn: sqlite3.Connection, user_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT vi.*
        FROM vault_items vi
        WHERE vi.deleted_at IS NULL
          AND vi.collection_id IS NULL
          AND vi.owner_user_id = ?
        UNION
        SELECT vi.*
        FROM vault_items vi
        JOIN collection_members cm ON cm.collection_id = vi.collection_id
        WHERE vi.deleted_at IS NULL
          AND cm.user_id = ?
        ORDER BY updated_at DESC, id DESC
        """,
        (user_id, user_id),
    ).fetchall()


def get_active_item(conn: sqlite3.Connection, item_id: int) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM vault_items WHERE id = ? AND deleted_at IS NULL",
        (item_id,),
    ).fetchone()


def create_item(
    conn: sqlite3.Connection,
    *,
    owner_user_id: int,
    folder_id: Optional[int],
    collection_id: Optional[int],
    encrypted_payload: str,
) -> int:
    cursor = conn.execute(
        """
        INSERT INTO vault_items(owner_user_id, folder_id, collection_id, encrypted_payload)
        VALUES(?, ?, ?, ?)
        """,
        (owner_user_id, folder_id, collection_id, encrypted_payload),
    )
    return int(cursor.lastrowid)


def update_item(
    conn: sqlite3.Connection,
    *,
    item_id: int,
    folder_id: Optional[int],
    encrypted_payload: str,
) -> None:
    conn.execute(
        """
        UPDATE vault_items
        SET encrypted_payload = ?,
            folder_id = ?,
            version = version + 1,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (encrypted_payload, folder_id, item_id),
    )


def soft_delete_item(conn: sqlite3.Connection, item_id: int) -> None:
    conn.execute("UPDATE vault_items SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?", (item_id,))

