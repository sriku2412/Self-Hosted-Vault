from __future__ import annotations

import sqlite3
from typing import Optional


def list_user_folders(conn: sqlite3.Connection, user_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM folders WHERE user_id = ? ORDER BY updated_at DESC, id DESC",
        (user_id,),
    ).fetchall()


def get_user_folder(conn: sqlite3.Connection, folder_id: int, user_id: int) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT id FROM folders WHERE id = ? AND user_id = ?",
        (folder_id, user_id),
    ).fetchone()


def create_folder(conn: sqlite3.Connection, user_id: int, encrypted_name: str) -> int:
    cursor = conn.execute(
        "INSERT INTO folders(user_id, encrypted_name) VALUES(?, ?)",
        (user_id, encrypted_name),
    )
    return int(cursor.lastrowid)


def update_folder(conn: sqlite3.Connection, folder_id: int, user_id: int, encrypted_name: str) -> int:
    result = conn.execute(
        """
        UPDATE folders
        SET encrypted_name = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND user_id = ?
        """,
        (encrypted_name, folder_id, user_id),
    )
    return int(result.rowcount)


def clear_folder_items(conn: sqlite3.Connection, folder_id: int, user_id: int) -> None:
    conn.execute(
        "UPDATE vault_items SET folder_id = NULL WHERE folder_id = ? AND owner_user_id = ?",
        (folder_id, user_id),
    )


def delete_folder(conn: sqlite3.Connection, folder_id: int, user_id: int) -> int:
    result = conn.execute(
        "DELETE FROM folders WHERE id = ? AND user_id = ?",
        (folder_id, user_id),
    )
    return int(result.rowcount)

