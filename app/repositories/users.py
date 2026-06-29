from __future__ import annotations

import sqlite3
from typing import Optional


def count_users(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])


def get_user_by_id(conn: sqlite3.Connection, user_id: int | str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def find_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def find_active_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT id FROM users WHERE email = ? AND is_disabled = 0", (email,)).fetchone()


def lookup_active_user(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT id, email, display_name, public_key FROM users WHERE email = ? AND is_disabled = 0",
        (email,),
    ).fetchone()


def create_user(
    conn: sqlite3.Connection,
    *,
    email: str,
    display_name: str,
    auth_verifier: str,
    kdf_salt: str,
    kdf_iterations: int,
    public_key: str,
    encrypted_private_key: str,
    is_admin: bool,
) -> int:
    cursor = conn.execute(
        """
        INSERT INTO users(
            email, display_name, auth_verifier, kdf_salt, kdf_iterations,
            public_key, encrypted_private_key, is_admin
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            email,
            display_name,
            auth_verifier,
            kdf_salt,
            kdf_iterations,
            public_key,
            encrypted_private_key,
            1 if is_admin else 0,
        ),
    )
    return int(cursor.lastrowid)


def update_last_login(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute("UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))


def bump_session_version(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute(
        """
        UPDATE users
        SET session_version = session_version + 1,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (user_id,),
    )


def set_totp_pending_ciphertext(conn: sqlite3.Connection, user_id: int, ciphertext: str) -> None:
    conn.execute(
        "UPDATE users SET totp_pending_ciphertext = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (ciphertext, user_id),
    )


def get_totp_pending_ciphertext(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    row = conn.execute("SELECT totp_pending_ciphertext FROM users WHERE id = ?", (user_id,)).fetchone()
    return row["totp_pending_ciphertext"] if row else None


def get_totp_secret_ciphertext(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    row = conn.execute("SELECT totp_secret_ciphertext FROM users WHERE id = ?", (user_id,)).fetchone()
    return row["totp_secret_ciphertext"] if row else None


def enable_totp(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute(
        """
        UPDATE users
        SET totp_enabled = 1,
            totp_secret_ciphertext = totp_pending_ciphertext,
            totp_pending_ciphertext = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (user_id,),
    )


def disable_totp(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute(
        """
        UPDATE users
        SET totp_enabled = 0,
            totp_secret_ciphertext = NULL,
            totp_pending_ciphertext = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (user_id,),
    )


def list_admin_users(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT id, email, display_name, is_admin, is_disabled, totp_enabled, created_at, last_login_at
        FROM users
        ORDER BY created_at DESC
        """
    ).fetchall()


def update_admin_flags(
    conn: sqlite3.Connection,
    target_user_id: int,
    *,
    is_admin: Optional[bool],
    is_disabled: Optional[bool],
) -> int:
    updates = [
        (column, int(value))
        for column, value in {"is_admin": is_admin, "is_disabled": is_disabled}.items()
        if value is not None
    ]
    if not updates:
        return 0

    assignments = ", ".join(f"{column} = ?" for column, _value in updates)
    values = [value for _column, value in updates]
    result = conn.execute(
        f"UPDATE users SET {assignments}, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        [*values, target_user_id],
    )
    return int(result.rowcount)
