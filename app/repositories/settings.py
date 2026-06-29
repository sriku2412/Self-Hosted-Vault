from __future__ import annotations

import sqlite3

from ..config import settings


def get_setting(conn: sqlite3.Connection, key: str, default: str) -> str:
    row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        """
        INSERT INTO app_settings(key, value, updated_at)
        VALUES(?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
        """,
        (key, value),
    )


def get_registration_enabled(conn: sqlite3.Connection) -> bool:
    return get_setting(conn, "registration_enabled", str(settings.registration_enabled_default).lower()) == "true"


def set_registration_enabled(conn: sqlite3.Connection, enabled: bool) -> None:
    set_setting(conn, "registration_enabled", str(enabled).lower())
