from __future__ import annotations

import json
import sqlite3
from typing import Any, Optional


def record_audit_event(
    conn: sqlite3.Connection,
    user_id: Optional[int],
    action: str,
    ip: str,
    detail: Optional[dict[str, Any]] = None,
) -> None:
    conn.execute(
        "INSERT INTO audit_events(user_id, action, ip, detail) VALUES(?, ?, ?, ?)",
        (user_id, action, ip, json.dumps(detail or {}, separators=(",", ":"))),
    )


def list_audit_events(conn: sqlite3.Connection, limit: int = 200) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT ae.id, ae.user_id, u.email, ae.action, ae.ip, ae.detail, ae.created_at
        FROM audit_events ae
        LEFT JOIN users u ON u.id = ae.user_id
        ORDER BY ae.created_at DESC, ae.id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

