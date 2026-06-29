from __future__ import annotations

import sqlite3

STAT_QUERIES = {
    "users": "SELECT COUNT(*) FROM users",
    "activeUsers": "SELECT COUNT(*) FROM users WHERE is_disabled = 0",
    "items": "SELECT COUNT(*) FROM vault_items WHERE deleted_at IS NULL",
    "collections": "SELECT COUNT(*) FROM collections",
    "folders": "SELECT COUNT(*) FROM folders",
}


def get_stats(conn: sqlite3.Connection) -> dict[str, int]:
    return {name: conn.execute(query).fetchone()[0] for name, query in STAT_QUERIES.items()}
