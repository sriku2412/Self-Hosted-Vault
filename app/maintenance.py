from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import settings


REQUIRED_TABLES = {
    "users",
    "folders",
    "collections",
    "collection_members",
    "vault_items",
    "app_settings",
    "audit_events",
}


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def create_backup(db_path: Optional[Path] = None, backup_dir: Optional[Path] = None) -> Path:
    source_path = db_path or settings.database_path
    target_dir = backup_dir or settings.backup_dir
    target_dir.mkdir(parents=True, exist_ok=True)
    stamp = utc_stamp()
    sqlite_copy = target_dir / f"vault-{stamp}.sqlite3"
    metadata_path = target_dir / f"vault-{stamp}.metadata.json"
    archive_path = target_dir / f"vault-{stamp}.tar.gz"

    with sqlite3.connect(source_path) as source, sqlite3.connect(sqlite_copy) as target:
        source.backup(target)

    metadata = {
        "created_at": stamp,
        "database": sqlite_copy.name,
        "app": "selfhosted-vault",
        "format": 1,
    }
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(sqlite_copy, arcname=sqlite_copy.name)
        archive.add(metadata_path, arcname=metadata_path.name)

    sqlite_copy.unlink(missing_ok=True)
    metadata_path.unlink(missing_ok=True)
    return archive_path


def _extract_database(archive_path: Path, target_dir: Path) -> Path:
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        for member in members:
            destination = (target_dir / member.name).resolve()
            if not str(destination).startswith(str(target_dir.resolve())):
                raise ValueError("Unsafe path in backup archive")
        archive.extractall(target_dir)
    sqlite_files = list(target_dir.glob("*.sqlite3"))
    if len(sqlite_files) != 1:
        raise ValueError("Backup archive must contain exactly one SQLite database")
    return sqlite_files[0]


def verify_backup(archive_path: Path) -> dict[str, object]:
    with tempfile.TemporaryDirectory() as tmp:
        db_file = _extract_database(archive_path, Path(tmp))
        with sqlite3.connect(db_file) as conn:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            }
            missing = sorted(REQUIRED_TABLES - tables)
            user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            item_count = conn.execute(
                "SELECT COUNT(*) FROM vault_items WHERE deleted_at IS NULL"
            ).fetchone()[0]
    ok = integrity == "ok" and not missing
    return {
        "ok": ok,
        "integrity": integrity,
        "missing_tables": missing,
        "users": user_count,
        "items": item_count,
        "archive": str(archive_path),
    }


def restore_backup(archive_path: Path, db_path: Optional[Path] = None) -> Path:
    destination = db_path or settings.database_path
    result = verify_backup(archive_path)
    if not result["ok"]:
        raise ValueError(f"Backup verification failed: {result}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    pre_restore = destination.with_suffix(f".pre-restore-{utc_stamp()}.sqlite3")
    if destination.exists():
        shutil.copy2(destination, pre_restore)

    with tempfile.TemporaryDirectory() as tmp:
        db_file = _extract_database(archive_path, Path(tmp))
        shutil.copy2(db_file, destination)
    return pre_restore


def main() -> None:
    parser = argparse.ArgumentParser(description="Vault backup and restore tools")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("backup")
    verify = sub.add_parser("verify")
    verify.add_argument("archive")
    restore = sub.add_parser("restore")
    restore.add_argument("archive")
    args = parser.parse_args()

    if args.command == "backup":
        print(create_backup())
    elif args.command == "verify":
        print(json.dumps(verify_backup(Path(args.archive)), indent=2))
    elif args.command == "restore":
        pre_restore = restore_backup(Path(args.archive))
        print(f"restored; previous database copy: {pre_restore}")


if __name__ == "__main__":
    main()
