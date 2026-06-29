# Backup And Restore

Backups use SQLite's online backup API, then package the database copy and metadata in a `tar.gz` archive. Verification runs `PRAGMA integrity_check` and confirms required tables exist.

## Create A Backup

```sh
scripts/backup.sh
```

The archive appears in `backups/` and is also visible inside the container at `/backups`.

## Verify A Backup

Verify the newest archive:

```sh
scripts/verify-backup.sh
```

Verify a specific archive:

```sh
scripts/verify-backup.sh backups/vault-YYYYMMDDTHHMMSSZ.tar.gz
```

Expected output includes:

```json
{
  "ok": true,
  "integrity": "ok",
  "missing_tables": []
}
```

## Restore

```sh
scripts/restore.sh backups/vault-YYYYMMDDTHHMMSSZ.tar.gz
```

The restore script:

1. Verifies the archive.
2. Stops the app container.
3. Copies the current database to a `pre-restore` file.
4. Restores the selected database.
5. Starts the app container.

## Restore Drill

Run this after first setup and after changing backup storage:

```sh
scripts/backup.sh
latest="$(ls -t backups/*.tar.gz | head -n 1)"
scripts/verify-backup.sh "$latest"
scripts/restore.sh "$latest"
docker compose ps
```

Sign in and confirm that users, folders, personal items, and shared vaults decrypt correctly.

## Offsite Copies

Copy `backups/*.tar.gz` to storage that is not on the Docker host. The backup still contains encrypted vault data, but protect it as sensitive because it includes account metadata and auth verifiers.

