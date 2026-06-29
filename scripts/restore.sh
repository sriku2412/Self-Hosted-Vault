#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

archive="${1:-}"
if [ -z "$archive" ]; then
  echo "Usage: scripts/restore.sh backups/vault-YYYYMMDDTHHMMSSZ.tar.gz" >&2
  exit 1
fi

name="$(basename "$archive")"

docker compose run --rm --no-deps app python -m app.maintenance verify "/backups/$name"
docker compose stop app
docker compose run --rm --no-deps app python -m app.maintenance restore "/backups/$name"
docker compose up -d app
docker compose ps

