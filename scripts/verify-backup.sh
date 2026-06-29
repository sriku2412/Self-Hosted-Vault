#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

archive="${1:-}"
if [ -z "$archive" ]; then
  archive="$(ls -t backups/*.tar.gz 2>/dev/null | head -n 1 || true)"
fi

if [ -z "$archive" ]; then
  echo "No backup archive found." >&2
  exit 1
fi

docker compose exec -T app python -m app.maintenance verify "/backups/$(basename "$archive")"

