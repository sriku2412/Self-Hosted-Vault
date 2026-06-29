#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

archive="$(docker compose exec -T app python -m app.maintenance backup | tr -d '\r')"
echo "Created backup: $archive"
docker compose exec -T app python -m app.maintenance verify "$archive"

