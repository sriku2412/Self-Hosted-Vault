#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

scripts/backup.sh
docker compose pull || true
docker compose build --pull
docker compose up -d
scripts/verify-backup.sh
docker compose ps

