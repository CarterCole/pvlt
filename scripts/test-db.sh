#!/usr/bin/env bash
# A throwaway Postgres for the pvlt-server Postgres tests. Loopback only, data in memory, gone when stopped.
#
#   scripts/test-db.sh start    start it (uses a local image; pulls nothing unless the image is missing)
#   scripts/test-db.sh url      print the connection URL
#   scripts/test-db.sh stop     remove it
#
# Then:  PVLT_TEST_DATABASE_URL=$(scripts/test-db.sh url) cargo test -p pvlt-server -- --include-ignored
#
# Defaults to PostgreSQL 17. Set PVLT_TEST_PG_IMAGE (for example postgres:18-alpine or postgres:15-alpine) to test
# another major version.
set -euo pipefail

NAME=pvlt-test-pg
PORT=54329
IMAGE=${PVLT_TEST_PG_IMAGE:-postgres:17-alpine}
URL="postgres://postgres:pvlt-test@127.0.0.1:${PORT}/postgres"

case "${1:-}" in
  start)
    if docker ps --format '{{.Names}}' | grep -qx "$NAME"; then echo "already running"; exit 0; fi
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:5432" \
      -e POSTGRES_PASSWORD=pvlt-test --tmpfs /var/lib/postgresql/data \
      "$IMAGE" -c fsync=off -c full_page_writes=off -c max_connections=200 >/dev/null
    for _ in $(seq 1 60); do
      if docker exec "$NAME" pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1; then echo "ready: $URL"; exit 0; fi
      sleep 0.5
    done
    echo "postgres did not become ready" >&2; docker logs "$NAME" >&2; exit 1 ;;
  url) echo "$URL" ;;
  stop) docker rm -f "$NAME" >/dev/null 2>&1 && echo "stopped" || echo "not running" ;;
  *) echo "usage: $0 start|url|stop" >&2; exit 2 ;;
esac
