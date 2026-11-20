#!/usr/bin/env bash
# Тесты хранения состояния keyguard на настоящем Postgres: поднимает одноразовую базу в контейнере (порт только на
# 127.0.0.1, без тома), прогоняет TestIntegration_Postgres и удаляет контейнер.
#   scripts/pg_test.sh            # нужны docker и go
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE="${PG_IMAGE:-postgres:18-alpine}"; NAME="keyguard-pg-test-$$"
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
docker run -d --name "$NAME" -e POSTGRES_USER=keyguard -e POSTGRES_PASSWORD=test -e POSTGRES_DB=keyguard -p 127.0.0.1::5432 "$IMAGE" >/dev/null
PORT=$(docker port "$NAME" 5432/tcp | head -1 | sed 's/.*://')
for _ in $(seq 60); do docker exec "$NAME" pg_isready -q -U keyguard -d keyguard 2>/dev/null && break; sleep 1; done
sleep 1   # образ перезапускает сервер после инициализации
for _ in $(seq 30); do docker exec "$NAME" psql -q -U keyguard -d keyguard -c 'select 1' >/dev/null 2>&1 && break; sleep 1; done
KG_TEST_PG_DSN="postgres://keyguard:test@127.0.0.1:$PORT/keyguard?sslmode=disable" go test -count=1 -race -run 'TestIntegration_Postgres' -v . \
  | grep -vE '^\s+\S+\.go:[0-9]+: PASS'
