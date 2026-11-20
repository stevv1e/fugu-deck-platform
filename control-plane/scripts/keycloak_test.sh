#!/usr/bin/env bash
# Тест control-plane на НАСТОЯЩЕМ Keycloak: сервисная учётная запись deck-control-plane создаёт пользователя под
# приглашение и ничего сверх этого сделать не может. Поднимает одноразовый Keycloak в контейнере (порт только на
# 127.0.0.1). Нужны docker, go, jq, curl.
#   scripts/keycloak_test.sh
set -euo pipefail
cd "$(dirname "$0")/.."
KC_IMAGE="${KC_IMAGE:-quay.io/keycloak/keycloak:26.7.5}"      # = версия Keycloak в fugu-deck-infra
NAME="deck-cp-kc-test-$$"
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT

echo "== Keycloak ($KC_IMAGE)"
docker run -d --name "$NAME" -p 127.0.0.1::8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin-pass \
  "$KC_IMAGE" start-dev --features=dpop >/dev/null
PORT=$(docker port "$NAME" 8080/tcp | head -1 | sed 's/.*://')
KC="http://127.0.0.1:$PORT"
for _ in $(seq 120); do curl -fsS -o /dev/null "$KC/realms/master" 2>/dev/null && break; sleep 2; done
curl -fsS -o /dev/null "$KC/realms/master" || { docker logs --tail 30 "$NAME"; echo "Keycloak не поднялся" >&2; exit 1; }

ADM=$(curl -fsS -d client_id=admin-cli -d username=admin -d password=admin-pass -d grant_type=password \
  "$KC/realms/master/protocol/openid-connect/token" | jq -r .access_token)
api() { curl -fsS -H "Authorization: Bearer $ADM" -H "Content-Type: application/json" "$@"; }
SECRET=$(head -c 24 /dev/urandom | base64 | tr -d '/+=')
api -X POST "$KC/admin/realms" -d '{"realm":"deck","enabled":true}'
# Клиент и роль — как в kubernetes/platform/keycloak/realms.yaml: только manage-users из realm-management.
api -X POST "$KC/admin/realms/deck/clients" -d "{\"clientId\":\"deck-control-plane\",\"publicClient\":false,\"secret\":\"$SECRET\",
  \"serviceAccountsEnabled\":true,\"standardFlowEnabled\":false,\"directAccessGrantsEnabled\":false,\"implicitFlowEnabled\":false,\"fullScopeAllowed\":false}"
CID=$(api "$KC/admin/realms/deck/clients?clientId=deck-control-plane" | jq -r '.[0].id')
SA=$(api "$KC/admin/realms/deck/clients/$CID/service-account-user" | jq -r .id)
RM=$(api "$KC/admin/realms/deck/clients?clientId=realm-management" | jq -r '.[0].id')
ROLE=$(api "$KC/admin/realms/deck/clients/$RM/roles/manage-users")
api -X POST "$KC/admin/realms/deck/users/$SA/role-mappings/clients/$RM" -d "[$ROLE]"
# fullScopeAllowed=false: роль должна быть и в области клиента, иначе в токен она не попадёт.
api -X POST "$KC/admin/realms/deck/clients/$CID/scope-mappings/clients/$RM" -d "[$ROLE]"

CP_KC_URL="$KC" CP_KC_SECRET="$SECRET" go test -count=1 -run TestKeycloak -v . | grep -vE '^=== RUN'
