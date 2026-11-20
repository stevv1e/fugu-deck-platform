#!/usr/bin/env bash
# Проверка модуля deck-invite на НАСТОЯЩЕМ Keycloak с realm deck из kubernetes/platform/keycloak/realms.yaml:
#   - приглашённый без passkey попадает на регистрацию passkey; без приглашения и с чужим ником — на обычный вход;
#   - сервисная учётная запись control-plane из этого realm создаёт пользователя и не может большего.
# Собирает модуль в контейнере, поднимает одноразовый Keycloak (порт только на 127.0.0.1). Нужны docker, go, jq, curl, python3-yaml.
#   images/keycloak/test.sh
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)
KC_IMAGE=$(sed -nE 's/^FROM (quay.io\/keycloak\/keycloak:[0-9.]+) AS build$/\1/p' Dockerfile)
NAME="deck-kc-invite-test-$$"; WORK=$(mktemp -d)
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT
FAIL=0
ok()  { echo "  ✓ $1"; }
bad() { echo "  ✗ $1"; FAIL=1; }

echo "== сборка модуля"
docker build -q --target provider -t deck-invite-provider:test . >/dev/null
CID=$(docker create deck-invite-provider:test); docker cp "$CID:/src/target/deck-invite.jar" "$WORK/deck-invite.jar" >/dev/null; docker rm "$CID" >/dev/null
chmod 644 "$WORK/deck-invite.jar"

echo "== Keycloak ($KC_IMAGE) с модулем и темой"
docker run -d --name "$NAME" -p 127.0.0.1::8080 -v "$WORK/deck-invite.jar:/opt/keycloak/providers/deck-invite.jar:ro" \
  -v "$ROOT/images/keycloak/theme/fugu:/opt/keycloak/themes/fugu:ro" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin-pass \
  "$KC_IMAGE" start-dev --features=dpop,passkeys >/dev/null
PORT=$(docker port "$NAME" 8080/tcp | head -1 | sed 's/.*://'); KC="http://127.0.0.1:$PORT"
for _ in $(seq 150); do curl -fsS -o /dev/null "$KC/realms/master" 2>/dev/null && break; sleep 2; done
curl -fsS -o /dev/null "$KC/realms/master" || { docker logs --tail 40 "$NAME"; echo "Keycloak не поднялся" >&2; exit 1; }

ADM=$(curl -fsS -d client_id=admin-cli -d username=admin -d password=admin-pass -d grant_type=password \
  "$KC/realms/master/protocol/openid-connect/token" | jq -r .access_token)
api() { curl -fsS -H "Authorization: Bearer $ADM" -H "Content-Type: application/json" "$@"; }
SECRET=$(head -c 24 /dev/urandom | base64 | tr -d '/+=')
# realm — тот же, что импортирует оператор; меняем только то, без чего он не живёт на http://127.0.0.1.
python3 - "$ROOT/kubernetes/platform/keycloak/realms.yaml" "$SECRET" > "$WORK/realm.json" <<'PY'
import json, sys, yaml
doc = next(d for d in yaml.safe_load_all(open(sys.argv[1])) if d["metadata"]["name"] == "deck")
realm = json.loads(json.dumps(doc["spec"]["realm"]).replace("${CP_CLIENT_SECRET}", sys.argv[2]))
realm["sslRequired"] = "none"
realm["webAuthnPolicyPasswordlessRpId"] = "127.0.0.1"
print(json.dumps(realm))
PY
api -X POST "$KC/admin/realms" -d @"$WORK/realm.json"
FLOW=$(api "$KC/admin/realms/deck/authentication/flows/deck-passkey/executions" | jq -r '[.[].providerId] | join(",")')
[[ $FLOW == "auth-cookie,deck-invite,webauthn-authenticator-passwordless" ]] && ok "поток входа: $FLOW" || bad "поток входа: $FLOW"

echo "== control-plane: сервисная учётная запись из этого realm"
if [[ -d "$ROOT/control-plane" ]]; then CP_DIR="$ROOT/control-plane"; else CP_DIR="$ROOT/../fugu-deck-control-plane"; fi
(cd "$CP_DIR" && CP_KC_URL="$KC" CP_KC_SECRET="$SECRET" go test -count=1 -run TestKeycloak . >/dev/null) \
  && ok "создаёт пользователя под приглашение; realm и клиентов менять не может" || bad "тест control-plane на этом realm"

echo "== первый вход"
AUTH="$KC/realms/deck/protocol/openid-connect/auth?client_id=deck-app&redirect_uri=fugudeck%3A%2F%2Foauth&response_type=code&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=s"
page() { curl -sS -L -c "$WORK/jar-$RANDOM" "$@" "$AUTH"; }
kind() { # какая страница пришла
  if grep -q 'webauthn-register\|registerByWebAuthn\|id="register"' <<<"$1"; then echo register
  elif grep -q 'authenticateByWebAuthn\|webauthn-authenticate\|id="webauth"' <<<"$1"; then echo login
  else echo other; fi
}
# newbie создан тестом control-plane: без пароля и passkey, с обязательной регистрацией passkey
NEWBIE=$(page -H 'X-Deck-Invite-Nick: newbie')
K=$(kind "$NEWBIE")
[[ $K == register ]] && ok "приглашённый без passkey → регистрация passkey" || bad "приглашённый без passkey → $K"
if grep -q 'id="registerPlatform"' <<<"$NEWBIE" && grep -q 'id="registerCrossPlatform"' <<<"$NEWBIE" \
  && grep -q "authenticatorAttachment: 'platform'" <<<"$NEWBIE" && grep -q "authenticatorAttachment: 'cross-platform'" <<<"$NEWBIE"; then
  ok "отдельный выбор Windows Hello/биометрии и телефона/USB"
else
  bad "на странице регистрации нет явного выбора platform/cross-platform"
fi
PENDING=$(page -H 'X-Deck-Invite-Nick: newbie' -H 'X-Deck-Pair-Status: pending')
if grep -q 'Подтверждение входа на ПК' <<<"$PENDING" && grep -q 'window.location.reload' <<<"$PENDING"; then
  ok "pairing ПК: pending показывает ожидание вместо WebAuthn"
else
  bad "pairing pending не открыл страницу ожидания"
fi
PAIRED=$(curl -sS -D - -o /dev/null -H 'X-Deck-Invite-Nick: newbie' -H 'X-Deck-Pair-Status: approved' "$AUTH" | tr -d '\r')
if grep -qi '^location: fugudeck://oauth?.*code=' <<<"$PAIRED"; then
  ok "pairing ПК: approved завершает обычный OAuth code flow"
else
  bad "pairing approved не выдал OAuth code: $(grep -i '^location:' <<<"$PAIRED")"
fi
LOGIN=$(page)
K=$(kind "$LOGIN")
[[ $K == login ]] && ok "без приглашения → обычный вход по passkey" || bad "без приглашения → $K"
if grep -q 'id="authenticatePlatform"' <<<"$LOGIN" && grep -q 'id="authenticateCrossPlatform"' <<<"$LOGIN" \
  && grep -q "hints: \['client-device'\]" <<<"$LOGIN" && grep -q "hints: \['hybrid', 'security-key'\]" <<<"$LOGIN"; then
  JS_PATH=$(grep -o '/resources/[^" ]*/js/webauthnAuthenticate.js' <<<"$LOGIN" | head -1)
  if curl -fsS "$KC$JS_PATH" | grep -q 'publicKey.hints = input.hints'; then
    ok "вход: Windows Hello через client-device; телефон/USB через hybrid/security-key"
  else
    bad "тема входа не отдаёт JS с WebAuthn hints"
  fi
else
  bad "на странице входа нет выбора Windows Hello и телефона/USB"
fi
K=$(kind "$(page -H 'X-Deck-Invite-Nick: nobody')")
[[ $K == login ]] && ok "приглашение на несуществующий ник → обычный вход" || bad "несуществующий ник → $K"
ADM=$(curl -fsS -d client_id=admin-cli -d username=admin -d password=admin-pass -d grant_type=password \
  "$KC/realms/master/protocol/openid-connect/token" | jq -r .access_token)
UID_=$(api "$KC/admin/realms/deck/users?exact=true&username=newbie" | jq -r '.[0].id')
api -X PUT "$KC/admin/realms/deck/users/$UID_" -d '{"enabled":false}'
K=$(kind "$(page -H 'X-Deck-Invite-Nick: newbie')")
[[ $K == login ]] && ok "заблокированный пользователь по приглашению не входит" || bad "заблокированный пользователь → $K"
echo "== образ запускается с параметрами оператора (--optimized)"
# Параметры времени сборки в Dockerfile обязаны совпасть с теми, что оператор передаёт из keycloak.yaml: иначе
# Keycloak с --optimized завершается сразу. Запускаем образ с этими параметрами; до базы он не дойдёт — и не должен.
docker build -q -t deck-keycloak:test . >/dev/null
python3 - "$ROOT/kubernetes/platform/keycloak/keycloak.yaml" > "$WORK/kc.env" <<'PY'
import sys, yaml
spec = yaml.safe_load(open(sys.argv[1]))["spec"]
env = {"KC_DB": spec["db"]["vendor"], "KC_HEALTH_ENABLED": "true", "KC_HTTP_ENABLED": "true", "KC_CACHE": "ispn",
       "KC_HOSTNAME": "https://id.deck.test", "KC_DB_URL_HOST": "127.0.0.1", "KC_DB_USERNAME": "u", "KC_DB_PASSWORD": "p",
       "KC_FEATURES": ",".join(spec["features"]["enabled"]), "KC_FEATURES_DISABLED": ",".join(spec["features"]["disabled"]),
       "KC_PROXY_HEADERS": spec["proxy"]["headers"]}
for o in spec.get("additionalOptions", []):
    env["KC_" + o["name"].upper().replace("-", "_")] = o["value"]
print("\n".join(f"{k}={v}" for k, v in env.items()))
PY
OUT=$(timeout 90 docker run --rm --env-file "$WORK/kc.env" deck-keycloak:test --verbose start --optimized 2>&1 || true)
if grep -q "build time options have values that differ" <<<"$OUT"; then bad "параметры сборки образа расходятся с оператором: $(grep -o 'is run: .*' <<<"$OUT" | head -1)"
elif grep -q "5432" <<<"$OUT"; then ok "образ принят: Keycloak дошёл до подключения к базе"
else bad "образ не дошёл до подключения к базе: $(tail -2 <<<"$OUT")"; fi

[[ $FAIL == 0 ]] && echo "deck-invite: всё в порядке" || { echo "deck-invite: есть ошибки"; exit 1; }
