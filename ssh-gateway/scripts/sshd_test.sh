#!/usr/bin/env bash
# ssh-gateway против НАСТОЯЩИХ OpenBao и sshd: сертификат из SSH CA (роль agent — как в terraform/openbao/main.tf)
# принимается сервером, настроенным теми же командами, что показывает приложение (TrustedUserCAKeys +
# AuthorizedPrincipalsFile); чужой principal, чужой адрес и чужой ключ хоста — нет.
# Нужны docker, go, curl, jq.   scripts/sshd_test.sh
set -euo pipefail
cd "$(dirname "$0")/.."
BAO_IMAGE="${BAO_IMAGE:-ghcr.io/openbao/openbao:2.4.4}"
NET="deck-gw-test-$$"; BAO="deck-gw-bao-$$"; SSHD="deck-gw-sshd-$$"
cleanup() { docker rm -f "$BAO" "$SSHD" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker network create "$NET" >/dev/null

echo "== OpenBao (dev): SSH CA и роль agent"
docker run -d --name "$BAO" --network "$NET" -p 127.0.0.1::8200 -e BAO_DEV_ROOT_TOKEN_ID=root -e BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  "$BAO_IMAGE" server -dev >/dev/null
BPORT=$(docker port "$BAO" 8200/tcp | head -1 | sed 's/.*://'); BAO_ADDR="http://127.0.0.1:$BPORT"
for _ in $(seq 60); do curl -fsS -o /dev/null "$BAO_ADDR/v1/sys/health" 2>/dev/null && break; sleep 1; done
bao() { curl -fsS -H "X-Vault-Token: root" "$@"; }
bao -X POST "$BAO_ADDR/v1/sys/mounts/ssh-client-signer" -d '{"type":"ssh"}' >/dev/null
bao -X POST "$BAO_ADDR/v1/ssh-client-signer/config/ca" -d '{"generate_signing_key":true,"key_type":"ed25519"}' >/dev/null
# те же параметры, что у vault_ssh_secret_backend_role.agent
bao -X POST "$BAO_ADDR/v1/ssh-client-signer/roles/agent" -d '{"key_type":"ca","allow_user_certificates":true,"allow_host_certificates":false,
  "allow_user_key_ids":false,"allowed_users":"*","default_user":"","allowed_extensions":"permit-pty","default_extensions":{"permit-pty":""},
  "allowed_critical_options":"source-address","ttl":"600","max_ttl":"600"}' >/dev/null
CA=$(bao "$BAO_ADDR/v1/ssh-client-signer/config/ca" | jq -r .data.public_key)
PRINCIPAL="deck-u-anna-fugu"

echo "== sshd: настройка командами из приложения"
docker run -d --name "$SSHD" --network "$NET" -p 127.0.0.1::22 ubuntu:24.04 sleep infinity >/dev/null
docker exec "$SSHD" bash -c 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null && apt-get install -y -qq openssh-server sudo >/dev/null && mkdir -p /run/sshd'
docker exec -e CA="$CA" -e PRINCIPAL="$PRINCIPAL" "$SSHD" bash -c '
  set -e
  useradd -m deck-agent
  echo "$CA" > /etc/ssh/deck_ca.pub
  mkdir -p /etc/ssh/principals
  echo "$PRINCIPAL" > /etc/ssh/principals/deck-agent
  printf "TrustedUserCAKeys /etc/ssh/deck_ca.pub\nAuthorizedPrincipalsFile /etc/ssh/principals/%%u\nPasswordAuthentication no\n" > /etc/ssh/sshd_config.d/deck.conf
  /usr/sbin/sshd'
SPORT=$(docker port "$SSHD" 22/tcp | head -1 | sed 's/.*://')
HOSTKEY=$(docker exec "$SSHD" ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}')
# адрес, с которого sshd видит шлюз (шлюз идёт с хоста через опубликованный порт — это шлюз сети docker)
SRC=$(docker network inspect "$NET" -f '{{(index .IPAM.Config 0).Gateway}}')
for _ in $(seq 30); do (exec 3<>"/dev/tcp/127.0.0.1/$SPORT") 2>/dev/null && break; sleep 1; done

echo "== шлюз: сертификат OpenBao → sshd"
GW_BAO_ADDR="$BAO_ADDR" GW_BAO_TOKEN=root GW_SSHD_HOST=127.0.0.1 GW_SSHD_PORT="$SPORT" GW_HOST_KEY="$HOSTKEY" GW_PRINCIPAL="$PRINCIPAL" \
  GW_SOURCE_IP="$SRC" go test -count=1 -run TestRealOpenBaoAndSSHD -v . | grep -E "^(---|===|ok|FAIL|PASS)|real_integration" || true
echo "--- журнал sshd (отказы) ---"
docker exec "$SSHD" bash -c 'journalctl -u ssh --no-pager 2>/dev/null | tail -5' 2>/dev/null || true
