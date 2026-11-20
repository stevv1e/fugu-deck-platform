#!/usr/bin/env bash
# Смоук СОБРАННОГО бинарника keyguard с живыми зависимостями: kube-apiserver (k3s) для TokenReview и входа в OpenBao
# методом kubernetes, OpenBao dev с политиками и скриптом ключа HPKE из инфраструктурного репозитория.
# Нужны: запущенные k3s (KUBECONFIG) и OpenBao dev (root-smoke на :8200), INFRA=путь к fugu-deck-infra, root.
set -u
INFRA=${INFRA:-/home/claude/infra}; K="${KUBECTL:-/tmp/bin/k3s kubectl}"; BAO=${BAO_BIN:-/tmp/bin/bao}
export BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=root-smoke VAULT_TOKEN=root-smoke
PASS=0; FAIL=0
ok() { if eval "$2"; then PASS=$((PASS+1)); echo "PASS $1"; else FAIL=$((FAIL+1)); echo "FAIL $1"; fi; }
ARGO="--as=system:serviceaccount:argocd:argocd-application-controller --as-group=system:serviceaccounts"
SA=/var/run/secrets/kubernetes.io/serviceaccount; mkdir -p $SA /var/run/secrets/openbao

# --- токены (keyguard — только через breakglass: человеку выпуск запрещён правилом допуска) ---
$K -n deck-keys create sa keyguard $ARGO >/dev/null 2>&1
$K -n default create sa kg-reviewer $ARGO >/dev/null 2>&1
$K create clusterrolebinding kg-reviewer --clusterrole=system:auth-delegator --serviceaccount=default:kg-reviewer $ARGO >/dev/null 2>&1
$K -n deck-u-anna create sa space $ARGO >/dev/null 2>&1
ok "человеку без breakglass выпуск токена keyguard запрещён" \
  "! $K -n deck-keys create token keyguard --audience=openbao >/dev/null 2>&1"
$K -n deck-keys create token keyguard --audience=openbao --duration=1h --as=breakglass-test --as-group=deck:breakglass --as-group=system:masters > /var/run/secrets/openbao/token
$K -n default create token kg-reviewer --duration=1h > $SA/token
$K config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > $SA/ca.crt
SPACE=$($K -n deck-u-anna create token space --audience=keyguard --duration=1h)
WRONG=$($K -n deck-u-anna create token space --audience=ssh-gateway --duration=1h)

# --- OpenBao как terraform/openbao: KV deck (cas), политики, вход kubernetes к живому API ---
$BAO secrets enable -path=deck -version=2 kv >/dev/null 2>&1; $BAO write -f deck/config cas_required=true >/dev/null
$BAO policy write keyguard $INFRA/terraform/openbao/policies/keyguard.hcl >/dev/null
$BAO policy write admin $INFRA/terraform/openbao/policies/admin.hcl >/dev/null
$BAO auth enable kubernetes >/dev/null 2>&1
$BAO write auth/kubernetes/config kubernetes_host=https://127.0.0.1:6443 kubernetes_ca_cert=@$SA/ca.crt token_reviewer_jwt=@$SA/token disable_local_ca_jwt=true >/dev/null
$BAO write auth/kubernetes/role/keyguard bound_service_account_names=keyguard bound_service_account_namespaces=deck-keys \
  audience=openbao token_policies=keyguard token_ttl=600 token_type=batch >/dev/null

# --- ключ HPKE скриптом бутстрапа ---
PUB=$(bash $INFRA/scripts/keyguard-hpke-init.sh 2>/dev/null | tail -1)
ok "keyguard-hpke-init.sh записал ключ и выдал публичную часть" "[[ \$(echo '$PUB' | base64 -d | wc -c) -eq 65 ]]"
ok "повторный запуск НЕ перезаписывает ключ" "! bash $INFRA/scripts/keyguard-hpke-init.sh >/dev/null 2>&1"
ADMIN=$($BAO token create -policy=admin -field=token)
ok "администратор OpenBao не читает ключ HPKE" "! BAO_TOKEN=$ADMIN $BAO kv get deck/keyguard/hpke >/dev/null 2>&1"
ok "администратор OpenBao не может его подменить" "! BAO_TOKEN=$ADMIN $BAO kv put deck/keyguard/hpke private_hex=00 >/dev/null 2>&1"
KG=$($BAO write -field=token auth/kubernetes/login role=keyguard jwt=@/var/run/secrets/openbao/token)
ok "keyguard читает ключ HPKE" "BAO_TOKEN=$KG $BAO kv get deck/keyguard/hpke >/dev/null 2>&1"
ok "keyguard НЕ может перезаписать ключ HPKE" "! BAO_TOKEN=$KG $BAO kv put -cas=1 deck/keyguard/hpke private_hex=00 >/dev/null 2>&1"
PRIV=$($BAO kv get -field=private_hex deck/keyguard/hpke)
DERIVED=$(cd "$(dirname "$0")/.." && go run ./scripts/pubkey "$PRIV")
ok "публичный ключ для приложения соответствует закрытому" "[[ '$DERIVED' == '$PUB' ]]"

# --- бинарник ---
KUBERNETES_SERVICE_HOST=127.0.0.1 KUBERNETES_SERVICE_PORT=6443 DECK_OPENBAO_ADDR=$BAO_ADDR DECK_OPENBAO_ROLE=keyguard \
  DECK_OPENBAO_JWT=/var/run/secrets/openbao/token DECK_TOKEN_AUDIENCE=keyguard DECK_STATE=memory setsid ${KEYGUARD_BIN:-/tmp/keyguard-bin} </dev/null >/tmp/kg.log 2>&1 &
KGPID=$!; trap 'kill $KGPID 2>/dev/null' EXIT
for i in $(seq 1 30); do curl -sf -m 1 http://127.0.0.1:8080/readyz >/dev/null && break; sleep 1; done
U=http://127.0.0.1:8080; B='{"model":"fugu-max-v1.0","max_tokens":10,"messages":[]}'
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }
ok "/readyz = 200 (вошёл в OpenBao, загрузил ключ HPKE)" "[[ \$(code $U/readyz) == 200 ]]"
ok "без токена — 401" "[[ \$(code -X POST $U/llm/sakana/v1/chat/completions -d '$B') == 401 ]]"
ok "токен с чужим audience — 401" "[[ \$(code -X POST -H 'Authorization: Bearer $WRONG' $U/llm/sakana/v1/chat/completions -d '$B') == 401 ]]"
ok "токен пространства, ключа нет — 409" "[[ \$(code -X POST -H 'Authorization: Bearer $SPACE' $U/llm/sakana/v1/chat/completions -d '$B') == 409 ]]"
$BAO kv put -cas=0 deck/keys/anna/sakana key=sk-sak-SMOKE-0123456789 >/dev/null
C=$(code -X POST -H "Authorization: Bearer $SPACE" $U/llm/sakana/v1/chat/completions -d "$B")
ok "ключ в OpenBao → запрос ушёл к провайдеру (здесь его режет сеть песочницы: $C)" "[[ $C != 409 && $C != 401 ]]"
ok "пространство не может вводить ключи — 403" "[[ \$(code -X POST -H 'Authorization: Bearer $SPACE' $U/v1/keys -d '{}') == 403 ]]"
ok "провайдер отклонил запрос → списано 0 (charged_usd=0)" "grep -q 'charged_usd=0.000000' /tmp/kg.log"
ok "в журнале нет ключа" "! grep -q SMOKE /tmp/kg.log"
ok "в журнале нет токена пространства" "! grep -qF '${SPACE:30:40}' /tmp/kg.log"
echo; echo "==== бинарник keyguard вживую: $PASS прошли, $FAIL провалились ===="; [[ $FAIL -eq 0 ]]
