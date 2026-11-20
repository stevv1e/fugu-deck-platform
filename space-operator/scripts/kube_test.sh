#!/usr/bin/env bash
# space-operator на НАСТОЯЩЕМ kube-apiserver с правилами допуска платформы: оператор под своей учётной записью
# создаёт пространство, а apiserver принимает его namespace и ПОД (правила deck-space-pods, PSS restricted).
# Поднимает одноразовый k3s без агента в контейнере (порт только на 127.0.0.1). Нужны docker, kubectl, go.
#   scripts/kube_test.sh
set -euo pipefail
cd "$(dirname "$0")/.."
K8S="$(cd ../fugu-deck-infra/kubernetes && pwd)"
K3S_IMAGE="${K3S_IMAGE:-rancher/k3s:v1.36.5-k3s1}"       # = k3s_version в terraform/envs/*/main.tf
NAME="deck-space-operator-test-$$"; WORK=$(mktemp -d)
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT
FAIL=0
ok()  { echo "  ✓ $1"; }
bad() { echo "  ✗ $1"; FAIL=1; }

echo "== одноразовый kube-apiserver ($K3S_IMAGE, без агента)"
docker run -d --name "$NAME" --tmpfs /run --tmpfs /var/run -p 127.0.0.1::6443 "$K3S_IMAGE" server --disable-agent \
  --disable=traefik,servicelb,metrics-server,local-storage,coredns --tls-san 127.0.0.1 >/dev/null
PORT=$(docker port "$NAME" 6443/tcp | head -1 | sed 's/.*://')
for _ in $(seq 90); do docker exec "$NAME" kubectl get --raw /readyz >/dev/null 2>&1 && break; sleep 2; done
docker exec "$NAME" cat /etc/rancher/k3s/k3s.yaml | sed "s|https://127.0.0.1:6443|https://127.0.0.1:$PORT|" > "$WORK/kubeconfig"
chmod 600 "$WORK/kubeconfig"; export KUBECONFIG="$WORK/kubeconfig"

echo "== платформа: namespace, CRD Space, правила допуска, RuntimeClass, права space-operator"
kubectl apply --server-side -k "$K8S/deck/crds" >/dev/null
kubectl apply --server-side -k "$K8S/platform/namespaces" >/dev/null
kubectl apply --server-side -k "$K8S/platform/gvisor" >/dev/null
kubectl wait --for=condition=Established crd/spaces.deck.fugu --timeout=60s >/dev/null
kubectl apply --server-side -k "$K8S/platform/admission" >/dev/null
kubectl apply --server-side -f "$K8S/deck/services/space-operator.yaml" -f "$K8S/deck/services/operator-scope.policy.yaml" >/dev/null
sleep 8   # привязки политик начинают действовать не мгновенно

PUB=$(openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null | openssl ec -pubout 2>/dev/null)
space() { # имя, владелец, вид, остановлено, ключ
  local key=""; [[ -n $5 ]] && key=$(printf '    deck.fugu/token-key: |\n%s\n' "$(sed 's/^/      /' <<<"$5")")
  kubectl apply -f - >/dev/null <<YAML
apiVersion: deck.fugu/v1alpha1
kind: Space
metadata:
  name: $1
  namespace: deck-system
  annotations:
    deck.fugu/test: "1"
$key
spec: {kind: $3, owner: $2, suspended: $4}
YAML
}
space anna anna personal false "$PUB"
space zoe zoe personal true "$PUB"
space mallory bob personal false "$PUB"    # имя ≠ владелец: попытка занять namespace чужого ника
space team1 team1 team false "$PUB"       # общее пространство с именем не по правилу t-<id>
space t-shop0001 anna team false "$PUB"   # общее пространство Анны
space nokey nokey personal false ""

echo "== оператор под учётной записью space-operator"
kubectl -n deck-system create token space-operator --duration=30m > "$WORK/token"
SO_KUBE_URL="https://127.0.0.1:$PORT" SO_KUBE_TOKEN_FILE="$WORK/token" go test -count=1 -run TestOperatorOnRealAPIServer . \
  && ok "оператор создал пространства и выставил статусы" || bad "тест оператора"

echo "== apiserver принял под пространства"
for _ in $(seq 30); do kubectl -n deck-u-anna get pods --no-headers 2>/dev/null | grep -q . && break; sleep 2; done
POD=$(kubectl -n deck-u-anna get pods -o name 2>/dev/null | head -1)
if [[ -n $POD ]]; then ok "под создан: $POD (правила deck-space-pods и PSS restricted пройдены)"
else bad "под не создан: $(kubectl -n deck-u-anna get rs -o jsonpath='{.items[0].status.conditions[*].message}' | cut -c1-400)"; fi
RC=$(kubectl -n deck-u-anna get "$POD" -o jsonpath='{.spec.runtimeClassName}/{.spec.dnsPolicy}/{.spec.automountServiceAccountToken}' 2>/dev/null || true)
[[ $RC == "gvisor/None/false" ]] && ok "под: gVisor, DNS только space-dns, без токена API Kubernetes" || bad "под: $RC"

kubectl -n deck-u-anna get secret space-backup -o jsonpath='{.data.token}' 2>/dev/null | grep -q . \
  && ok "секрет с токеном копирования создан в пространстве" || bad "секрета space-backup нет"
SV=$(kubectl -n deck-u-anna get "$POD" -o jsonpath='{.spec.volumes[*].secret.secretName}' 2>/dev/null || true)
[[ $SV == "space-backup" ]] && ok "под с томом секрета space-backup принят правилами допуска" || bad "тома секрета в поде: '$SV'"

echo "== удаление пространства по принятой подписи (и только пространства)"
SO_KUBE_URL="https://127.0.0.1:$PORT" SO_KUBE_TOKEN_FILE="$WORK/token" go test -count=1 -run TestDeletionOnRealAPIServer . \
  && ok "оператор удалил namespace пространства и затем Space; чужой namespace удалить не смог" || bad "тест удаления"
kubectl get ns deck-keys >/dev/null 2>&1 && ok "namespace deck-keys на месте" || bad "namespace deck-keys пропал"

echo "== оператору нельзя писать вне пространств"
T=$(cat "$WORK/token")
for ns in deck-keys deck-secrets kube-system; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
    "https://127.0.0.1:$PORT/api/v1/namespaces/$ns/configmaps" -d '{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"so-probe"}}')
  [[ $code == 403 ]] && ok "ConfigMap в $ns — отказ" || bad "ConfigMap в $ns — HTTP $code"
done
[[ $FAIL == 0 ]] && echo "space-operator: всё в порядке" || { echo "space-operator: есть ошибки"; exit 1; }
