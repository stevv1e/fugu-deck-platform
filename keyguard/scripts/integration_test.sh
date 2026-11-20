#!/usr/bin/env bash
# Интеграционные тесты keyguard на настоящих OpenBao и kube-apiserver (в `go test` без окружения они пропускаются):
#   TestIntegration_OpenBao        — вход, чтение/запись ключей под политикой keyguard.hcl из fugu-deck-infra
#   TestIntegration_DeviceCertPKI  — выпуск сертификата устройства через pki-device
#   TestIntegration_TokenReview    — опознание пространства по проецируемому токену ServiceAccount
# OpenBao — бинарник из официального образа (запускается тестом на 127.0.0.1); kube-apiserver — одноразовый k3s без
# агента в контейнере. Рабочие кластеры не затрагиваются. Нужны docker, kubectl, go.
#   scripts/integration_test.sh
set -euo pipefail
cd "$(dirname "$0")/.."
BAO_IMAGE="${BAO_IMAGE:-ghcr.io/openbao/openbao:2.7.0}"      # = версия OpenBao в fugu-deck-infra
K3S_IMAGE="${K3S_IMAGE:-rancher/k3s:v1.36.5-k3s1}"           # = k3s на ноде
NAME="keyguard-itest-$$"; WORK=$(mktemp -d)
trap 'docker rm -f "$NAME" "$NAME-bao" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

echo "== OpenBao: бинарник из $BAO_IMAGE"
docker create --name "$NAME-bao" "$BAO_IMAGE" >/dev/null
docker cp "$NAME-bao:/usr/bin/bao" "$WORK/bao" && chmod +x "$WORK/bao"
"$WORK/bao" version

echo "== одноразовый kube-apiserver ($K3S_IMAGE, без агента)"
docker run -d --name "$NAME" --tmpfs /run --tmpfs /var/run -p 127.0.0.1::6443 "$K3S_IMAGE" server --disable-agent \
  --disable=traefik,servicelb,metrics-server,local-storage,coredns --tls-san 127.0.0.1 >/dev/null
PORT=$(docker port "$NAME" 6443/tcp | head -1 | sed 's/.*://')
for _ in $(seq 90); do docker exec "$NAME" kubectl get --raw /readyz >/dev/null 2>&1 && break; sleep 2; done
docker exec "$NAME" cat /etc/rancher/k3s/k3s.yaml | sed "s|https://127.0.0.1:6443|https://127.0.0.1:$PORT|" > "$WORK/kubeconfig"
chmod 600 "$WORK/kubeconfig"; export KUBECONFIG="$WORK/kubeconfig"
# Пространства и «контроллер Argo CD», от имени которого тест создаёт ServiceAccount (в кластере это его право по GitOps).
kubectl create namespace deck-u-anna >/dev/null; kubectl create namespace deck-t-shop >/dev/null; kubectl create namespace argocd >/dev/null
kubectl create clusterrolebinding itest-argocd --clusterrole=cluster-admin \
  --serviceaccount=argocd:argocd-application-controller >/dev/null
for ns in default deck-u-anna deck-t-shop; do
  for _ in $(seq 30); do kubectl -n "$ns" get sa default >/dev/null 2>&1 && break; sleep 1; done
done

BAO_BIN="$WORK/bao" KUBECTL=kubectl KEYGUARD_POLICY="$(cd ../fugu-deck-infra/terraform/openbao/policies && pwd)/keyguard.hcl" \
  go test -count=1 -run 'TestIntegration_(OpenBao|DeviceCertPKI|TokenReview)' -v . | grep -vE '^\s+\S+\.go:[0-9]+: PASS'
