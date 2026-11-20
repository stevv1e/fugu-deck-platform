#!/usr/bin/env bash
# Сквозной тест v2: КОД АГЕНТА пространства (backend fugu-deck, режим keyguard) → СОБРАННЫЙ keyguard → TokenReview (k3s)
# → вход в OpenBao методом kubernetes → ключ владельца → мок-провайдеры бэкенда (Anthropic, Sakana, GitHub).
# Между keyguard и моками — записывающий прокси: проверяем, что РЕАЛЬНО ушло провайдеру.
# Нужны: k3s (KUBECONFIG), OpenBao dev root-smoke :8200, BACKEND=путь к fugu-deck/backend, PY=python с его зависимостями.
set -u
INFRA=${INFRA:-/home/claude/infra}; BACKEND=${BACKEND:-/tmp/app/fugu-deck/backend}; PY=${PY:-/tmp/venv/bin/python}
K="${KUBECTL:-/tmp/bin/k3s kubectl}"; BAO=${BAO_BIN:-/tmp/bin/bao}; KGBIN=${KEYGUARD_BIN:-/tmp/keyguard-bin}
export BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=root-smoke VAULT_TOKEN=root-smoke
for i in $(seq 1 40); do $K get ns deck-u-anna >/dev/null 2>&1 && break; sleep 2; done
ARGO="--as=system:serviceaccount:argocd:argocd-application-controller --as-group=system:serviceaccounts"
SA=/var/run/secrets/kubernetes.io/serviceaccount; mkdir -p $SA /var/run/secrets/openbao
PIDS=(); cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; }; trap cleanup EXIT

# --- кластер и OpenBao (как scripts/live_smoke.sh) ---
for x in "deck-keys keyguard" "default kg-reviewer" "deck-u-anna space"; do set -- $x; $K -n $1 create sa $2 $ARGO >/dev/null 2>&1; done
$K create clusterrolebinding kg-reviewer --clusterrole=system:auth-delegator --serviceaccount=default:kg-reviewer $ARGO >/dev/null 2>&1
$K -n deck-keys create token keyguard --audience=openbao --duration=1h --as=bg --as-group=deck:breakglass --as-group=system:masters > /var/run/secrets/openbao/token
$K -n default create token kg-reviewer --duration=1h > $SA/token
$K config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > $SA/ca.crt
$K -n deck-u-anna create token space --audience=keyguard --duration=1h > /tmp/space.tok
$BAO secrets enable -path=deck -version=2 kv >/dev/null 2>&1; $BAO write -f deck/config cas_required=true >/dev/null
$BAO policy write keyguard $INFRA/terraform/openbao/policies/keyguard.hcl >/dev/null
$BAO auth enable kubernetes >/dev/null 2>&1
$BAO write auth/kubernetes/config kubernetes_host=https://127.0.0.1:6443 kubernetes_ca_cert=@$SA/ca.crt token_reviewer_jwt=@$SA/token disable_local_ca_jwt=true >/dev/null
$BAO write auth/kubernetes/role/keyguard bound_service_account_names=keyguard bound_service_account_namespaces=deck-keys audience=openbao token_policies=keyguard token_ttl=600 >/dev/null
$BAO kv get deck/keyguard/hpke >/dev/null 2>&1 || bash $INFRA/scripts/keyguard-hpke-init.sh >/dev/null
for kv in "anthropic sk-ant-test" "sakana sk-sak-OWNER-0123456789" "github ghp_OWNER_0123456789"; do set -- $kv
  $BAO kv metadata delete deck/keys/anna/$1 >/dev/null 2>&1; $BAO kv put -cas=0 deck/keys/anna/$1 key=$2 >/dev/null; done

# --- мок-провайдеры бэкенда + записывающий прокси ---
(cd $BACKEND && exec $PY -m uvicorn tests.mock_server:app --port 9100 --log-level warning) >/tmp/mock.log 2>&1 & PIDS+=($!)
rm -f /tmp/rec.jsonl
$PY - >/tmp/rec.log 2>&1 <<'PY' & PIDS+=($!)
import http.server, json, urllib.request
class H(http.server.BaseHTTPRequestHandler):
    def _go(self):
        n=int(self.headers.get("Content-Length") or 0); body=self.rfile.read(n) if n else None
        with open("/tmp/rec.jsonl","a") as f: f.write(json.dumps({"m":self.command,"p":self.path,"h":dict(self.headers.items()),"b":(body or b"").decode(errors="replace")})+"\n")
        req=urllib.request.Request("http://127.0.0.1:9100"+self.path, data=body, method=self.command,
            headers={k:v for k,v in self.headers.items() if k.lower() not in ("host","content-length")})
        try: r=urllib.request.urlopen(req, timeout=30); code=r.status; data=r.read(); ct=r.headers.get("Content-Type","")
        except urllib.error.HTTPError as e: code=e.code; data=e.read(); ct=e.headers.get("Content-Type","")
        self.send_response(code); self.send_header("Content-Type",ct); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
    do_GET=do_POST=do_PUT=do_PATCH=_go
    def log_message(self,*a): pass
http.server.ThreadingHTTPServer(("127.0.0.1",9200),H).serve_forever()
PY

# --- keyguard ---
KUBERNETES_SERVICE_HOST=127.0.0.1 KUBERNETES_SERVICE_PORT=6443 DECK_OPENBAO_ADDR=$BAO_ADDR DECK_OPENBAO_JWT=/var/run/secrets/openbao/token \
  DECK_UPSTREAM_ANTHROPIC=http://127.0.0.1:9200/anthropic DECK_UPSTREAM_SAKANA=http://127.0.0.1:9200 DECK_UPSTREAM_GITHUB=http://127.0.0.1:9200/gh \
  DECK_PRICES_ANTHROPIC="claude-test=3:15" DECK_STATE=memory $KGBIN >/tmp/kg.log 2>&1 & PIDS+=($!)
for i in $(seq 1 30); do curl -sf -m1 http://127.0.0.1:8080/readyz >/dev/null && break; sleep 1; done

# --- код агента пространства ---
cd $BACKEND && KEYGUARD_URL=http://127.0.0.1:8080 KEYGUARD_TOKEN_PATH=/tmp/space.tok $PY - <<'PY'
import asyncio, json, shutil, sys
from app.config import get_settings
from app import keyguard_client as kgc
from app.llm import get_provider
from app.agent import Agent
R=[]
def ok(n,c,d=""): R.append(bool(c)); print(("PASS " if c else "FAIL ")+n+(f"  [{d}]" if d and not c else ""))
async def nothing(*a,**k): pass
def rec():
    try: return [json.loads(l) for l in open("/tmp/rec.jsonl")]
    except FileNotFoundError: return []
async def main():
    s=get_settings(); tok=open("/tmp/space.tok").read().strip()
    ok("режим keyguard включён в бэкенде", kgc.enabled())
    a=get_provider("anthropic", s)
    r=await a.stream(kgc.token(),"claude-test",[{"role":"user","content":"hi"}],[],nothing,nothing)
    last=[x for x in rec() if "/messages" in x["p"]][-1]
    ok("Anthropic: агент → keyguard → провайдер получил ключ владельца из OpenBao (мок принимает только sk-ant-test)", last["h"].get("X-Api-Key")=="sk-ant-test", last["h"].get("X-Api-Key"))
    ok("Anthropic: ответ модели дошёл до агента", bool(r.text) or bool(r.tool_calls), r)
    sk=get_provider("sakana", s)
    r=await sk.stream(kgc.token(),"fugu-max-v1.0",[{"role":"user","content":"hi"}],[],nothing,nothing,headers=kgc.headers("chat-1","anna"))
    last=[x for x in rec() if "/chat/completions" in x["p"]][-1]
    body=json.loads(last["b"])
    ok("Sakana: провайдер получил ключ владельца", last["h"].get("Authorization")=="Bearer sk-sak-OWNER-0123456789", last["h"].get("Authorization"))
    ok("Sakana: max_tokens передан (без него keyguard отказывает)", body.get("max_tokens")==s.sakana_max_tokens, body.get("max_tokens"))
    ok("Sakana: X-Deck-* не ушли провайдеру", not any(k.lower().startswith("x-deck") for k in last["h"]), list(last["h"]))
    ag=Agent(None, s, {}); git=ag._git_for({}, "chat-1", "anna")
    me=await git["github"]._whoami()
    last=[x for x in rec() if x["p"].startswith("/gh/")][-1]
    ok("GitHub: агент → keyguard → провайдер получил токен владельца", last["h"].get("Authorization")=="Bearer ghp_OWNER_0123456789", last["h"].get("Authorization"))
    ok("GitHub: ответ дошёл (whoami)", bool(me.get("login")), me)
    ok("ни в один запрос к провайдерам не ушёл токен пространства", all(tok not in json.dumps(x) for x in rec()))
    # ротация токена: kubelet переписал файл — следующий запрос берёт новый (не кэширует старый)
    shutil.copy("/tmp/space.tok","/tmp/space.tok.bak"); open("/tmp/space.tok","w").write("revoked-token")
    try: await git["github"]._req("GET","/user/repos"); rot=False
    except Exception as e: rot="401" in str(e) or "не опознан" in str(e)
    ok("токен читается на каждый запрос (подменённый файл сразу виден)", rot)
    shutil.copy("/tmp/space.tok.bak","/tmp/space.tok")
    r2=await git["github"]._req("GET","/user/repos")
    ok("после обновления файла Git снова работает", r2.status_code==200)
    try: await git["github"]._req("DELETE","/repos/me/demo"); dele=False
    except Exception as e: dele="403" in str(e)
    ok("удаление репозитория из пространства запрещено keyguard", dele)
asyncio.run(main())
print(f"\n==== сквозной v2: {sum(R)}/{len(R)} ===="); sys.exit(0 if all(R) else 1)
PY
