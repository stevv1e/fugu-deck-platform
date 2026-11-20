// Package spaceoperator — space-operator Fugu Deck: по описанию Space создаёт пространство пользователя.
//
// control-plane доступен из интернета и умеет только создать объект Space в deck-system. Всё остальное — namespace,
// квоты, сетевые политики, том и под с агентом — создаёт этот сервис, у которого входа из интернета нет
// (docs/ARCHITECTURE-v2.md, 6.2). Удаляет пространство тоже он — и только по подписи владельца (delete.go).
package spaceoperator

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

// Config — то, что одинаково для всех пространств кластера.
type Config struct {
	SpaceImage   string // образ агента (backend в режиме space)
	RuntimeClass string // gvisor
	KeyguardURL  string // http://keyguard.deck-keys.svc.cluster.local:8080
	SquidURL     string // http://squid.deck-egress.svc.cluster.local:3128
	// SSHGatewayURL — http://ssh-gateway.deck-ssh.svc.cluster.local:8080; пусто — у агента нет доступа к серверам.
	SSHGatewayURL string
	SpaceDNS      string        // адрес space-dns (10.43.0.53)
	StorageClass  string        // local-path
	DeleteDelay   time.Duration // сколько ждать между принятым запросом удаления и удалением (24 ч)
	// InactiveAfter — удалить аккаунт по просьбе control-plane, если пространство непрерывно спит столько (30 дней); 0 — нет.
	InactiveAfter time.Duration
	// BackupToken — токен, по которому оператор забирает у агента снимок базы (свой у каждого пространства).
	// nil — резервные копии выключены, в под ничего не добавляется.
	BackupToken func(space string) string
}

// Space — то, что оператору нужно от объекта Space.
type Space struct {
	Name       string
	stopped    bool // ждёт удаления: агент остановлен, данные на месте
	Generation int64
	Kind       string
	Owner      string
	TitleText  string // аннотация deck.fugu/title: название общего пространства, как его видят люди
	Suspended  bool
	Memory     string // spec.resources.memoryLimit
	Storage    string // spec.resources.storage
	TokenKey   string // аннотация deck.fugu/token-key: публичный ключ control-plane (PEM) для токенов входа
	Deleting   bool   // spec.deleteRequestedAt задан
	DeleteSig  string // spec.deleteSignature: подписанное владельцем действие space_delete (JWS)
	// Из status — то, что оператор сам записал о запросе удаления:
	DeleteVerified string // SHA-256 проверенной подписи; "rejected:<хеш>" — подпись отклонена
	DeleteAt       string // когда удалять (RFC 3339)
	DeleteKind     string // "account" — подпись account_delete, "inactive" — неактивность: удаляется весь аккаунт
	InactiveDelete bool   // spec.inactiveDelete: control-plane просит удалить аккаунт по неактивности
	SleepingSince  string // status.sleepingSince: с какого момента пространство непрерывно спит
	// Резервная копия (status):
	BackupSHA      string // SHA-256 последнего загруженного снимка
	FilesSHA       string // SHA-256 последней загруженной описи файлов
	RestorePending bool   // том создан заново, а копия есть: после запуска агента восстановить
}

const (
	TokenKeyAnnotation = "deck.fugu/token-key"
	TitleAnnotation    = "deck.fugu/title"
	manager            = "space-operator"
	spaceUID           = 10001 // пользователь fugu в образе агента
)

var (
	teamRe     = regexp.MustCompile(`^t-[a-z0-9]{6,20}$`)
	nickRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$`)
	quantRe    = regexp.MustCompile(`^[1-9][0-9]{0,4}(Mi|Gi)$`)
	pemKeyRe   = regexp.MustCompile(`^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]{80,400}-----END PUBLIC KEY-----\n?$`)
	ErrSkipped = errors.New("пространство пропущено")
)

// Namespace — namespace пространства. keyguard по нему определяет, чьим ключом платить: в личном (deck-u-<ник>) —
// ключом владельца, поэтому имя Space обязано совпадать с ником владельца (иначе один пользователь назвал бы
// пространство чужим ником); в общем (deck-t-<id>) — ключом спонсора чата по подписанному им разрешению.
func (s Space) Namespace() string {
	if s.Kind == "team" {
		return "deck-" + s.Name
	}
	return "deck-u-" + s.Owner
}

// Title — название для людей: у общего пространства — заданное при создании, у личного — ник владельца.
func (s Space) Title() string {
	if s.Kind == "team" && s.TitleText != "" {
		return s.TitleText
	}
	return s.Owner
}

// Key — как пространство названо в подписанных действиях и разрешениях (поле space): u-<ник> или t-<id>.
func (s Space) Key() string {
	if s.Kind == "team" {
		return s.Name
	}
	return "u-" + s.Owner
}

// Check — можно ли это пространство обслуживать.
func (s Space) Check() error {
	switch {
	case s.Kind != "personal" && s.Kind != "team":
		return errors.New("неизвестный вид пространства (kind: personal или team)")
	case !nickRe.MatchString(s.Owner) || strings.Contains(s.Owner, "--"):
		return errors.New("недопустимый ник владельца")
	case s.Kind == "personal" && s.Name != s.Owner:
		return errors.New("имя личного пространства должно совпадать с ником владельца")
	case s.Kind == "team" && !teamRe.MatchString(s.Name):
		// Имя общего пространства выдаёт control-plane; namespace deck-<имя> не может совпасть с личным deck-u-…
		return errors.New("имя общего пространства: t- и 6–20 строчных букв и цифр")
	case s.Memory != "" && !quantRe.MatchString(s.Memory):
		return errors.New("resources.memoryLimit: ожидается число с Mi или Gi")
	case s.Storage != "" && !quantRe.MatchString(s.Storage):
		return errors.New("resources.storage: ожидается число с Mi или Gi")
	case !pemKeyRe.MatchString(s.TokenKey):
		return errors.New("нет ключа control-plane для токенов входа (аннотация " + TokenKeyAnnotation + ")")
	}
	return nil
}

type obj = map[string]any

func meta(name, ns string, labels map[string]string) obj {
	m := obj{"name": name}
	if ns != "" {
		m["namespace"] = ns
	}
	l := obj{"app.kubernetes.io/managed-by": manager}
	for k, v := range labels {
		l[k] = v
	}
	m["labels"] = l
	return m
}

func nsSel(names ...string) obj {
	vals := make([]any, len(names))
	for i, n := range names {
		vals[i] = n
	}
	return obj{"namespaceSelector": obj{"matchExpressions": []any{obj{"key": "kubernetes.io/metadata.name", "operator": "In", "values": vals}}}}
}

func port(n int, proto string) obj { return obj{"port": n, "protocol": proto} }

// Render — все объекты пространства в порядке применения. Образец — kubernetes/deck/smoke-space: его проверяют
// правила допуска и смоктест, и пространство пользователя обязано быть не слабее.
func Render(s Space, c Config) []obj {
	ns := s.Namespace()
	mem, storage := s.Memory, s.Storage
	if mem == "" {
		mem = "512Mi"
	}
	if storage == "" {
		storage = "2Gi"
	}
	replicas := 1
	if s.Suspended || s.stopped {
		replicas = 0
	}
	app := map[string]string{"app.kubernetes.io/name": "space"}
	noProxy := "localhost,127.0.0.1,.svc,.svc.cluster.local,.cluster.local"

	objs := []obj{
		{"apiVersion": "v1", "kind": "Namespace", "metadata": meta(ns, "", map[string]string{
			"deck.fugu/space": "true", "deck.fugu/owner": s.Owner,
			"pod-security.kubernetes.io/enforce": "restricted"})},

		{"apiVersion": "v1", "kind": "ResourceQuota", "metadata": meta("space", ns, nil),
			"spec": obj{"hard": obj{
				"requests.cpu": "1", "requests.memory": "1Gi", "limits.memory": "2Gi", "pods": "10",
				"persistentvolumeclaims": "2", "requests.storage": "4Gi",
				"services.loadbalancers": "0", "services.nodeports": "0"}}},

		{"apiVersion": "v1", "kind": "LimitRange", "metadata": meta("space", ns, nil),
			"spec": obj{"limits": []any{obj{"type": "Container",
				"default": obj{"memory": "256Mi", "cpu": "500m"}, "defaultRequest": obj{"memory": "64Mi", "cpu": "50m"},
				"max": obj{"memory": "600Mi"}}}}},

		{"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta("default-deny", ns, nil),
			"spec": obj{"podSelector": obj{}, "policyTypes": []any{"Ingress", "Egress"}}},

		// Входящие — только от Traefik и control-plane; исходящие — space-dns, keyguard, ssh-gateway и Squid.
		// К API Kubernetes, базам, OpenBao и напрямую в интернет пространство не ходит.
		{"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta("space", ns, nil),
			"spec": obj{"podSelector": obj{}, "policyTypes": []any{"Ingress", "Egress"},
				"ingress": []any{obj{"from": []any{nsSel("traefik", "deck-system")}, "ports": []any{port(8080, "TCP")}}},
				"egress": []any{
					obj{"to": []any{obj{
						"namespaceSelector": obj{"matchLabels": obj{"kubernetes.io/metadata.name": "deck-egress"}},
						"podSelector":       obj{"matchLabels": obj{"app.kubernetes.io/name": "space-dns"}}}},
						"ports": []any{port(1053, "UDP"), port(1053, "TCP")}},
					obj{"to": []any{nsSel("deck-keys", "deck-ssh")}, "ports": []any{port(8080, "TCP")}},
					obj{"to": []any{obj{
						"namespaceSelector": obj{"matchLabels": obj{"kubernetes.io/metadata.name": "deck-egress"}},
						"podSelector":       obj{"matchLabels": obj{"app.kubernetes.io/name": "squid"}}}},
						"ports": []any{port(3128, "TCP")}},
				}}},

		{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": meta("space", ns, nil), "automountServiceAccountToken": false},

		// Данные агента (SQLite, вложения). Том переживает сон и перезапуск пода.
		{"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": meta("data", ns, nil),
			"spec": obj{"accessModes": []any{"ReadWriteOnce"}, "storageClassName": c.StorageClass,
				"resources": obj{"requests": obj{"storage": storage}}}},

		{"apiVersion": "v1", "kind": "Service", "metadata": meta("space", ns, app),
			"spec": obj{"selector": app, "ports": []any{obj{"name": "http", "port": 8080, "targetPort": "http"}}}},

		{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": meta("space", ns, app),
			"spec": obj{
				"replicas": replicas, "revisionHistoryLimit": 2,
				// один под на том ReadWriteOnce; состояние запусков агента живёт в памяти процесса
				"strategy": obj{"type": "Recreate"},
				"selector": obj{"matchLabels": app},
				"template": obj{
					"metadata": obj{"labels": app},
					"spec": obj{
						"runtimeClassName": c.RuntimeClass, "serviceAccountName": "space", "automountServiceAccountToken": false,
						"enableServiceLinks": false,
						// DNS только через space-dns: имена кластера, без пересылки наружу
						"dnsPolicy": "None",
						"dnsConfig": obj{"nameservers": []any{c.SpaceDNS},
							"searches": []any{ns + ".svc.cluster.local", "svc.cluster.local", "cluster.local"}},
						"securityContext": obj{"runAsNonRoot": true, "runAsUser": spaceUID, "runAsGroup": spaceUID, "fsGroup": spaceUID,
							"seccompProfile": obj{"type": "RuntimeDefault"}},
						"containers": []any{obj{
							"name": "space", "image": c.SpaceImage,
							// порт 8080 — тот, что открыт сетевой политикой; один воркер (см. Dockerfile агента)
							"command": []any{"uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080",
								"--proxy-headers", "--forwarded-allow-ips", "*", "--timeout-keep-alive", "75"},
							"ports": []any{obj{"name": "http", "containerPort": 8080}},
							"env": []any{
								obj{"name": "DECK_MODE", "value": "space"},
								obj{"name": "SPACE_ID", "value": s.Name},
								obj{"name": "SPACE_KIND", "value": s.Kind},
								obj{"name": "SPACE_NAME", "value": s.Title()},
								// Пространство знает только публичный ключ: выпустить себе токен или роль оно не может.
								obj{"name": "CP_PUBLIC_KEY", "value": s.TokenKey},
								// Ключей API в пространстве нет: модели и Git — только через keyguard, по токену пода.
								obj{"name": "KEYGUARD_URL", "value": c.KeyguardURL},
								obj{"name": "KEYGUARD_TOKEN_PATH", "value": "/var/run/secrets/keyguard/token"},
								obj{"name": "DATA_DIR", "value": "/data"},
								obj{"name": "HOME", "value": "/tmp"},
								obj{"name": "HTTPS_PROXY", "value": c.SquidURL}, obj{"name": "HTTP_PROXY", "value": c.SquidURL},
								obj{"name": "NO_PROXY", "value": noProxy},
							},
							"securityContext": obj{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
								"capabilities": obj{"drop": []any{"ALL"}}},
							"readinessProbe": obj{"httpGet": obj{"path": "/api/health", "port": "http"}, "periodSeconds": 5},
							"livenessProbe":  obj{"httpGet": obj{"path": "/api/health", "port": "http"}, "periodSeconds": 20, "failureThreshold": 6},
							"resources":      obj{"requests": obj{"cpu": "50m", "memory": "128Mi"}, "limits": obj{"memory": mem}},
							"volumeMounts": []any{
								obj{"name": "data", "mountPath": "/data"},
								obj{"name": "tmp", "mountPath": "/tmp"},
								obj{"name": "keyguard-token", "mountPath": "/var/run/secrets/keyguard", "readOnly": true},
							},
						}},
						"volumes": []any{
							obj{"name": "data", "persistentVolumeClaim": obj{"claimName": "data"}},
							obj{"name": "tmp", "emptyDir": obj{"sizeLimit": "256Mi"}},
							obj{"name": "keyguard-token", "projected": obj{"sources": []any{obj{"serviceAccountToken": obj{
								"audience": "keyguard", "expirationSeconds": 600, "path": "token"}}}}},
						},
					},
				},
			}},
	}
	if c.SSHGatewayURL != "" {
		// Серверы пользователя — только через ssh-gateway. Агент предъявляет ему отдельный токен (audience=ssh-gateway):
		// токен для keyguard шлюзу не годится, и наоборот.
		pod := objs[len(objs)-1]["spec"].(obj)["template"].(obj)["spec"].(obj)
		ctr := pod["containers"].([]any)[0].(obj)
		ctr["env"] = append(ctr["env"].([]any), obj{"name": "SSH_GATEWAY_URL", "value": c.SSHGatewayURL},
			obj{"name": "SSH_GATEWAY_TOKEN_PATH", "value": "/var/run/secrets/ssh-gateway/token"})
		ctr["volumeMounts"] = append(ctr["volumeMounts"].([]any), obj{"name": "ssh-gateway-token", "mountPath": "/var/run/secrets/ssh-gateway", "readOnly": true})
		pod["volumes"] = append(pod["volumes"].([]any), obj{"name": "ssh-gateway-token", "projected": obj{"sources": []any{obj{"serviceAccountToken": obj{
			"audience": "ssh-gateway", "expirationSeconds": 600, "path": "token"}}}}})
	}
	if c.BackupToken == nil {
		return objs
	}
	// Резервная копия: агент отдаёт снимок базы только предъявителю этого токена. Токен лежит в Secret и виден
	// контейнеру файлом; ключа хранилища копий в пространстве нет.
	last := len(objs) - 1
	pod := objs[last]["spec"].(obj)["template"].(obj)["spec"].(obj)
	ctr := pod["containers"].([]any)[0].(obj)
	ctr["env"] = append(ctr["env"].([]any), obj{"name": "BACKUP_TOKEN_FILE", "value": "/var/run/secrets/backup/token"})
	ctr["volumeMounts"] = append(ctr["volumeMounts"].([]any), obj{"name": "backup-token", "mountPath": "/var/run/secrets/backup", "readOnly": true})
	pod["volumes"] = append(pod["volumes"].([]any), obj{"name": "backup-token", "secret": obj{"secretName": "space-backup"}})
	secret := obj{"apiVersion": "v1", "kind": "Secret", "metadata": meta("space-backup", ns, nil), "type": "Opaque",
		"stringData": obj{"token": c.BackupToken(s.Name)}}
	return append(objs[:last:last], secret, objs[last])
}
