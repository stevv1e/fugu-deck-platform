package spaceoperator

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"
)

type Operator struct {
	Kube      Kube
	Cfg       Config
	Namespace string // где лежат объекты Space (deck-system)
	Log       *log.Logger
	Now       func() time.Time
	// Verify — проверка подписанного действия через keyguard (delete.go). nil — удаление пространств выключено.
	Verify func(ctx context.Context, jws string) (Verified, error)
	// Purge — стереть в keyguard данные удалённого аккаунта (ключи, устройства, разрешения); reason — account или
	// inactive. nil — не стирать.
	Purge func(ctx context.Context, user, reason string) error
	// Backup — резервные копии пространств (backup.go). nil — выключены.
	Backup *Backups
}

const spacesAPI = "/apis/deck.fugu/v1alpha1/namespaces/%s/spaces"

// objectPath — адрес объекта в API Kubernetes (для server-side apply).
func objectPath(o obj) (string, error) {
	md := o["metadata"].(obj)
	name, _ := md["name"].(string)
	ns, _ := md["namespace"].(string)
	kind, _ := o["kind"].(string)
	plural, ok := map[string]string{
		"Namespace": "namespaces", "ResourceQuota": "resourcequotas", "LimitRange": "limitranges",
		"NetworkPolicy": "networkpolicies", "ServiceAccount": "serviceaccounts", "PersistentVolumeClaim": "persistentvolumeclaims",
		"Service": "services", "Deployment": "deployments", "Secret": "secrets",
	}[kind]
	if !ok {
		return "", fmt.Errorf("неизвестный вид объекта %q", kind)
	}
	prefix := "/api/v1"
	if av, _ := o["apiVersion"].(string); av != "v1" {
		prefix = "/apis/" + av
	}
	if kind == "Namespace" {
		return prefix + "/namespaces/" + name, nil
	}
	return prefix + "/namespaces/" + ns + "/" + plural + "/" + name, nil
}

func str(m map[string]any, path ...string) string {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = mm[p]
	}
	s, _ := cur.(string)
	return s
}

// cleanTitle — название попадает в переменную окружения пода: без управляющих символов и не длиннее 80 знаков.
func cleanTitle(t string) string {
	out := make([]rune, 0, len(t))
	for _, r := range t {
		if r >= 0x20 && r != 0x7f && len(out) < 80 {
			out = append(out, r)
		}
	}
	return strings.TrimSpace(string(out))
}

func parseSpace(o map[string]any) Space {
	s := Space{Name: str(o, "metadata", "name"), Kind: str(o, "spec", "kind"), Owner: str(o, "spec", "owner"),
		Memory: str(o, "spec", "resources", "memoryLimit"), Storage: str(o, "spec", "resources", "storage"),
		TitleText: cleanTitle(str(o, "metadata", "annotations", TitleAnnotation)),
		TokenKey:  str(o, "metadata", "annotations", TokenKeyAnnotation), Deleting: str(o, "spec", "deleteRequestedAt") != "",
		DeleteSig: str(o, "spec", "deleteSignature"), DeleteVerified: str(o, "status", "deleteVerified"), DeleteAt: str(o, "status", "deleteAt"),
		DeleteKind: str(o, "status", "deleteKind"), SleepingSince: str(o, "status", "sleepingSince"),
		BackupSHA: str(o, "status", "backupSha"), FilesSHA: str(o, "status", "filesSha")}
	if st, ok := o["status"].(map[string]any); ok {
		s.RestorePending, _ = st["restorePending"].(bool)
	}
	if spec, ok := o["spec"].(map[string]any); ok {
		s.Suspended, _ = spec["suspended"].(bool)
		s.InactiveDelete, _ = spec["inactiveDelete"].(bool)
	}
	if md, ok := o["metadata"].(map[string]any); ok {
		if g, ok := md["generation"].(float64); ok {
			s.Generation = int64(g)
		}
	}
	return s
}

// ReconcileAll — один проход по всем пространствам. Ошибка одного пространства не мешает остальным.
func (op *Operator) ReconcileAll(ctx context.Context) error {
	items, err := op.Kube.List(ctx, fmt.Sprintf(spacesAPI, op.Namespace))
	if err != nil {
		return err
	}
	for _, it := range items {
		s := parseSpace(it)
		// Запрос удаления: проверка подписи, отсчёт, само удаление. extra — что записать об этом в status.
		s, extra, gone := op.deletion(ctx, s)
		if gone {
			continue
		}
		// Резервная копия: последний снимок перед остановкой агента и отметка «восстановить» для нового тома.
		more, hold := op.beforeReconcile(ctx, &s)
		for k, v := range more {
			if extra == nil {
				extra = map[string]any{}
			}
			extra[k] = v
		}
		phase, msg := "Pending", "хранилище резервных копий не отвечает — повтор"
		if !hold {
			phase, msg = op.reconcile(ctx, s)
		}
		if s.RestorePending && phase == "Ready" {
			more, done := op.restore(ctx, s)
			for k, v := range more {
				if extra == nil {
					extra = map[string]any{}
				}
				extra[k] = v
			}
			if !done {
				phase, msg = "Pending", "восстановление из резервной копии"
			}
		}
		// Сколько пространство спит без перерыва — для удаления по неактивности (отметку ставит только оператор).
		if phase == "Sleeping" && s.SleepingSince == "" {
			extra = setExtra(extra, "sleepingSince", op.Now().UTC().Format(time.RFC3339))
		} else if phase != "Sleeping" && phase != "Deleting" && s.SleepingSince != "" {
			extra = setExtra(extra, "sleepingSince", nil)
		}
		prev := str(it, "status", "phase")
		st := map[string]any{"phase": phase, "observedGeneration": s.Generation,
			"conditions": []any{map[string]any{"type": "Ready", "status": map[bool]string{true: "True", false: "False"}[phase == "Ready"],
				"reason": phase, "message": msg, "lastTransitionTime": op.Now().UTC().Format(time.RFC3339)}}}
		if phase != "Failed" {
			st["namespace"] = s.Namespace()
		}
		for k, v := range extra {
			st[k] = v
		}
		if prev != phase || str(it, "status", "namespace") != str(st, "namespace") || len(extra) > 0 {
			op.Log.Printf("event=space.phase space=%s from=%q to=%s msg=%q", s.Name, prev, phase, msg)
			if err := op.Kube.PatchStatus(ctx, fmt.Sprintf(spacesAPI, op.Namespace)+"/"+s.Name, st); err != nil {
				op.Log.Printf("event=space.status_failed space=%s err=%q", s.Name, err.Error())
			}
		}
	}
	return nil
}

func (op *Operator) reconcile(ctx context.Context, s Space) (phase, msg string) {
	if err := s.Check(); err != nil {
		return "Failed", err.Error()
	}
	for _, o := range Render(s, op.Cfg) {
		path, err := objectPath(o)
		if err != nil {
			return "Failed", err.Error()
		}
		if err := op.Kube.Apply(ctx, path, o); err != nil {
			op.Log.Printf("event=space.apply_failed space=%s kind=%v err=%q", s.Name, o["kind"], err.Error())
			return "Pending", "не удалось применить " + fmt.Sprint(o["kind"])
		}
	}
	if s.stopped {
		return "Deleting", "пространство остановлено и будет удалено " + s.DeleteAt + "; до этого удаление можно отменить"
	}
	if s.Suspended {
		return "Sleeping", "пространство остановлено"
	}
	d, err := op.Kube.Get(ctx, "/apis/apps/v1/namespaces/"+s.Namespace()+"/deployments/space")
	if err != nil {
		return "Pending", "ожидание запуска"
	}
	if deploymentReady(d) {
		return "Ready", "агент запущен"
	}
	return "Pending", "агент запускается"
}

// deploymentReady — запущен ли под именно с ТЕКУЩИМ описанием. Просто «есть доступная реплика» мало: сразу после
// изменения (новый ключ токенов, новый образ) доступной ещё числится старая, и пространство выглядело бы готовым
// за несколько секунд до того, как агент перезапустится.
func deploymentReady(d map[string]any) bool {
	num := func(m map[string]any, k string) float64 { f, _ := m[k].(float64); return f }
	md, _ := d["metadata"].(map[string]any)
	st, _ := d["status"].(map[string]any)
	if md == nil || st == nil {
		return false
	}
	return num(st, "observedGeneration") >= num(md, "generation") &&
		num(st, "updatedReplicas") >= 1 && num(st, "availableReplicas") >= 1 && num(st, "replicas") == num(st, "updatedReplicas")
}

// Run — проходы с заданным шагом, пока не отменён контекст.
func (op *Operator) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := op.ReconcileAll(ctx); err != nil && ctx.Err() == nil {
			op.Log.Printf("event=reconcile.failed err=%q", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func setExtra(m map[string]any, k string, v any) map[string]any {
	if m == nil {
		m = map[string]any{}
	}
	m[k] = v
	return m
}
