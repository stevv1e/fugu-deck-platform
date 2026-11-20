package spaceoperator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"testing"
	"time"
)

// fakeKube — API Kubernetes в памяти: объекты по пути, status объединяется как merge-patch.
type fakeKube struct {
	objs    map[string]map[string]any
	deleted []string
}

func (f *fakeKube) List(_ context.Context, path string) ([]map[string]any, error) {
	out := []map[string]any{}
	for p, o := range f.objs {
		if strings.HasPrefix(p, path+"/") {
			out = append(out, o)
		}
	}
	return out, nil
}
func (f *fakeKube) Get(_ context.Context, path string) (map[string]any, error) {
	if o, ok := f.objs[path]; ok {
		return o, nil
	}
	return nil, ErrNotFound
}
func (f *fakeKube) Apply(_ context.Context, path string, o map[string]any) error {
	if cur, ok := f.objs[path]; ok && cur["status"] != nil { // status ведёт не тот, кто применяет описание
		o["status"] = cur["status"]
	}
	f.objs[path] = o
	return nil
}
func (f *fakeKube) PatchStatus(_ context.Context, path string, st map[string]any) error {
	o, ok := f.objs[path]
	if !ok {
		return ErrNotFound
	}
	cur, _ := o["status"].(map[string]any)
	if cur == nil {
		cur = map[string]any{}
	}
	for k, v := range st {
		if v == nil {
			delete(cur, k)
		} else {
			cur[k] = v
		}
	}
	o["status"] = cur
	return nil
}
func (f *fakeKube) Delete(_ context.Context, path string) error {
	f.deleted = append(f.deleted, path)
	delete(f.objs, path)
	return nil
}

const (
	spAnna = "/apis/deck.fugu/v1alpha1/namespaces/deck-system/spaces/anna"
	nsAnna = "/api/v1/namespaces/deck-u-anna"
)

func TestSpaceDeletion(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	kube := &fakeKube{objs: map[string]map[string]any{spAnna: {
		"metadata": map[string]any{"name": "anna", "annotations": map[string]any{TokenKeyAnnotation: testKey}},
		"spec":     map[string]any{"kind": "personal", "owner": "anna"}}}}
	var asked []string
	answer := func(string) (Verified, error) { return Verified{}, errors.New("не настроено") }
	op := &Operator{Kube: kube, Namespace: "deck-system", Log: log.New(io.Discard, "", 0), Now: func() time.Time { return now },
		Cfg: Config{SpaceImage: "img", DeleteDelay: 24 * time.Hour},
		Verify: func(_ context.Context, jws string) (Verified, error) {
			asked = append(asked, jws)
			return answer(jws)
		}}
	owner := func(user, space, typ string) func(string) (Verified, error) {
		return func(string) (Verified, error) {
			var v Verified
			v.Action.Type, v.Action.Space, v.User, v.DeviceID = typ, space, user, "d-1"
			return v, nil
		}
	}
	pass := func() {
		t.Helper()
		if err := op.ReconcileAll(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	spec := func() map[string]any { return kube.objs[spAnna]["spec"].(map[string]any) }
	status := func(k string) string { return str(kube.objs[spAnna], "status", k) }
	replicas := func() any {
		return kube.objs["/apis/apps/v1/namespaces/deck-u-anna/deployments/space"]["spec"].(map[string]any)["replicas"]
	}
	request := func(jws string) { spec()["deleteRequestedAt"], spec()["deleteSignature"] = "2026-10-11T12:00:00Z", jws }
	cancel := func() { delete(spec(), "deleteRequestedAt"); delete(spec(), "deleteSignature") }

	pass()
	if replicas() != 1 || kube.objs[nsAnna] == nil {
		t.Fatalf("пространство не создано: %v", replicas())
	}

	// 1. Запрос без действительной подписи владельца ничего не меняет — пространство работает.
	for name, ans := range map[string]func(string) (Verified, error){
		"keyguard отклонил":                  func(string) (Verified, error) { return Verified{}, fmt.Errorf("%w: подпись", ErrRejected) },
		"подписал другой пользователь":       owner("bob", "u-anna", "space_delete"),
		"подписано для другого пространства": owner("anna", "u-bob", "space_delete"),
		"действие другого типа":              owner("anna", "u-anna", "device_revoke"),
		"аккаунт другого пользователя":       owner("bob", "", "account_delete"),
	} {
		jws := "a.b." + name
		request(jws)
		answer = ans
		n := len(asked)
		pass()
		pass() // отклонённую подпись второй раз не проверяем: keyguard уже запомнил её номер
		if len(asked) != n+1 {
			t.Errorf("%s: проверок %d, ожидалась одна", name, len(asked)-n)
		}
		if replicas() != 1 || status("deleteAt") != "" || !strings.HasPrefix(status("deleteVerified"), "rejected:") || status("deleteError") == "" || status("phase") == "Deleting" {
			t.Errorf("%s: replicas=%v status=%v", name, replicas(), kube.objs[spAnna]["status"])
		}
	}
	// keyguard недоступен — не отказ: пространство работает, проверка повторится.
	request("a.b.down")
	answer = func(string) (Verified, error) { return Verified{}, errors.New("connection refused") }
	n := len(asked)
	pass()
	pass()
	if len(asked) != n+2 || replicas() != 1 || status("deleteAt") != "" {
		t.Fatalf("недоступный keyguard: проверок %d, replicas=%v", len(asked)-n, replicas())
	}

	// 2. Настоящая подпись владельца: агент остановлен, срок отсчитывает оператор; повторно подпись не проверяется.
	answer = owner("anna", "u-anna", "space_delete")
	pass()
	want := now.Add(24 * time.Hour).Format(time.RFC3339)
	if status("phase") != "Deleting" || status("deleteAt") != want || replicas() != 0 {
		t.Fatalf("принятый запрос: status=%v replicas=%v", kube.objs[spAnna]["status"], replicas())
	}
	n = len(asked)
	now = now.Add(23 * time.Hour)
	pass()
	if len(asked) != n || kube.objs[nsAnna] == nil || len(kube.deleted) != 0 || replicas() != 0 {
		t.Fatalf("до срока: проверок %d, удалено %v", len(asked)-n, kube.deleted)
	}

	// 3. Отмена до срока: пространство снова работает, отметки об удалении сняты.
	cancel()
	pass()
	pass()
	if status("phase") == "Deleting" || status("deleteAt") != "" || status("deleteVerified") != "" || replicas() != 1 {
		t.Fatalf("после отмены: status=%v replicas=%v", kube.objs[spAnna]["status"], replicas())
	}
	now = now.Add(48 * time.Hour)
	pass()
	if len(kube.deleted) != 0 {
		t.Fatalf("отменённое удаление выполнено: %v", kube.deleted)
	}

	// 4. Новый запрос, срок вышел: сначала namespace, и только когда его не стало — сам Space.
	request("a.b.second")
	pass()
	// control-plane не может приблизить срок: его считает оператор, а не поле в spec.
	spec()["deleteRequestedAt"] = "2020-01-01T00:00:00Z"
	now = now.Add(23 * time.Hour)
	pass()
	if len(kube.deleted) != 0 {
		t.Fatalf("удалено раньше срока: %v", kube.deleted)
	}
	// подмена подписи в уже принятом запросе — новая проверка, а не «уже проверено»
	spec()["deleteSignature"] = "a.b.swapped"
	answer = func(string) (Verified, error) { return Verified{}, fmt.Errorf("%w: подпись", ErrRejected) }
	now = now.Add(2 * time.Hour)
	pass()
	if len(kube.deleted) != 0 || replicas() != 1 {
		t.Fatalf("подменённая подпись: удалено %v, replicas=%v", kube.deleted, replicas())
	}
	spec()["deleteSignature"] = "a.b.third"
	answer = owner("anna", "u-anna", "space_delete")
	pass()
	now = now.Add(24 * time.Hour)
	pass()
	if len(kube.deleted) != 1 || kube.deleted[0] != nsAnna || kube.objs[spAnna] == nil {
		t.Fatalf("первым удаляется namespace: %v", kube.deleted)
	}
	pass()
	if len(kube.deleted) != 2 || kube.deleted[1] != spAnna {
		t.Fatalf("затем Space: %v", kube.deleted)
	}
	pass()
	if kube.objs[nsAnna] != nil {
		t.Fatal("удалённое пространство создано заново")
	}
}

// Чужой namespace с подходящим именем оператор не удаляет.
func TestDeletionRefusesForeignNamespace(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	kube := &fakeKube{objs: map[string]map[string]any{
		spAnna: {"metadata": map[string]any{"name": "anna", "annotations": map[string]any{TokenKeyAnnotation: testKey}},
			"spec":   map[string]any{"kind": "personal", "owner": "anna", "deleteRequestedAt": "x", "deleteSignature": "a.b.c"},
			"status": map[string]any{"deleteVerified": sigHash("a.b.c"), "deleteAt": now.Add(-time.Hour).Format(time.RFC3339)}},
		nsAnna: {"metadata": map[string]any{"name": "deck-u-anna", "labels": map[string]any{"deck.fugu/owner": "bob"}}}}}
	op := &Operator{Kube: kube, Namespace: "deck-system", Log: log.New(io.Discard, "", 0), Now: func() time.Time { return now },
		Cfg: Config{SpaceImage: "img", DeleteDelay: time.Hour}}
	if err := op.ReconcileAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(kube.deleted) != 0 {
		t.Fatalf("удалён чужой namespace: %v", kube.deleted)
	}
}

// Удаление аккаунта: подпись account_delete удаляет личное пространство владельца, затем данные в keyguard.
func TestAccountDeletion(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	kube := &fakeKube{objs: map[string]map[string]any{spAnna: {
		"metadata": map[string]any{"name": "anna", "annotations": map[string]any{TokenKeyAnnotation: testKey}},
		"spec":     map[string]any{"kind": "personal", "owner": "anna"}}}}
	var purged []string
	purgeErr := errors.New("keyguard недоступен")
	op := &Operator{Kube: kube, Namespace: "deck-system", Log: log.New(io.Discard, "", 0), Now: func() time.Time { return now },
		Cfg: Config{SpaceImage: "img", DeleteDelay: 24 * time.Hour},
		Verify: func(context.Context, string) (Verified, error) {
			var v Verified
			v.Action.Type, v.User, v.DeviceID = "account_delete", "anna", "d-1"
			return v, nil
		},
		Purge: func(_ context.Context, user, _ string) error {
			purged = append(purged, user)
			return purgeErr
		}}
	pass := func() {
		t.Helper()
		if err := op.ReconcileAll(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	spec := func() map[string]any { return kube.objs[spAnna]["spec"].(map[string]any) }
	pass()
	spec()["deleteRequestedAt"], spec()["deleteSignature"] = "x", "a.b.acct"
	pass()
	if str(kube.objs[spAnna], "status", "deleteKind") != "account" || str(kube.objs[spAnna], "status", "phase") != "Deleting" {
		t.Fatalf("удаление аккаунта не принято: %v", kube.objs[spAnna]["status"])
	}
	now = now.Add(25 * time.Hour)
	pass() // namespace
	pass() // keyguard недоступен — Space остаётся, попытка повторится
	if kube.objs[spAnna] == nil || len(purged) != 1 || purged[0] != "anna" {
		t.Fatalf("при сбое keyguard: purged=%v space=%v", purged, kube.objs[spAnna] != nil)
	}
	purgeErr = nil
	pass()
	if kube.objs[spAnna] != nil || len(purged) != 2 {
		t.Fatalf("после стирания в keyguard Space удаляется: purged=%v", purged)
	}

	// Общее пространство подписью удаления аккаунта не удаляется (у него могут быть другие участники).
	const spTeam = "/apis/deck.fugu/v1alpha1/namespaces/deck-system/spaces/t-abc123"
	kube.objs[spTeam] = map[string]any{
		"metadata": map[string]any{"name": "t-abc123", "annotations": map[string]any{TokenKeyAnnotation: testKey}},
		"spec":     map[string]any{"kind": "team", "owner": "anna", "title": "Команда", "deleteRequestedAt": "x", "deleteSignature": "a.b.team"}}
	pass()
	if !strings.HasPrefix(str(kube.objs[spTeam], "status", "deleteVerified"), "rejected:") {
		t.Fatalf("общее пространство: %v", kube.objs[spTeam]["status"])
	}
}

// Неактивность: control-plane только просит; оператор удаляет, если сам видел пространство спящим 30 дней.
func TestInactiveDeletion(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	kube := &fakeKube{objs: map[string]map[string]any{spAnna: {
		"metadata": map[string]any{"name": "anna", "annotations": map[string]any{TokenKeyAnnotation: testKey}},
		"spec":     map[string]any{"kind": "personal", "owner": "anna"}}}}
	var purged []string
	op := &Operator{Kube: kube, Namespace: "deck-system", Log: log.New(io.Discard, "", 0), Now: func() time.Time { return now },
		Cfg: Config{SpaceImage: "img", DeleteDelay: 24 * time.Hour, InactiveAfter: 30 * 24 * time.Hour},
		Purge: func(_ context.Context, user, reason string) error {
			purged = append(purged, user+":"+reason)
			return nil
		}}
	pass := func() {
		t.Helper()
		if err := op.ReconcileAll(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	spec := func() map[string]any { return kube.objs[spAnna]["spec"].(map[string]any) }
	status := func(k string) string { return str(kube.objs[spAnna], "status", k) }
	pass()
	// Просьба без сна (control-plane взломан или ошибся) — ничего.
	spec()["inactiveDelete"] = true
	pass()
	now = now.Add(60 * 24 * time.Hour)
	pass()
	if status("deleteAt") != "" {
		t.Fatal("удаление по просьбе без сна")
	}
	// Уснуло — отсчёт пошёл с этого момента.
	spec()["suspended"] = true
	pass()
	if status("sleepingSince") != now.Format(time.RFC3339) {
		t.Fatalf("начало сна: %q", status("sleepingSince"))
	}
	now = now.Add(29 * 24 * time.Hour)
	pass()
	if status("deleteAt") != "" {
		t.Fatal("удалено раньше 30 дней сна")
	}
	// Проснулось (человек зашёл) — отсчёт сначала.
	spec()["suspended"] = false
	pass()
	spec()["suspended"] = true
	pass()
	now = now.Add(2 * 24 * time.Hour)
	pass()
	if status("deleteAt") != "" {
		t.Fatal("пробуждение не сбросило отсчёт сна")
	}
	now = now.Add(29 * 24 * time.Hour)
	pass()
	if status("deleteKind") != "inactive" || status("phase") != "Deleting" {
		t.Fatalf("после 30 дней сна: %v", kube.objs[spAnna]["status"])
	}
	// Человек вернулся в отведённые сутки: control-plane снимает просьбу — удаление отменено.
	delete(spec(), "inactiveDelete")
	pass()
	if status("deleteAt") != "" || status("deleteKind") != "" {
		t.Fatalf("отмена: %v", kube.objs[spAnna]["status"])
	}
	spec()["inactiveDelete"] = true
	pass()
	now = now.Add(25 * time.Hour)
	pass() // namespace
	pass() // данные в keyguard, Space
	if kube.objs[spAnna] != nil || len(purged) != 1 || purged[0] != "anna:inactive" {
		t.Fatalf("удаление по неактивности: purged=%v", purged)
	}
}
