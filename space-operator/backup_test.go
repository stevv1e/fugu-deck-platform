package spaceoperator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeStore struct {
	objs    map[string][]byte
	puts    int
	down    bool
	deleted []string
}

func (f *fakeStore) Put(_ context.Context, key string, body io.Reader, size int64, sha string) error {
	if f.down {
		return errors.New("хранилище недоступно")
	}
	b, _ := io.ReadAll(body)
	sum := sha256.Sum256(b)
	if int64(len(b)) != size || hex.EncodeToString(sum[:]) != sha {
		return errors.New("размер или хеш не совпали с содержимым")
	}
	f.objs[key] = b
	f.puts++
	return nil
}
func (f *fakeStore) Get(_ context.Context, key string) (io.ReadCloser, error) {
	if f.down {
		return nil, errors.New("хранилище недоступно")
	}
	b, ok := f.objs[key]
	if !ok {
		return nil, ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}
func (f *fakeStore) Exists(_ context.Context, key string) (bool, error) {
	if f.down {
		return false, errors.New("хранилище недоступно")
	}
	_, ok := f.objs[key]
	return ok, nil
}
func (f *fakeStore) Delete(_ context.Context, key string) error {
	if f.down {
		return errors.New("хранилище недоступно")
	}
	f.deleted = append(f.deleted, key)
	delete(f.objs, key)
	return nil
}

// backupStand — оператор с API Kubernetes в памяти, хранилищем в памяти и «агентом» пространства anna.
type backupStand struct {
	kube     *fakeKube
	store    *fakeStore
	op       *Operator
	now      time.Time
	db       string // содержимое базы агента
	empty    bool
	restored []string
	lie      bool // агент сообщает не тот хеш (снимок оборвался)
	// файлы агента: путь → содержимое (nil — агент старой версии, описи файлов нет)
	files      map[string]string
	gotFiles   []string // какие файлы вернул оператор при восстановлении (по порядку)
	dbRestored bool     // база восстановлена — файлы после этого агент не принимает
}

const (
	depAnna = "/apis/apps/v1/namespaces/deck-u-anna/deployments/space"
	pvcAnna = "/api/v1/namespaces/deck-u-anna/persistentvolumeclaims/data"
	keyAnna = "spaces/anna/fugu-deck.sqlite3"
)

func newBackupStand(t *testing.T) *backupStand {
	t.Helper()
	st := &backupStand{now: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC), db: "база-1", store: &fakeStore{objs: map[string][]byte{}}}
	st.kube = &fakeKube{objs: map[string]map[string]any{spAnna: {
		"metadata": map[string]any{"name": "anna", "annotations": map[string]any{TokenKeyAnnotation: testKey}},
		"spec":     map[string]any{"kind": "personal", "owner": "anna"}}}}
	token := BackupTokenFunc("секрет оператора")
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token("anna") {
			http.Error(w, "не опознан", 401)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /internal/backup":
			sum := sha256.Sum256([]byte(st.db))
			h := hex.EncodeToString(sum[:])
			if st.lie {
				h = strings.Repeat("0", 64)
			}
			w.Header().Set("X-Deck-Snapshot-Sha256", h)
			io.WriteString(w, st.db)
		case "GET /internal/backup/state":
			if st.empty {
				io.WriteString(w, `{"empty":true}`)
			} else {
				io.WriteString(w, `{"empty":false}`)
			}
		case "GET /internal/backup/files":
			if st.files == nil {
				http.NotFound(w, r)
				return
			}
			var out []map[string]any
			for p, c := range st.files {
				h := sha256.Sum256([]byte(c))
				out = append(out, map[string]any{"path": p, "size": len(c), "sha256": hex.EncodeToString(h[:])})
			}
			json.NewEncoder(w).Encode(map[string]any{"files": out})
		case "GET /internal/backup/file":
			c, ok := st.files[r.URL.Query().Get("path")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			io.WriteString(w, c)
		case "PUT /internal/restore/file":
			if !st.empty || st.dbRestored {
				http.Error(w, "есть данные", 409)
				return
			}
			b, _ := io.ReadAll(r.Body)
			h := sha256.Sum256(b)
			if hex.EncodeToString(h[:]) != r.URL.Query().Get("sha256") {
				http.Error(w, "хеш", 400)
				return
			}
			st.gotFiles = append(st.gotFiles, r.URL.Query().Get("path")+"="+string(b))
			io.WriteString(w, `{"ok":true}`)
		case "POST /internal/restore":
			b, _ := io.ReadAll(r.Body)
			if string(b) == "битая копия" {
				http.Error(w, "снимок не принят", 400)
				return
			}
			st.restored = append(st.restored, string(b))
			st.db, st.empty, st.dbRestored = string(b), false, true
			io.WriteString(w, `{"ok":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(agent.Close)
	st.op = &Operator{Kube: st.kube, Namespace: "deck-system", Log: log.New(io.Discard, "", 0), Now: func() time.Time { return st.now },
		Cfg: Config{SpaceImage: "img", DeleteDelay: time.Hour, BackupToken: token},
		Backup: &Backups{Store: st.store, Every: 15 * time.Minute, HTTP: agent.Client(), Token: token, TmpDir: t.TempDir(),
			SpaceURL: func(ns string) string {
				if ns != "deck-u-anna" {
					t.Errorf("запрос к агенту чужого пространства: %s", ns)
				}
				return agent.URL
			}}}
	return st
}

func (st *backupStand) pass(t *testing.T) {
	t.Helper()
	if err := st.op.ReconcileAll(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// ready изображает kubelet: под с текущим описанием запущен (или остановлен, если реплик 0).
func (st *backupStand) ready() {
	d := st.kube.objs[depAnna]
	if d == nil {
		return
	}
	n := 0.0
	if r, _ := d["spec"].(map[string]any)["replicas"].(int); r > 0 {
		n = 1
	}
	d["status"] = map[string]any{"observedGeneration": 0.0, "updatedReplicas": n, "availableReplicas": n, "replicas": n}
}
func (st *backupStand) status(k string) any {
	s, _ := st.kube.objs[spAnna]["status"].(map[string]any)
	return s[k]
}
func (st *backupStand) spec() map[string]any { return st.kube.objs[spAnna]["spec"].(map[string]any) }

func TestBackupSchedule(t *testing.T) {
	st := newBackupStand(t)
	ctx := context.Background()
	st.pass(t)
	// В поде — только токен копирования; ключа хранилища в пространстве нет.
	sec := st.kube.objs["/api/v1/namespaces/deck-u-anna/secrets/space-backup"]
	if sec == nil || sec["stringData"].(map[string]any)["token"] != st.op.Cfg.BackupToken("anna") || st.op.Cfg.BackupToken("anna") == st.op.Cfg.BackupToken("bob") {
		t.Fatalf("секрет с токеном копирования: %v", sec)
	}
	st.op.BackupAll(ctx)
	if st.store.puts != 0 {
		t.Fatal("снимок взят у пространства, которое ещё не запущено")
	}
	st.ready()
	st.pass(t)
	st.op.BackupAll(ctx)
	if string(st.store.objs[keyAnna]) != "база-1" || st.status("backupSha") == nil || st.status("lastBackup") != "2026-10-11T12:00:00Z" {
		t.Fatalf("первый снимок: %q %v", st.store.objs[keyAnna], st.kube.objs[spAnna]["status"])
	}
	st.op.BackupAll(ctx)
	if st.store.puts != 1 {
		t.Fatalf("неизменившаяся база загружена повторно: %d", st.store.puts)
	}
	st.db = "база-2"
	st.lie = true
	st.op.BackupAll(ctx)
	if string(st.store.objs[keyAnna]) != "база-1" {
		t.Fatal("оборванный снимок попал в хранилище")
	}
	st.lie = false
	st.store.down = true
	st.op.BackupAll(ctx)
	st.store.down = false
	st.op.BackupAll(ctx)
	if string(st.store.objs[keyAnna]) != "база-2" || st.store.puts != 2 {
		t.Fatalf("после сбоя хранилища снимок не загружен: %q", st.store.objs[keyAnna])
	}

	// Сон: последний снимок берётся ДО остановки агента; спящее пространство больше не опрашивается.
	st.db = "база-3"
	st.spec()["suspended"] = true
	st.pass(t)
	if string(st.store.objs[keyAnna]) != "база-3" || st.kube.objs[depAnna]["spec"].(map[string]any)["replicas"] != 0 {
		t.Fatalf("снимок перед сном: %q", st.store.objs[keyAnna])
	}
	st.ready()
	st.pass(t)
	st.db = "недоступно"
	st.op.BackupAll(ctx)
	st.pass(t)
	if st.store.puts != 3 {
		t.Fatalf("снимок у спящего пространства: %d", st.store.puts)
	}
}

func TestRestoreIntoNewVolume(t *testing.T) {
	// Диск потерян, кластер поднят заново: Space создан снова, тома нет, а копия в хранилище есть.
	st := newBackupStand(t)
	st.store.objs[keyAnna] = []byte("прежние данные")
	st.empty, st.db = true, "новая пустая база"
	st.store.down = true
	st.pass(t)
	if st.kube.objs[pvcAnna] != nil || st.status("phase") != "Pending" {
		t.Fatalf("хранилище не ответило, а том уже создан (восстановление не состоялось бы): %v", st.kube.objs[spAnna]["status"])
	}
	st.store.down = false
	st.pass(t)
	if st.status("restorePending") != true || st.kube.objs[pvcAnna] == nil {
		t.Fatalf("восстановление не запланировано: %v", st.kube.objs[spAnna]["status"])
	}
	st.op.BackupAll(context.Background())
	st.ready()
	st.op.BackupAll(context.Background()) // пустая база не должна затереть копию до восстановления
	if string(st.store.objs[keyAnna]) != "прежние данные" {
		t.Fatal("пустая база нового пространства затёрла копию")
	}
	st.pass(t)
	if len(st.restored) != 1 || st.restored[0] != "прежние данные" || st.status("restorePending") != nil || st.status("restoredAt") == nil {
		t.Fatalf("восстановление: %v %v", st.restored, st.kube.objs[spAnna]["status"])
	}
	st.pass(t)
	if len(st.restored) != 1 || st.status("phase") != "Ready" {
		t.Fatalf("повторное восстановление или фаза: %v %v", st.restored, st.status("phase"))
	}
}

func TestRestoreNeverOverwritesData(t *testing.T) {
	st := newBackupStand(t)
	st.store.objs[keyAnna] = []byte("прежние данные")
	st.empty = false // человек уже успел что-то создать
	st.pass(t)
	st.ready()
	st.pass(t)
	if len(st.restored) != 0 || st.status("restorePending") != nil || st.status("restoreError") == nil || st.status("phase") != "Ready" {
		t.Fatalf("непустое пространство: %v %v", st.restored, st.kube.objs[spAnna]["status"])
	}

	// Битую копию агент не принимает — пространство не зависает в «восстановлении».
	st2 := newBackupStand(t)
	st2.store.objs[keyAnna] = []byte("битая копия")
	st2.empty = true
	st2.pass(t)
	st2.ready()
	st2.pass(t)
	st2.pass(t)
	if st2.status("restorePending") != nil || st2.status("restoreError") == nil || st2.status("phase") != "Ready" {
		t.Fatalf("битая копия: %v", st2.kube.objs[spAnna]["status"])
	}

	// Существующий том (обычный перезапуск, пробуждение) — никакого восстановления.
	st3 := newBackupStand(t)
	st3.pass(t)
	st3.ready()
	st3.store.objs[keyAnna] = []byte("старая копия")
	st3.empty = true
	st3.pass(t)
	if st3.status("restorePending") != nil || len(st3.restored) != 0 {
		t.Fatal("восстановление в пространство с существующим томом")
	}
}

func TestDeletionRemovesBackup(t *testing.T) {
	st := newBackupStand(t)
	st.op.Verify = func(context.Context, string) (Verified, error) {
		var v Verified
		v.Action.Type, v.Action.Space, v.User = "space_delete", "u-anna", "anna"
		return v, nil
	}
	st.pass(t)
	st.ready()
	st.spec()["deleteRequestedAt"], st.spec()["deleteSignature"] = "x", "a.b.c"
	st.pass(t)
	if string(st.store.objs[keyAnna]) != "база-1" {
		t.Fatalf("перед остановкой на удаление снимок не взят: %q", st.store.objs[keyAnna])
	}
	st.now = st.now.Add(2 * time.Hour)
	st.pass(t) // namespace
	st.store.down = true
	st.pass(t)
	if st.kube.objs[spAnna] == nil {
		t.Fatal("Space удалён, хотя копию убрать не удалось (она осталась бы навсегда)")
	}
	st.store.down = false
	st.pass(t)
	if st.kube.objs[spAnna] != nil || strings.Join(st.store.deleted, ",") != "spaces/anna/files.json,"+keyAnna {
		t.Fatalf("копия не убрана: %v", st.store.deleted)
	}
	// Новое пространство с тем же ником начинается с чистого листа.
	if ok, _ := st.store.Exists(context.Background(), keyAnna); ok {
		t.Fatal("копия удалённого пространства осталась")
	}
}

// Файлы пространства: каждый — один раз под своим хешем; при восстановлении — до базы; при удалении — все.
func TestFilesBackupRestoreDelete(t *testing.T) {
	st := newBackupStand(t)
	st.files = map[string]string{"attachments/c1/a_фото.jpg": "jpeg", "skills/deploy/SKILL.md": "# шаги"}
	st.pass(t)
	st.ready()
	st.pass(t)
	st.op.BackupAll(context.Background())
	sha := func(c string) string { h := sha256.Sum256([]byte(c)); return hex.EncodeToString(h[:]) }
	for _, c := range []string{"jpeg", "# шаги"} {
		if string(st.store.objs["spaces/anna/files/"+sha(c)]) != c {
			t.Fatalf("файл %q не в хранилище: %v", c, st.store.keys())
		}
	}
	if st.status("filesSha") == nil || string(st.store.objs[keyAnna]) != "база-1" {
		t.Fatal("опись или база не записаны")
	}
	puts := st.store.puts
	st.op.BackupAll(context.Background())
	if st.store.puts != puts {
		t.Fatal("без изменений файлы и база загружены повторно")
	}
	// Новый файл и удалённый: загружается только новый; удалённый остаётся в «всех» — уберётся с пространством.
	delete(st.files, "skills/deploy/SKILL.md")
	st.files["attachments/c2/b.pdf"] = "pdf"
	st.op.BackupAll(context.Background())
	if st.store.puts != puts+2 { // новый файл + опись
		t.Fatalf("загрузок %d, ждали %d", st.store.puts-puts, 2)
	}

	// Диск потерян: новый том, пустое пространство. Файлы — до базы, по текущей описи.
	delete(st.kube.objs, pvcAnna)
	st.db, st.empty = "", true
	st.pass(t)
	st.ready()
	st.pass(t)
	if len(st.restored) != 1 || st.restored[0] != "база-1" {
		t.Fatalf("база не восстановлена: %v", st.restored)
	}
	got := strings.Join(st.gotFiles, ",")
	if !strings.Contains(got, "attachments/c1/a_фото.jpg=jpeg") || !strings.Contains(got, "attachments/c2/b.pdf=pdf") || strings.Contains(got, "SKILL") {
		t.Fatalf("файлы при восстановлении: %v", st.gotFiles)
	}

	// Удаление пространства убирает все когда-либо загруженные файлы, включая удалённый навык.
	st.op.Verify = func(context.Context, string) (Verified, error) {
		var v Verified
		v.Action.Type, v.Action.Space, v.User = "space_delete", "u-anna", "anna"
		return v, nil
	}
	st.spec()["deleteRequestedAt"], st.spec()["deleteSignature"] = "x", "a.b.c"
	st.pass(t)
	st.now = st.now.Add(2 * time.Hour)
	st.pass(t)
	st.pass(t)
	for _, k := range st.store.keys() {
		if strings.HasPrefix(k, "spaces/anna/") {
			t.Fatalf("после удаления в хранилище осталось %s", k)
		}
	}
}

func (f *fakeStore) keys() []string {
	var out []string
	for k := range f.objs {
		out = append(out, k)
	}
	return out
}
