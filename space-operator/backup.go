package spaceoperator

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Резервные копии пространств. Данные пространства — одна база SQLite на томе ноды; пропал диск — пропало всё.
// Ключа хранилища в пространстве нет (взломанный агент читал бы чужие копии): оператор сам забирает у агента
// согласованный снимок базы и сам кладёт его под ключом spaces/<имя>/. Бакет хранит версии с блокировкой
// удаления, поэтому история копий переживает и взлом пространства, и ошибку оператора.
//
// Восстановление — только в пустое пространство с новым томом (диск ноды потерян, кластер поднят заново):
// данные, которые человек успел создать, копией не затираются.

// Store — хранилище копий (S3).
type Store interface {
	Put(ctx context.Context, key string, body io.Reader, size int64, sha string) error
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Exists(ctx context.Context, key string) (bool, error)
	Delete(ctx context.Context, key string) error
}

type Backups struct {
	Store Store
	Every time.Duration // шаг между снимками работающего пространства
	HTTP  *http.Client
	// Token — токен пространства для запросов к агенту (тот же, что Config.BackupToken).
	Token func(space string) string
	// SpaceURL — адрес агента в namespace пространства (в тестах подменяется).
	SpaceURL func(namespace string) string
	TmpDir   string
}

const maxSnapshot = 1 << 30

func backupKey(space string) string { return "spaces/" + space + "/fugu-deck.sqlite3" }

// BackupTokenFunc — токен пространства: HMAC от секрета оператора. Хранить его негде и незачем — он вычисляется
// заново после перезапуска; токен одного пространства ничего не говорит о токене другого.
func BackupTokenFunc(secret string) func(space string) string {
	return func(space string) string {
		h := hmac.New(sha256.New, []byte(secret))
		h.Write([]byte("space-backup:" + space))
		return hex.EncodeToString(h.Sum(nil))
	}
}

func (b *Backups) url(ns, path string) string {
	if b.SpaceURL != nil {
		return b.SpaceURL(ns) + path
	}
	return "http://space." + ns + ".svc.cluster.local:8080" + path
}

func (b *Backups) agent(ctx context.Context, s Space, method, path string, body io.Reader, size int64) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, b.url(s.Namespace(), path), body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = size
		req.Header.Set("Content-Type", "application/vnd.sqlite3")
	}
	req.Header.Set("Authorization", "Bearer "+b.Token(s.Name))
	return b.HTTP.Do(req)
}

// errAgent — агент ответил отказом (в отличие от «недоступен»): повторять тот же запрос бессмысленно.
type errAgent struct {
	code int
	msg  string
}

func (e errAgent) Error() string { return fmt.Sprintf("агент: HTTP %d: %s", e.code, e.msg) }

func agentErr(r *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(r.Body, 400))
	return errAgent{r.StatusCode, string(b)}
}

// snapshot забирает снимок базы во временный файл; возвращает файл (в начале), размер и SHA-256.
func (b *Backups) snapshot(ctx context.Context, s Space) (*os.File, int64, string, error) {
	r, err := b.agent(ctx, s, http.MethodGet, "/internal/backup", nil, 0)
	if err != nil {
		return nil, 0, "", err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return nil, 0, "", agentErr(r)
	}
	f, err := os.CreateTemp(b.TmpDir, "snapshot-*")
	if err != nil {
		return nil, 0, "", err
	}
	os.Remove(f.Name()) // файл живёт, пока открыт
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(r.Body, maxSnapshot+1))
	if err == nil && n > maxSnapshot {
		err = errors.New("снимок больше 1 ГиБ")
	}
	sum := hex.EncodeToString(h.Sum(nil))
	// Агент сообщает хеш того, что отправил: обрезанный по дороге снимок в хранилище не попадёт.
	if want := r.Header.Get("X-Deck-Snapshot-Sha256"); err == nil && want != sum {
		err = errors.New("снимок пришёл не целиком (хеш не совпал)")
	}
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		f.Close()
		return nil, 0, "", err
	}
	return f, n, sum, nil
}

// backupOne делает снимок и загружает его, если он отличается от последнего загруженного.
// Возвращает поля для status (nil — загружать было нечего).
func (op *Operator) backupOne(ctx context.Context, s Space) (map[string]any, error) {
	b := op.Backup
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	// Сначала файлы: снимок базы ссылается на них, и в хранилище не должно оказаться базы без её файлов.
	st, err := op.backupFiles(ctx, s)
	if err != nil && !errors.Is(err, errNoFiles) {
		return nil, fmt.Errorf("файлы: %w", err)
	}
	f, size, sum, err := b.snapshot(ctx, s)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if sum == s.BackupSHA {
		return st, nil
	}
	if err := b.Store.Put(ctx, backupKey(s.Name), f, size, sum); err != nil {
		return nil, err
	}
	op.Log.Printf("event=space.backup space=%s bytes=%d sha=%.12s", s.Name, size, sum)
	if st == nil {
		st = map[string]any{}
	}
	st["backupSha"], st["lastBackup"] = sum, op.Now().UTC().Format(time.RFC3339)
	return st, nil
}

// BackupAll — снимки всех работающих пространств. Ошибка одного пространства не мешает остальным.
func (op *Operator) BackupAll(ctx context.Context) {
	if op.Backup == nil {
		return
	}
	items, err := op.Kube.List(ctx, fmt.Sprintf(spacesAPI, op.Namespace))
	if err != nil {
		op.Log.Printf("event=backup.list_failed err=%q", err.Error())
		return
	}
	for _, it := range items {
		s := parseSpace(it)
		// Только готовое пространство: спящее и ждущее удаления получили последний снимок перед остановкой.
		if str(it, "status", "phase") != "Ready" || s.Suspended || s.Deleting || s.RestorePending || s.Check() != nil {
			continue
		}
		st, err := op.backupOne(ctx, s)
		if err != nil {
			op.Log.Printf("event=space.backup_failed space=%s err=%q", s.Name, err.Error())
			continue
		}
		if st != nil {
			if err := op.Kube.PatchStatus(ctx, fmt.Sprintf(spacesAPI, op.Namespace)+"/"+s.Name, st); err != nil {
				op.Log.Printf("event=space.status_failed space=%s err=%q", s.Name, err.Error())
			}
		}
	}
}

// RunBackups — проходы BackupAll с шагом Backup.Every, пока не отменён контекст.
func (op *Operator) RunBackups(ctx context.Context) {
	if op.Backup == nil {
		return
	}
	t := time.NewTicker(op.Backup.Every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			op.BackupAll(ctx)
		}
	}
}

// beforeReconcile — то, что надо успеть до применения описания пространства:
//   - том создаётся заново, а копия в хранилище есть → отметить «восстановить» (сработает, когда агент запустится);
//   - агент сейчас работает, а описание его остановит (сон, ожидание удаления) → последний снимок.
//
// hold=true — применять описание пока нельзя: неизвестно, есть ли копия (хранилище не ответило). Создай оператор том
// сейчас, на следующем проходе он уже не выглядел бы новым, и восстановление не состоялось бы.
func (op *Operator) beforeReconcile(ctx context.Context, s *Space) (extra map[string]any, hold bool) {
	if op.Backup == nil || s.Check() != nil {
		return nil, false
	}
	ns := s.Namespace()
	if !s.Suspended && !s.stopped && !s.RestorePending {
		if _, err := op.Kube.Get(ctx, "/api/v1/namespaces/"+ns+"/persistentvolumeclaims/data"); errors.Is(err, ErrNotFound) {
			ok, err := op.Backup.Store.Exists(ctx, backupKey(s.Name))
			if err != nil {
				op.Log.Printf("event=space.backup_check_failed space=%s err=%q", s.Name, err.Error())
				return nil, true
			}
			if ok {
				op.Log.Printf("event=space.restore_planned space=%s", s.Name)
				s.RestorePending = true
				return map[string]any{"restorePending": true}, false
			}
		}
		return nil, false
	}
	if !s.Suspended && !s.stopped {
		return nil, false
	}
	d, err := op.Kube.Get(ctx, "/apis/apps/v1/namespaces/"+ns+"/deployments/space")
	if err != nil || !deploymentReady(d) {
		return nil, false // агент уже остановлен или ещё не запущен — снимать нечего
	}
	st, err := op.backupOne(ctx, *s)
	if err != nil {
		// Остановку не задерживаем: данные остаются на томе, а предыдущий снимок не старше шага копирования.
		op.Log.Printf("event=space.backup_failed space=%s when=before_stop err=%q", s.Name, err.Error())
		return nil, false
	}
	return st, false
}

// restore передаёт копию из хранилища агенту нового пустого пространства. done=false — повторить на следующем проходе.
func (op *Operator) restore(ctx context.Context, s Space) (map[string]any, bool) {
	b := op.Backup
	if b == nil {
		return map[string]any{"restorePending": nil}, true
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	giveUp := func(why string) (map[string]any, bool) {
		op.Log.Printf("event=space.restore_skipped space=%s reason=%q", s.Name, why)
		return map[string]any{"restorePending": nil, "restoreError": why}, true
	}
	r, err := b.agent(ctx, s, http.MethodGet, "/internal/backup/state", nil, 0)
	if err != nil {
		return nil, false
	}
	var state struct {
		Empty bool `json:"empty"`
	}
	bad := r.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&state) != nil
	r.Body.Close()
	if bad {
		return nil, false // токен ещё не доехал до пода или агент перезапускается
	}
	if !state.Empty {
		return giveUp("в пространстве уже есть данные — копия их затёрла бы")
	}
	// Файлы — до базы: пока базы нет, пространство пустое, и агент принимает файлы.
	if ok, err := op.restoreFiles(ctx, s); !ok {
		var ae errAgent
		if errors.As(err, &ae) && (ae.code == http.StatusBadRequest || ae.code == http.StatusConflict) {
			return giveUp("файлы: " + ae.Error())
		}
		op.Log.Printf("event=space.restore_failed space=%s err=%q", s.Name, fmt.Sprint(err))
		return nil, false
	}
	body, err := b.Store.Get(ctx, backupKey(s.Name))
	if errors.Is(err, ErrNotFound) {
		return giveUp("копии в хранилище нет")
	}
	if err != nil {
		op.Log.Printf("event=space.restore_failed space=%s err=%q", s.Name, err.Error())
		return nil, false
	}
	defer body.Close()
	f, err := os.CreateTemp(b.TmpDir, "restore-*")
	if err != nil {
		return nil, false
	}
	defer f.Close()
	os.Remove(f.Name())
	n, err := io.Copy(f, io.LimitReader(body, maxSnapshot+1))
	if err != nil || n > maxSnapshot {
		op.Log.Printf("event=space.restore_failed space=%s err=%q", s.Name, fmt.Sprint(err))
		return nil, false
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, false
	}
	resp, err := b.agent(ctx, s, http.MethodPost, "/internal/restore", f, n)
	if err != nil {
		op.Log.Printf("event=space.restore_failed space=%s err=%q", s.Name, err.Error())
		return nil, false
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
		op.Log.Printf("event=space.restored space=%s bytes=%d", s.Name, n)
		return map[string]any{"restorePending": nil, "restoreError": nil, "restoredAt": op.Now().UTC().Format(time.RFC3339)}, true
	case resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusConflict:
		return giveUp(agentErr(resp).Error()) // агент копию не принял: повтор ничего не изменит
	}
	op.Log.Printf("event=space.restore_failed space=%s err=%q", s.Name, agentErr(resp).Error())
	return nil, false
}
