package spaceoperator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"time"
)

// Файлы пространства (вложения, файлы агента, скилы) — рядом со снимком базы. Каждый файл хранится один раз под
// своим SHA-256 (spaces/<имя>/files/<sha>): одинаковые не дублируются, загруженный не меняется. Опись
// spaces/<имя>/files.json — какой файл где лежал, и все когда-либо загруженные (по ним при удалении пространства
// убирается всё). Восстановление — до базы, только в пустое пространство: агент сам проверяет это и хеш каждого файла.

const maxFile = 64 << 20

var shaRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

type fileEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type fileManifest struct {
	Files []fileEntry `json:"files"`
	All   []string    `json:"all"` // все SHA, когда-либо загруженные для этого пространства
}

func filesKey(space string) string     { return "spaces/" + space + "/files.json" }
func fileKey(space, sha string) string { return "spaces/" + space + "/files/" + sha }
func manifestSHA(m []fileEntry) string {
	b, _ := json.Marshal(m)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (b *Backups) agentManifest(ctx context.Context, s Space) ([]fileEntry, error) {
	r, err := b.agent(ctx, s, http.MethodGet, "/internal/backup/files", nil, 0)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.StatusCode == http.StatusNotFound {
		return nil, errNoFiles // агент старой версии: описи файлов ещё не умеет
	}
	if r.StatusCode != http.StatusOK {
		return nil, agentErr(r)
	}
	var m struct {
		Files []fileEntry `json:"files"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<20)).Decode(&m); err != nil {
		return nil, err
	}
	for _, f := range m.Files {
		if !shaRe.MatchString(f.SHA256) || f.Size < 0 || f.Size > maxFile || f.Path == "" {
			return nil, fmt.Errorf("опись агента: неверная запись %q", f.Path)
		}
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	return m.Files, nil
}

var errNoFiles = errors.New("агент не отдаёт опись файлов")

func (b *Backups) storedManifest(ctx context.Context, space string) (fileManifest, error) {
	var m fileManifest
	body, err := b.Store.Get(ctx, filesKey(space))
	if errors.Is(err, ErrNotFound) {
		return m, nil
	}
	if err != nil {
		return m, err
	}
	defer body.Close()
	return m, json.NewDecoder(io.LimitReader(body, 32<<20)).Decode(&m)
}

// uploadFile забирает файл у агента во временный файл, сверяет хеш и кладёт в хранилище.
func (b *Backups) uploadFile(ctx context.Context, s Space, f fileEntry) error {
	r, err := b.agent(ctx, s, http.MethodGet, "/internal/backup/file?path="+url.QueryEscape(f.Path), nil, 0)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode == http.StatusNotFound {
		return nil // файл удалили между описью и запросом — попадёт в следующий проход как надо
	}
	if r.StatusCode != http.StatusOK {
		return agentErr(r)
	}
	tmp, err := os.CreateTemp(b.TmpDir, "file-*")
	if err != nil {
		return err
	}
	os.Remove(tmp.Name())
	defer tmp.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r.Body, maxFile+1))
	if err != nil {
		return err
	}
	if n > maxFile || hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
		return nil // файл изменился после описи — следующий проход возьмёт новую версию
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return b.Store.Put(ctx, fileKey(s.Name, f.SHA256), tmp, n, f.SHA256)
}

// backupFiles — новые файлы пространства в хранилище и новая опись. Возвращает поля status (nil — без изменений).
func (op *Operator) backupFiles(ctx context.Context, s Space) (map[string]any, error) {
	b := op.Backup
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cur, err := b.agentManifest(ctx, s)
	if err != nil {
		return nil, err
	}
	sum := manifestSHA(cur)
	if sum == s.FilesSHA {
		return nil, nil
	}
	old, err := b.storedManifest(ctx, s.Name)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, x := range old.All {
		known[x] = true
	}
	all := append([]string{}, old.All...)
	uploaded := 0
	for _, f := range cur {
		if known[f.SHA256] {
			continue
		}
		// всё, что могло попасть в хранилище, — сразу в «все»: при удалении пространства уберётся
		if err := b.uploadFile(ctx, s, f); err != nil {
			return nil, err
		}
		known[f.SHA256] = true
		all = append(all, f.SHA256)
		uploaded++
	}
	body, _ := json.Marshal(fileManifest{Files: cur, All: all})
	h := sha256.Sum256(body)
	if err := b.Store.Put(ctx, filesKey(s.Name), bytes.NewReader(body), int64(len(body)), hex.EncodeToString(h[:])); err != nil {
		return nil, err
	}
	op.Log.Printf("event=space.backup_files space=%s files=%d uploaded=%d", s.Name, len(cur), uploaded)
	return map[string]any{"filesSha": sum}, nil
}

// restoreFiles возвращает файлы из описи в новое пустое пространство (до базы). done=false — повторить позже.
func (op *Operator) restoreFiles(ctx context.Context, s Space) (bool, error) {
	b := op.Backup
	m, err := b.storedManifest(ctx, s.Name)
	if err != nil {
		return false, err
	}
	for _, f := range m.Files {
		body, err := b.Store.Get(ctx, fileKey(s.Name, f.SHA256))
		if errors.Is(err, ErrNotFound) {
			op.Log.Printf("event=space.restore_file_missing space=%s path=%q", s.Name, f.Path)
			continue // одного файла нет — остальное важнее
		}
		if err != nil {
			return false, err
		}
		q := url.Values{"path": {f.Path}, "sha256": {f.SHA256}}
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, b.url(s.Namespace(), "/internal/restore/file?"+q.Encode()), body)
		if err != nil {
			body.Close()
			return false, err
		}
		req.ContentLength = f.Size
		req.Header.Set("Authorization", "Bearer "+b.Token(s.Name))
		resp, err := b.HTTP.Do(req)
		body.Close()
		if err != nil {
			return false, err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return false, errAgent{resp.StatusCode, "файл " + f.Path}
		}
	}
	if len(m.Files) > 0 {
		op.Log.Printf("event=space.restored_files space=%s files=%d", s.Name, len(m.Files))
	}
	return true, nil
}

// deleteFiles убирает все файлы пространства и опись (при удалении пространства).
func (op *Operator) deleteFiles(ctx context.Context, space string) error {
	b := op.Backup
	m, err := b.storedManifest(ctx, space)
	if err != nil {
		return err
	}
	for _, sha := range m.All {
		if err := b.Store.Delete(ctx, fileKey(space, sha)); err != nil {
			return err
		}
	}
	return b.Store.Delete(ctx, filesKey(space))
}
