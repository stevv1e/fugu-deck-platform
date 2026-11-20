package sshgateway

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"sync"
	"time"
)

// Журнал команд: что агент выполнил на серверах пространства, кто подтвердил и что вывелось. Хранится 30 дней
// (JournalKeep), не больше JournalMax записей на пространство; вывод — первые OutputKeep байт каждого потока.
// Файл JSONL на томе шлюза: запись дописывается строкой, раз в какое-то время файл переписывается без устаревшего.

const (
	JournalKeep = 30 * 24 * time.Hour
	JournalMax  = 500
	OutputKeep  = 4096
)

type Entry struct {
	Time     time.Time `json:"time"`
	Space    string    `json:"space"`
	Agent    string    `json:"agent"`
	Server   string    `json:"server"`
	Command  string    `json:"command"`
	Level    Level     `json:"level"`
	Signer   string    `json:"signer,omitempty"` // кто подписал (пусто — чтение без подтверждения или авто-write по разрешению)
	Auto     bool      `json:"auto,omitempty"`   // изменение (write) выполнено без подписи по стоячему разрешению владельца
	Exit     int       `json:"exit_code"`
	Millis   int64     `json:"duration_ms"`
	Stdout   string    `json:"stdout,omitempty"`
	Stderr   string    `json:"stderr,omitempty"`
	Error    string    `json:"error,omitempty"` // команда не выполнена (подключение, сертификат…)
	Stopped  bool      `json:"stopped,omitempty"`
	Preview  bool      `json:"preview,omitempty"` // пробный прогон перед подтверждением
	TimedOut bool      `json:"timed_out,omitempty"`
}

type Journal interface {
	Append(e Entry) error
	List(space string, limit int) ([]Entry, error)
}

func clip(s string) string {
	if len(s) <= OutputKeep {
		return s
	}
	return s[:OutputKeep] + "\n…(обрезано)"
}

// FileJournal — path == "" — только память (тесты).
type FileJournal struct {
	mu    sync.Mutex
	path  string
	now   func() time.Time
	m     map[string][]Entry
	lines int
}

func OpenFileJournal(path string, now func() time.Time) (*FileJournal, error) {
	if now == nil {
		now = time.Now
	}
	j := &FileJournal{path: path, now: now, m: map[string][]Entry{}}
	if path == "" {
		return j, nil
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return j, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) == nil { // битая строка (обрыв при записи) пропускается
			j.m[e.Space] = append(j.m[e.Space], e)
			j.lines++
		}
	}
	j.prune()
	return j, j.compact()
}

// prune — убрать устаревшее и лишнее (под j.mu или при открытии).
func (j *FileJournal) prune() {
	cutoff := j.now().Add(-JournalKeep)
	for sp, es := range j.m {
		kept := es[:0]
		for _, e := range es {
			if e.Time.After(cutoff) {
				kept = append(kept, e)
			}
		}
		if len(kept) > JournalMax {
			kept = kept[len(kept)-JournalMax:]
		}
		if len(kept) == 0 {
			delete(j.m, sp)
		} else {
			j.m[sp] = kept
		}
	}
}

// compact переписывает файл только с тем, что хранится (через временный файл и переименование).
func (j *FileJournal) compact() error {
	if j.path == "" {
		return nil
	}
	tmp := j.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	n := 0
	spaces := make([]string, 0, len(j.m))
	for sp := range j.m {
		spaces = append(spaces, sp)
	}
	sort.Strings(spaces)
	for _, sp := range spaces {
		for _, e := range j.m[sp] {
			if err := enc.Encode(e); err != nil {
				f.Close()
				return err
			}
			n++
		}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	j.lines = n
	return os.Rename(tmp, j.path)
}

func (j *FileJournal) Append(e Entry) error {
	e.Stdout, e.Stderr = clip(e.Stdout), clip(e.Stderr)
	j.mu.Lock()
	defer j.mu.Unlock()
	j.m[e.Space] = append(j.m[e.Space], e)
	if j.path == "" {
		j.prune()
		return nil
	}
	f, err := os.OpenFile(j.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(e)
	_, err = f.Write(append(b, '\n'))
	f.Close()
	j.lines++
	total := 0
	j.prune()
	for _, es := range j.m {
		total += len(es)
	}
	if j.lines > 2*total+100 { // в файле вдвое больше, чем храним, — переписать
		return j.compact()
	}
	return err
}

// List — последние записи пространства, новые первыми.
func (j *FileJournal) List(space string, limit int) ([]Entry, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.prune()
	es := j.m[space]
	out := make([]Entry, 0, len(es))
	for i := len(es) - 1; i >= 0 && (limit <= 0 || len(out) < limit); i-- {
		out = append(out, es[i])
	}
	return out, nil
}
