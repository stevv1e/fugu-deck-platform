package sshgateway

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Server — сервер пользователя, как его подписал владелец (действие server_add): адрес, пользователь и отпечаток
// ключа хоста. Шлюз подключается только к тому, что подписано, и только если ключ хоста совпал.
type Server struct {
	ID      string    `json:"id"`
	Host    string    `json:"host"`
	Port    int       `json:"port"`
	User    string    `json:"user"`
	HostKey string    `json:"host_key"` // SHA256:<43 символа base64>
	AddedBy string    `json:"added_by"`
	Device  string    `json:"device"`
	Added   time.Time `json:"added"`
}

// Rights — права агента, подписанные владельцем (действие agent_rights): к каким серверам он допущен и можно ли
// ему читать без подтверждения.
type Rights struct {
	Agent              string   `json:"agent"`
	Servers            []string `json:"servers"`
	ReadWithoutConfirm bool     `json:"read_without_confirm"`
	// Изменения (write) без подписи каждой команды — до срока WriteAutoUntil (unix-секунды). Danger — никогда.
	WriteWithoutConfirm bool      `json:"write_without_confirm,omitempty"`
	WriteAutoUntil      int64     `json:"write_auto_until,omitempty"`
	SignedBy            string    `json:"signed_by"`
	Device              string    `json:"device"`
	Signed              time.Time `json:"signed"`
}

func (r Rights) Allows(server string) bool {
	for _, s := range r.Servers {
		if s == server {
			return true
		}
	}
	return false
}

// WriteAuto — действует ли сейчас разрешение владельца на изменения без подписи (write), с учётом срока.
func (r Rights) WriteAuto(now time.Time) bool {
	return r.WriteWithoutConfirm && now.Unix() < r.WriteAutoUntil
}

// spaceState — всё, что шлюз знает об одном пространстве.
type spaceState struct {
	Servers map[string]Server `json:"servers"`
	Rights  map[string]Rights `json:"rights"`
	Paused  bool              `json:"paused,omitempty"` // владелец остановил агента на серверах
}

var ErrNotFound = errors.New("не найдено")

// Store — подписанные привязки. Проверенное действие нельзя проверить второй раз (keyguard сжигает его номер),
// поэтому результат проверки хранит сам шлюз. Писать сюда может только он.
type Store interface {
	PutServer(space string, s Server) error
	DeleteServer(space, id string) error
	PutRights(space string, r Rights) error
	Server(space, id string) (Server, error)
	Rights(space, agent string) (Rights, error)
	List(space string) ([]Server, []Rights, error)
	SetPaused(space string, paused bool) error
	Paused(space string) bool
}

// FileStore — состояние в одном файле JSON (том шлюза). Запись — через временный файл и переименование: файл либо
// прежний, либо новый целиком. path == "" — только память (тесты).
type FileStore struct {
	mu     sync.Mutex
	path   string
	spaces map[string]*spaceState
}

func OpenFileStore(path string) (*FileStore, error) {
	f := &FileStore{path: path, spaces: map[string]*spaceState{}}
	if path == "" {
		return f, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &f.spaces); err != nil {
			return nil, err // повреждённый файл не затираем пустым состоянием: пусть человек посмотрит
		}
	}
	return f, nil
}

func (f *FileStore) space(name string) *spaceState {
	s := f.spaces[name]
	if s == nil {
		s = &spaceState{}
		f.spaces[name] = s
	}
	if s.Servers == nil {
		s.Servers = map[string]Server{}
	}
	if s.Rights == nil {
		s.Rights = map[string]Rights{}
	}
	return s
}

// save пишет состояние на диск; вызывается под f.mu.
func (f *FileStore) save() error {
	if f.path == "" {
		return nil
	}
	b, err := json.Marshal(f.spaces)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.path), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.path)
}

func (f *FileStore) PutServer(space string, s Server) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.space(space).Servers[s.ID] = s
	return f.save()
}

func (f *FileStore) DeleteServer(space, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	sp := f.space(space)
	if _, ok := sp.Servers[id]; !ok {
		return ErrNotFound
	}
	delete(sp.Servers, id)
	// Сервер убран — права агентов на него тоже: новый сервер с тем же id не должен унаследовать старое разрешение.
	for a, r := range sp.Rights {
		kept := r.Servers[:0:0]
		for _, s := range r.Servers {
			if s != id {
				kept = append(kept, s)
			}
		}
		r.Servers = kept
		sp.Rights[a] = r
	}
	return f.save()
}

func (f *FileStore) PutRights(space string, r Rights) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.space(space).Rights[r.Agent] = r
	return f.save()
}

func (f *FileStore) Server(space, id string) (Server, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.space(space).Servers[id]
	if !ok {
		return Server{}, ErrNotFound
	}
	return s, nil
}

func (f *FileStore) Rights(space, agent string) (Rights, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.space(space).Rights[agent]
	if !ok {
		return Rights{}, ErrNotFound
	}
	return r, nil
}

func (f *FileStore) List(space string) ([]Server, []Rights, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sp := f.space(space)
	servers, rights := []Server{}, []Rights{}
	for _, s := range sp.Servers {
		servers = append(servers, s)
	}
	for _, r := range sp.Rights {
		rights = append(rights, r)
	}
	sort.Slice(servers, func(i, j int) bool { return servers[i].ID < servers[j].ID })
	sort.Slice(rights, func(i, j int) bool { return rights[i].Agent < rights[j].Agent })
	return servers, rights, nil
}

func (f *FileStore) SetPaused(space string, paused bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.space(space).Paused = paused
	return f.save()
}

func (f *FileStore) Paused(space string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.space(space).Paused
}
