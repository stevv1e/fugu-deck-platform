package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Общие пространства. Один человек создаёт пространство и зовёт в него других пользователей кластера; у каждого
// участника роль. Состав ведёт control-plane, но менять его можно только действием role_change, подписанным
// владельцем на телефоне (подпись проверяет keyguard): взломанный control-plane мог бы пустить в пространство
// постороннего и так — он выпускает токены входа, — но не может сделать это от имени владельца незаметно для журнала
// keyguard, а платить ключом спонсора посторонний всё равно не сможет: список допущенных подписывает спонсор.

// Team — общее пространство.
type Team struct {
	ID    string // t-<случайное>: имя объекта Space и ключ в подписанных действиях
	Title string
	Owner string
}

// Member — участник общего пространства.
type Member struct {
	Nick string
	Role string // owner | editor | reader
}

var (
	ErrOwnerRole = errors.New("роль владельца не меняется")
	teamRe       = regexp.MustCompile(`^t-[a-z0-9]{6,20}$`)
)

const (
	maxTeamsPerOwner = 10
	maxTeamMembers   = 50
)

// spaceAccess — что пользователю можно в пространстве.
type spaceAccess struct {
	Team      bool
	Owner     string // владелец пространства
	Role      string // роль пользователя в терминах агента: owner | editor | viewer
	Namespace string
	Key       string // поле space в подписанных действиях: u-<ник> или t-<id>
	Title     string
}

// access — доступ пользователя к пространству по имени. Личное — только своё; общее — если он участник.
func (s *Server) access(id *Identity, name string) (spaceAccess, bool) {
	if name == id.User {
		return spaceAccess{Owner: id.User, Role: "owner", Namespace: "deck-u-" + id.User, Key: "u-" + id.User, Title: id.User}, true
	}
	if !teamRe.MatchString(name) {
		return spaceAccess{}, false
	}
	t, err := s.Store.Team(name)
	if err != nil {
		return spaceAccess{}, false
	}
	ms, err := s.Store.Members(name)
	if err != nil {
		return spaceAccess{}, false
	}
	for _, m := range ms {
		if m.Nick == id.User {
			return spaceAccess{Team: true, Owner: t.Owner, Role: agentRole(m.Role), Namespace: "deck-" + name, Key: name, Title: t.Title}, true
		}
	}
	return spaceAccess{}, false
}

// agentRole — роль из подписанного действия (reader) в терминах агента (viewer).
func agentRole(r string) string {
	if r == "reader" {
		return "viewer"
	}
	return r
}

func newTeamID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "t-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}

// cleanTitle — название пространства: без управляющих символов, 1–60 знаков.
func cleanTitle(t string) (string, bool) {
	t = strings.TrimSpace(t)
	if t == "" || utf8.RuneCountInString(t) > 60 {
		return "", false
	}
	for _, r := range t {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	return t, true
}

func (s *Server) spaceJSON(info SpaceInfo, exists bool, acc spaceAccess, name string) map[string]any {
	out := map[string]any{"id": name, "kind": map[bool]string{true: "team", false: "personal"}[acc.Team], "title": acc.Title,
		"owner": acc.Owner, "role": acc.Role, "space": acc.Key, "exists": exists, "url": s.Cfg.APIURL + "/s/" + name}
	if exists {
		phase := info.Phase
		if phase == "" {
			phase = "Pending"
		}
		if phase != "Deleting" && asleep(info) {
			phase = "Sleeping"
		}
		out["phase"], out["message"] = phase, info.Message
		if info.DeleteRequested {
			out["delete_requested"] = true
			if info.DeleteAt != "" {
				out["delete_at"] = info.DeleteAt
			}
			if info.DeleteError != "" {
				out["delete_error"] = info.DeleteError
			}
		}
	}
	return out
}

func (s *Server) registerTeams(m *http.ServeMux) {
	// Все пространства пользователя: личное и общие, где он участник.
	m.HandleFunc("/v1/spaces", s.apiAny(func(w http.ResponseWriter, r *http.Request, id *Identity) {
		switch r.Method {
		case http.MethodGet:
			out := []map[string]any{}
			acc, _ := s.access(id, id.User)
			info, err := s.Spaces.Get(r.Context(), id.User)
			out = append(out, s.spaceJSON(info, err == nil, acc, id.User))
			teams, err := s.Store.TeamsOf(id.User)
			if err != nil {
				s.Log.Printf("event=state.failed op=teams_of err=%q", err.Error())
				fail(w, http.StatusServiceUnavailable, "временно недоступно")
				return
			}
			for _, t := range teams {
				acc, ok := s.access(id, t.ID)
				if !ok {
					continue
				}
				info, err := s.Spaces.Get(r.Context(), t.ID)
				out = append(out, s.spaceJSON(info, err == nil, acc, t.ID))
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			json.NewEncoder(w).Encode(map[string]any{"spaces": out})
		case http.MethodPost:
			body, ok := readSmall(w, r)
			if !ok {
				return
			}
			var q struct {
				Title string `json:"title"`
			}
			title, okT := "", false
			if json.Unmarshal(body, &q) == nil {
				title, okT = cleanTitle(q.Title)
			}
			if !okT {
				fail(w, http.StatusBadRequest, "название: от 1 до 60 знаков")
				return
			}
			teams, err := s.Store.TeamsOf(id.User)
			if err != nil {
				fail(w, http.StatusServiceUnavailable, "временно недоступно")
				return
			}
			owned := 0
			for _, t := range teams {
				if t.Owner == id.User {
					owned++
				}
			}
			if owned >= maxTeamsPerOwner {
				fail(w, http.StatusConflict, "слишком много общих пространств у одного владельца")
				return
			}
			_, pub, err := s.signer()
			if err != nil {
				fail(w, http.StatusServiceUnavailable, "временно недоступно")
				return
			}
			tid, err := newTeamID()
			if err != nil {
				fail(w, http.StatusServiceUnavailable, "временно недоступно")
				return
			}
			t := Team{ID: tid, Title: title, Owner: id.User}
			if err := s.Store.CreateTeam(t); err != nil {
				s.Log.Printf("event=team.create_failed user=%s err=%q", id.User, err.Error())
				fail(w, http.StatusServiceUnavailable, "не удалось создать пространство")
				return
			}
			if err := s.Spaces.EnsureTeam(r.Context(), tid, id.User, title, pub); err != nil {
				s.Store.DeleteTeam(tid) // без объекта Space запись бесполезна
				s.Log.Printf("event=team.create_failed user=%s err=%q", id.User, err.Error())
				fail(w, http.StatusBadGateway, "не удалось создать пространство")
				return
			}
			s.Log.Printf("event=team.created team=%s owner=%s device=%s", tid, id.User, id.DeviceID)
			acc, _ := s.access(id, tid)
			info, err := s.Spaces.Get(r.Context(), tid)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			json.NewEncoder(w).Encode(s.spaceJSON(info, err == nil, acc, tid))
		default:
			fail(w, http.StatusMethodNotAllowed, "GET или POST")
		}
	}))

	// /v1/spaces/<id>[/members|/delete|/restore|/wake]
	m.HandleFunc("/v1/spaces/", s.apiAny(func(w http.ResponseWriter, r *http.Request, id *Identity) {
		name, op, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/v1/spaces/"), "/")
		acc, ok := s.access(id, name)
		if !ok || !acc.Team { // личное пространство обслуживает /v1/space
			fail(w, http.StatusNotFound, "пространство не найдено")
			return
		}
		switch {
		case op == "" && r.Method == http.MethodGet:
			s.teamState(w, r, id, name, acc)
		case op == "wake" && r.Method == http.MethodPost:
			info, err := s.Spaces.Get(r.Context(), name)
			if err != nil {
				fail(w, http.StatusBadGateway, "не удалось узнать состояние пространства")
				return
			}
			if info.Phase != "Deleting" && asleep(info) && s.wake(r.Context(), info) != nil {
				fail(w, http.StatusBadGateway, "не удалось разбудить пространство")
				return
			}
			s.teamState(w, r, id, name, acc)
		case op == "members" && r.Method == http.MethodPost:
			s.teamMember(w, r, id, name, acc)
		case op == "delete" && r.Method == http.MethodPost:
			if acc.Owner != id.User {
				fail(w, http.StatusForbidden, "удалить пространство может только владелец")
				return
			}
			s.requestDelete(w, r, id, name, acc.Key, func(info SpaceInfo) { s.writeJSON(w, s.spaceJSON(info, true, acc, name)) })
		case op == "restore" && r.Method == http.MethodPost:
			if acc.Owner != id.User {
				fail(w, http.StatusForbidden, "отменить удаление может только владелец")
				return
			}
			s.cancelDelete(w, r, id, name, func(info SpaceInfo) { s.writeJSON(w, s.spaceJSON(info, true, acc, name)) })
		default:
			fail(w, http.StatusNotFound, "не найдено")
		}
	}))
}

// registerGrants — разрешения спонсоров. Спонсор подписывает на телефоне, на каких условиях общий чат может
// пользоваться его ключом (grant), или отзывает разрешение (grant_revoke). control-plane передаёт подпись в keyguard
// как есть: проверить, изменить или выпустить разрешение сам он не может. Здесь только отсекается разрешение для
// пространства, в котором подписавший не состоит.
func (s *Server) registerGrants(m *http.ServeMux) {
	for path, typ := range map[string]string{"/v1/grants": "grant", "/v1/grants/revoke": "grant_revoke"} {
		path, typ := path, typ
		m.HandleFunc(path, s.api(http.MethodPost, func(w http.ResponseWriter, r *http.Request, id *Identity) {
			body, ok := readSmall(w, r)
			if !ok {
				return
			}
			var q struct {
				JWS string `json:"jws"`
			}
			var a struct {
				Type, Space string
				DeviceID    string `json:"device_id"`
			}
			if json.Unmarshal(body, &q) != nil || !jwsRe.MatchString(q.JWS) {
				fail(w, http.StatusBadRequest, "нужно подписанное действие "+typ)
				return
			}
			payload, err := b64.DecodeString(strings.Split(q.JWS, ".")[1])
			if err != nil || json.Unmarshal(payload, &a) != nil || a.Type != typ || a.DeviceID != id.DeviceID {
				fail(w, http.StatusForbidden, "действие другого типа или подписано не этим устройством")
				return
			}
			if acc, ok := s.access(id, a.Space); !ok || !acc.Team {
				fail(w, http.StatusNotFound, "пространство не найдено")
				return
			}
			status, resp, ok := s.kgJSON(w, r, path, body)
			if !ok {
				return
			}
			s.Log.Printf("event=%s space=%s user=%s device=%s status=%d", typ, a.Space, id.User, id.DeviceID, status)
			relay(w, status, resp)
		}))
	}
}

func (s *Server) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func (s *Server) teamState(w http.ResponseWriter, r *http.Request, id *Identity, name string, acc spaceAccess) {
	info, err := s.Spaces.Get(r.Context(), name)
	if err != nil && !errors.Is(err, ErrNotFound) {
		fail(w, http.StatusBadGateway, "не удалось узнать состояние пространства")
		return
	}
	out := s.spaceJSON(info, err == nil, acc, name)
	ms, merr := s.Store.Members(name)
	if merr != nil {
		fail(w, http.StatusServiceUnavailable, "временно недоступно")
		return
	}
	list := make([]map[string]string, 0, len(ms))
	for _, m := range ms {
		list = append(list, map[string]string{"nick": m.Nick, "role": m.Role})
	}
	out["members"] = list
	s.writeJSON(w, out)
}

// teamMember — добавить участника, сменить роль или исключить: действие role_change, подписанное владельцем.
func (s *Server) teamMember(w http.ResponseWriter, r *http.Request, id *Identity, name string, acc spaceAccess) {
	if acc.Owner != id.User {
		fail(w, http.StatusForbidden, "состав пространства меняет владелец")
		return
	}
	body, ok := readSmall(w, r)
	if !ok {
		return
	}
	status, resp, ok := s.kgJSON(w, r, "/v1/actions/verify", body)
	if !ok {
		return
	}
	if status != http.StatusOK {
		relay(w, status, resp)
		return
	}
	var v struct {
		Action struct {
			Type, Space, Member, Role string
		} `json:"action"`
		User     string `json:"user"`
		DeviceID string `json:"device_id"`
	}
	if json.Unmarshal(resp, &v) != nil || v.Action.Type != "role_change" || v.Action.Space != name || v.User != id.User || v.DeviceID != id.DeviceID {
		fail(w, http.StatusForbidden, "действие не об этом пространстве или подписано не этим устройством")
		return
	}
	nick, role := v.Action.Member, v.Action.Role
	if role == "owner" && ValidNick(nick) && nick != acc.Owner {
		s.transferTeam(w, r, id, name, acc, nick)
		return
	}
	switch {
	case !ValidNick(nick):
		fail(w, http.StatusBadRequest, ErrBadNick.Error())
		return
	case nick == acc.Owner || role == "owner":
		fail(w, http.StatusConflict, "владелец пространства не меняется")
		return
	case role != "editor" && role != "reader" && role != "none":
		fail(w, http.StatusBadRequest, "роль: editor, reader или none")
		return
	}
	ms, err := s.Store.Members(name)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "временно недоступно")
		return
	}
	known := false
	for _, m := range ms {
		known = known || m.Nick == nick
	}
	if role == "none" {
		role = ""
	} else if !known {
		if len(ms) >= maxTeamMembers {
			fail(w, http.StatusConflict, "в пространстве слишком много участников")
			return
		}
		// Позвать можно только того, у кого есть действующее устройство в кластере: опечатка в нике не должна
		// молча «зарезервировать» место тому, кто зарегистрируется под ним позже.
		if !s.userActive(w, r, nick) {
			return
		}
	}
	if err := s.Store.SetMember(name, nick, role, id.User); err != nil {
		s.Log.Printf("event=team.member_failed team=%s member=%s err=%q", name, nick, err.Error())
		fail(w, http.StatusServiceUnavailable, "не удалось изменить состав")
		return
	}
	s.Log.Printf("event=team.member team=%s member=%s role=%q by=%s", name, nick, role, id.User)
	if role == "" {
		s.memberLeft(r.Context(), name, nick)
	}
	if info, err := s.Spaces.Get(r.Context(), name); err == nil && info.Phase == "Ready" {
		target := s.SpaceURL(info.Namespace)
		s.syncRoster(r.Context(), name, target)
		if role == "" {
			s.revokeInSpace(r.Context(), name, nick, target) // исключённого отключаем сразу, не дожидаясь срока токена
		}
	}
	s.teamState(w, r, id, name, acc)
}

// transferTeam — передача владения участнику (подпись role_change с ролью owner уже проверена keyguard).
// Новый владелец должен быть участником с действующим устройством; прежний становится редактором.
func (s *Server) transferTeam(w http.ResponseWriter, r *http.Request, id *Identity, name string, acc spaceAccess, nick string) {
	ms, err := s.Store.Members(name)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "временно недоступно")
		return
	}
	member := false
	for _, m := range ms {
		member = member || m.Nick == nick
	}
	if !member {
		fail(w, http.StatusConflict, "передать владение можно только участнику пространства")
		return
	}
	if !s.userActive(w, r, nick) {
		return
	}
	if err := s.doTransfer(r.Context(), name, nick); err != nil {
		s.Log.Printf("event=team.transfer_failed team=%s to=%s err=%q", name, nick, err.Error())
		fail(w, http.StatusServiceUnavailable, "не удалось передать владение")
		return
	}
	s.Log.Printf("event=team.transferred team=%s from=%s to=%s device=%s", name, id.User, nick, id.DeviceID)
	go s.notify(context.Background(), nick, Notification{Title: "Вы — владелец общего пространства",
		Body: id.User + " передал вам владение", Data: map[string]string{"kind": "team", "space": name}})
	acc.Owner = nick
	s.teamState(w, r, id, name, acc)
}

// doTransfer — запись о владельце в базе и в объекте Space (по нему оператор проверяет подписи удаления).
func (s *Server) doTransfer(ctx context.Context, team, nick string) error {
	if err := s.Store.TransferTeam(team, nick); err != nil {
		return err
	}
	if err := s.Spaces.SetOwner(ctx, team, nick); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if info, err := s.Spaces.Get(ctx, team); err == nil && info.Phase == "Ready" {
		s.syncRoster(ctx, team, s.SpaceURL(info.Namespace))
	}
	return nil
}

// userActive — есть ли у пользователя действующее устройство (спрашиваем keyguard). false — ответ уже отправлен.
func (s *Server) userActive(w http.ResponseWriter, r *http.Request, nick string) bool {
	q, _ := json.Marshal(map[string]string{"user": nick})
	status, resp, ok := s.kgJSON(w, r, "/v1/devices/list", q)
	if !ok {
		return false
	}
	var l struct {
		Devices []struct{ User, Status string }
	}
	if status != http.StatusOK || json.Unmarshal(resp, &l) != nil {
		fail(w, http.StatusBadGateway, "не удалось проверить пользователя")
		return false
	}
	for _, d := range l.Devices {
		if d.User == nick && d.Status == "active" {
			return true
		}
	}
	fail(w, http.StatusNotFound, "пользователя с таким ником и действующим устройством нет")
	return false
}

// ---------- состав для агента ----------

// rosterState — какой состав уже передан агенту каждого пространства (хеш), чтобы не слать его на каждый запрос.
type rosterState struct {
	mu   sync.Mutex
	sent map[string][32]byte
}

func (s *Server) internalPost(ctx context.Context, team string, target *url.URL, path string, claims map[string]any) error {
	claims["aud"], claims["sub"] = "space-internal:"+team, "control-plane"
	tok, err := s.signSpaceJWT(claims)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"token": tok})
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String()+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("агент ответил " + resp.Status)
	}
	return nil
}

// syncRoster передаёт агенту общего пространства состав участников, если он изменился с прошлой передачи.
// Агенту состав нужен для голосований и подписей в чате; права на запросы задаёт роль в токене, а не этот список.
func (s *Server) syncRoster(ctx context.Context, team string, target *url.URL) {
	ms, err := s.Store.Members(team)
	if err != nil {
		return
	}
	list := make([]map[string]string, 0, len(ms))
	for _, m := range ms {
		list = append(list, map[string]string{"id": m.Nick, "name": m.Nick, "role": agentRole(m.Role)})
	}
	raw, _ := json.Marshal(list)
	sum := sha256.Sum256(append([]byte(target.Host+"|"), raw...))
	s.rosters.mu.Lock()
	same := s.rosters.sent[team] == sum
	s.rosters.mu.Unlock()
	if same {
		return
	}
	if err := s.internalPost(ctx, team, target, "/internal/roster", map[string]any{"action": "roster", "members": list}); err != nil {
		s.Log.Printf("event=team.roster_failed team=%s err=%q", team, err.Error())
		return
	}
	s.rosters.mu.Lock()
	if s.rosters.sent == nil {
		s.rosters.sent = map[string][32]byte{}
	}
	s.rosters.sent[team] = sum
	s.rosters.mu.Unlock()
}

func (s *Server) revokeInSpace(ctx context.Context, team, nick string, target *url.URL) {
	if err := s.internalPost(ctx, team, target, "/internal/revoke", map[string]any{"action": "revoke", "user_id": nick}); err != nil {
		s.Log.Printf("event=team.revoke_failed team=%s member=%s err=%q", team, nick, err.Error())
	}
}

// memberLeft — исключённый участник: keyguard отзывает его разрешения спонсора и убирает его из чужих. Не удалось —
// в журнал (состав уже изменён; пространство при обновлении состава снимет такого спонсора и само).
func (s *Server) memberLeft(ctx context.Context, team, nick string) {
	body, _ := json.Marshal(map[string]string{"space": team, "member": nick})
	st, resp, err := s.KG.Post(ctx, "/v1/grants/member-left", body)
	if err != nil || st != http.StatusOK {
		s.Log.Printf("event=team.member_left_failed team=%s member=%s status=%d err=%v", team, nick, st, err)
		return
	}
	s.Log.Printf("event=team.member_left team=%s member=%s keyguard=%s", team, nick, strings.TrimSpace(string(resp)))
}
