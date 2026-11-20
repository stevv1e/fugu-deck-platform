package controlplane

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// teamStand — вход на api, хранилище Space в памяти и «агент», который проверяет токены control-plane так же,
// как backend: подпись ключом из аннотации Space; запоминает, с какой ролью и куда к нему пришли.
type teamStand struct {
	*authStand
	sp     *fakeSpaces
	calls  []string         // "<роль> <метод> <путь>" для запросов приложения
	roster []map[string]any // последний переданный состав
	revoke []string
}

func newTeamStand(t *testing.T) *teamStand {
	t.Helper()
	st := &teamStand{authStand: newAuthStand(t), sp: &fakeSpaces{m: map[string]SpaceInfo{}}}
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		space := r.Host // у каждого пространства свой адрес: проверяем, что токен выпущен именно для него
		var pub string
		for _, sp := range st.sp.m {
			if strings.HasPrefix(space, "127.0.0.1") {
				pub = sp.TokenKey
			}
		}
		blk, _ := pem.Decode([]byte(pub))
		if blk == nil {
			http.Error(w, "нет ключа", 500)
			return
		}
		pk, _ := x509.ParsePKIXPublicKey(blk.Bytes)
		check := func(tok string) map[string]any {
			_, cl, err := verifyJWS(tok, func(map[string]any) (crypto.PublicKey, error) { return pk, nil })
			if err != nil || cl["iss"] != "deck-control-plane" {
				return nil
			}
			return cl
		}
		if strings.HasPrefix(r.URL.Path, "/internal/") {
			var b struct{ Token string }
			raw, _ := io.ReadAll(r.Body)
			json.Unmarshal(raw, &b)
			cl := check(b.Token)
			if cl == nil || !strings.HasPrefix(cl["aud"].(string), "space-internal:t-") {
				http.Error(w, "служебный токен не принят", 401)
				return
			}
			switch cl["action"] {
			case "roster":
				st.roster = nil
				for _, m := range cl["members"].([]any) {
					st.roster = append(st.roster, m.(map[string]any))
				}
			case "revoke":
				st.revoke = append(st.revoke, cl["user_id"].(string))
			}
			io.WriteString(w, `{"ok":true}`)
			return
		}
		cl := check(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if cl == nil || !strings.HasPrefix(cl["aud"].(string), "space:") {
			http.Error(w, "токен пространства не принят", 401)
			return
		}
		st.calls = append(st.calls, cl["role"].(string)+" "+cl["sub"].(string)+" "+cl["aud"].(string)+" "+r.Method+" "+r.URL.Path)
		io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(agent.Close)
	u, _ := url.Parse(agent.URL)
	st.s.Spaces = st.sp
	st.s.SpaceURL = func(string) *url.URL { return u }
	return st
}

// as — запрос от имени другого пользователя (то же устройство стенда, другой ник в токене Keycloak).
func (st *teamStand) as(user, method, path, body string) *httptest.ResponseRecorder {
	tok := st.token(map[string]any{"preferred_username": user})
	return st.req(method, path, body, func(r *http.Request) {
		r.Header.Set("Authorization", "DPoP "+tok)
		htu, _, _ := strings.Cut("https://api.deck.test"+path, "?")
		r.Header.Set("DPoP", st.proof(st.device, method, htu, tok, nil))
	})
}

func (st *teamStand) verified(space, by, member, role string) {
	st.kg.byPath = map[string]string{
		"/v1/actions/verify": `{"action":{"type":"role_change","space":"` + space + `","member":"` + member + `","role":"` + role +
			`"},"user":"` + by + `","device_id":"d-device1"}`,
		"/v1/devices/list": `{"devices":[{"id":"d-b","user":"bob","status":"active"},{"id":"d-c","user":"carol","status":"active"},` +
			`{"id":"d-x","user":"dave","status":"revoked"}],"admin":true}`,
	}
}

func TestTeamSpaces(t *testing.T) {
	st := newTeamStand(t)
	for _, bad := range []string{`{"title":""}`, `{"title":"` + strings.Repeat("я", 61) + `"}`, `{"title":"a\nb"}`, `nope`} {
		if w := st.as("anna", "POST", "/v1/spaces", bad); w.Code != 400 {
			t.Errorf("название %s: %d", bad, w.Code)
		}
	}
	w := st.as("anna", "POST", "/v1/spaces", `{"title":"Магазин"}`)
	var created struct{ ID, Kind, Role, Owner, Title, Space, URL string }
	json.Unmarshal(w.Body.Bytes(), &created)
	tid := created.ID
	if w.Code != 200 || !teamRe.MatchString(tid) || created.Kind != "team" || created.Role != "owner" || created.Space != tid ||
		created.Title != "Магазин" || created.URL != "https://api.deck.test/s/"+tid {
		t.Fatalf("создание: %d %s", w.Code, w.Body)
	}
	if sp := st.sp.m[tid]; sp.Owner != "anna" || !strings.HasPrefix(sp.TokenKey, "-----BEGIN PUBLIC KEY-----") {
		t.Fatalf("объект Space общего пространства: %+v", sp)
	}
	ready := func(name, ns string) { s := st.sp.m[name]; s.Phase, s.Namespace = "Ready", ns; st.sp.m[name] = s }
	ready(tid, "deck-"+tid)

	// Список: личное (ещё не создано) и общее.
	w = st.as("anna", "GET", "/v1/spaces", "")
	if !strings.Contains(w.Body.String(), `"id":"anna"`) || !strings.Contains(w.Body.String(), `"id":"`+tid+`"`) || !strings.Contains(w.Body.String(), `"kind":"personal"`) {
		t.Fatalf("список Анны: %s", w.Body)
	}
	if w := st.as("bob", "GET", "/v1/spaces", ""); strings.Contains(w.Body.String(), tid) {
		t.Fatalf("Боб видит чужое пространство: %s", w.Body)
	}
	// Не участник: пространства для него нет — ни состояния, ни входа, ни состава.
	for _, p := range []string{"/v1/spaces/" + tid, "/s/" + tid + "/api/projects"} {
		if w := st.as("bob", "GET", p, ""); w.Code != 404 {
			t.Errorf("не участник, %s: %d", p, w.Code)
		}
	}
	if len(st.calls) != 0 {
		t.Fatalf("запрос не участника дошёл до агента: %v", st.calls)
	}

	// Состав меняет только владелец и только подписанным действием об этом пространстве.
	member := func(by string) *httptest.ResponseRecorder {
		return st.as(by, "POST", "/v1/spaces/"+tid+"/members", `{"jws":"x.y.z"}`)
	}
	deny := map[string]func(){
		"подписал не тот, кто вошёл":     func() { st.verified(tid, "bob", "bob", "editor") },
		"действие о другом пространстве": func() { st.verified("t-other0001", "anna", "bob", "editor") },
		"передача владения":              func() { st.verified(tid, "anna", "bob", "owner") },
		"смена роли владельца":           func() { st.verified(tid, "anna", "anna", "reader") },
		"неизвестный пользователь":       func() { st.verified(tid, "anna", "nobody", "editor") },
		"пользователь без устройств":     func() { st.verified(tid, "anna", "dave", "editor") },
		"недопустимый ник":               func() { st.verified(tid, "anna", "../x", "editor") },
	}
	for name, set := range deny {
		set()
		if w := member("anna"); w.Code == 200 {
			t.Errorf("%s: состав изменён (%s)", name, w.Body)
		}
	}
	st.verified(tid, "anna", "bob", "editor")
	if w := member("anna"); w.Code != 200 || !strings.Contains(w.Body.String(), `{"nick":"bob","role":"editor"}`) {
		t.Fatalf("добавление Боба: %d %s", w.Code, w.Body)
	}
	if len(st.roster) != 2 {
		t.Fatalf("агенту не передан состав: %v", st.roster)
	}
	// Боб — редактор: входит со своей ролью; сам состав менять не может.
	if w := st.as("bob", "POST", "/s/"+tid+"/api/projects", "{}"); w.Code != 200 || st.calls[len(st.calls)-1] != "editor bob space:"+tid+" POST /api/projects" {
		t.Fatalf("вход Боба: %d %v", w.Code, st.calls)
	}
	st.verified(tid, "bob", "carol", "editor")
	if w := member("bob"); w.Code != 403 {
		t.Fatalf("участник меняет состав: %d", w.Code)
	}
	// Читатель получает у агента роль viewer.
	st.verified(tid, "anna", "carol", "reader")
	member("anna")
	if w := st.as("carol", "GET", "/s/"+tid+"/api/projects", ""); w.Code != 200 || !strings.HasPrefix(st.calls[len(st.calls)-1], "viewer carol ") {
		t.Fatalf("вход читателя: %d %v", w.Code, st.calls)
	}
	// Владелец — owner, и чужая роль в общем пространстве не переносится в его личное.
	st.as("anna", "GET", "/s/"+tid+"/api/projects", "")
	if !strings.HasPrefix(st.calls[len(st.calls)-1], "owner anna space:"+tid+" ") {
		t.Fatalf("вход владельца: %v", st.calls)
	}
	if w := st.as("bob", "GET", "/s/anna/api/projects", ""); w.Code != 404 {
		t.Fatalf("участник общего пространства попал в личное пространство владельца: %d", w.Code)
	}

	// Исключение: вход закрыт сразу, агенту велено отключить.
	st.verified(tid, "anna", "bob", "none")
	if w := member("anna"); w.Code != 200 || strings.Contains(w.Body.String(), `"nick":"bob"`) {
		t.Fatalf("исключение: %d %s", w.Code, w.Body)
	}
	if len(st.revoke) != 1 || st.revoke[0] != "bob" || len(st.roster) != 2 {
		t.Fatalf("после исключения: revoke=%v roster=%v", st.revoke, st.roster)
	}
	left := -1
	for i, c := range st.kg.calls {
		if c == "/v1/grants/member-left" {
			left = i
		}
	}
	if left < 0 || string(st.kg.bodies[left]) != `{"member":"bob","space":"`+tid+`"}` {
		t.Fatalf("keyguard не узнал об исключении (разрешения Боба как спонсора остались бы): %v", st.kg.calls)
	}
	if w := st.as("bob", "GET", "/s/"+tid+"/api/projects", ""); w.Code != 404 {
		t.Fatalf("исключённый входит: %d", w.Code)
	}

	// Удаление — только владелец и только подписью для этого пространства.
	good := fakeJWS(map[string]any{"type": "space_delete", "space": tid, "device_id": "d-device1"})
	body := `{"jws":"` + good + `"}`
	if w := st.as("carol", "POST", "/v1/spaces/"+tid+"/delete", body); w.Code != 403 {
		t.Fatalf("участник удаляет пространство: %d", w.Code)
	}
	personal := fakeJWS(map[string]any{"type": "space_delete", "space": "u-anna", "device_id": "d-device1"})
	if w := st.as("anna", "POST", "/v1/spaces/"+tid+"/delete", `{"jws":"`+personal+`"}`); w.Code != 403 || st.sp.m[tid].DeleteRequested {
		t.Fatalf("подпись на удаление личного пространства принята для общего: %d", w.Code)
	}
	if w := st.as("anna", "POST", "/v1/spaces/"+tid+"/delete", body); w.Code != 200 || !st.sp.m[tid].DeleteRequested || st.sp.deleteSig != good {
		t.Fatalf("удаление владельцем: %d %s", w.Code, w.Body)
	}
	if w := st.as("anna", "POST", "/v1/spaces/"+tid+"/restore", ""); w.Code != 200 || st.sp.m[tid].DeleteRequested {
		t.Fatalf("отмена: %d", w.Code)
	}

	// Сон и пробуждение работают и для общего пространства.
	s := st.sp.m[tid]
	s.Suspended, s.Phase = true, "Sleeping"
	st.sp.m[tid] = s
	if w := st.as("carol", "GET", "/s/"+tid+"/api/projects", ""); w.Code != 503 || st.sp.m[tid].Suspended {
		t.Fatalf("участник будит общее пространство: %d", w.Code)
	}
}

func TestGrantsRelay(t *testing.T) {
	st := newTeamStand(t)
	w := st.as("anna", "POST", "/v1/spaces", `{"title":"Магазин"}`)
	var created struct{ ID string }
	json.Unmarshal(w.Body.Bytes(), &created)
	tid := created.ID
	st.verified(tid, "anna", "bob", "editor")
	st.as("anna", "POST", "/v1/spaces/"+tid+"/members", `{"jws":"x.y.z"}`)
	st.kg.byPath = map[string]string{"/v1/grants": `{"grant_id":"g-abc"}`, "/v1/grants/revoke": `{"ok":true}`}
	jws := func(typ, space, dev string) string {
		return `{"jws":"` + fakeJWS(map[string]any{"type": typ, "space": space, "device_id": dev, "chat": "c1"}) + `"}`
	}
	n := len(st.kg.calls)
	// Участник подписывает разрешение для своего общего пространства — подпись уходит в keyguard без изменений.
	body := jws("grant", tid, "d-device1")
	if w := st.as("bob", "POST", "/v1/grants", body); w.Code != 200 || w.Body.String() != `{"grant_id":"g-abc"}` ||
		st.kg.calls[len(st.kg.calls)-1] != "/v1/grants" || string(st.kg.bodies[len(st.kg.bodies)-1]) != body {
		t.Fatalf("разрешение: %d %s %v", w.Code, w.Body, st.kg.calls[n:])
	}
	if w := st.as("bob", "POST", "/v1/grants/revoke", jws("grant_revoke", tid, "d-device1")); w.Code != 200 || st.kg.calls[len(st.kg.calls)-1] != "/v1/grants/revoke" {
		t.Fatalf("отзыв: %d", w.Code)
	}
	n = len(st.kg.calls)
	for name, w := range map[string]*httptest.ResponseRecorder{
		"не участник пространства":     st.as("carol", "POST", "/v1/grants", jws("grant", tid, "d-device1")),
		"личное пространство":          st.as("anna", "POST", "/v1/grants", jws("grant", "u-anna", "d-device1")),
		"действие другого типа":        st.as("bob", "POST", "/v1/grants", jws("grant_revoke", tid, "d-device1")),
		"отзыв вместо разрешения":      st.as("bob", "POST", "/v1/grants/revoke", jws("grant", tid, "d-device1")),
		"подписано другим устройством": st.as("bob", "POST", "/v1/grants", jws("grant", tid, "d-other")),
		"не подписанное действие":      st.as("bob", "POST", "/v1/grants", `{"jws":"мусор"}`),
	} {
		if w.Code == 200 {
			t.Errorf("%s: принято", name)
		}
	}
	if len(st.kg.calls) != n {
		t.Fatalf("отклонённое дошло до keyguard: %v", st.kg.calls[n:])
	}
}

func TestTeamLimits(t *testing.T) {
	st := newTeamStand(t)
	for i := 0; i < maxTeamsPerOwner; i++ {
		if w := st.as("anna", "POST", "/v1/spaces", `{"title":"п"}`); w.Code != 200 {
			t.Fatalf("пространство %d: %d", i, w.Code)
		}
	}
	if w := st.as("anna", "POST", "/v1/spaces", `{"title":"лишнее"}`); w.Code != 409 {
		t.Fatalf("сверх лимита: %d", w.Code)
	}
	if w := st.as("bob", "POST", "/v1/spaces", `{"title":"у Боба свой счёт"}`); w.Code != 200 {
		t.Fatalf("лимит одного владельца задел другого: %d", w.Code)
	}
}

// Передача владения, наследник при удалении аккаунта, неактивность.
func TestTeamTransferAndInactive(t *testing.T) {
	st := newTeamStand(t)
	push := &fakePush{gone: map[string]bool{}}
	st.s.Push = push
	w := st.as("anna", "POST", "/v1/spaces", `{"title":"Магазин"}`)
	var created struct{ ID string }
	json.Unmarshal(w.Body.Bytes(), &created)
	tid := created.ID
	s := st.sp.m[tid]
	s.Phase, s.Namespace = "Ready", "deck-"+tid
	st.sp.m[tid] = s
	st.verified(tid, "anna", "bob", "editor")
	st.as("anna", "POST", "/v1/spaces/"+tid+"/members", `{"jws":"x.y.z"}`)
	st.verified(tid, "anna", "carol", "owner")
	if w := st.as("anna", "POST", "/v1/spaces/"+tid+"/members", `{"jws":"x.y.z"}`); w.Code == 200 {
		t.Fatal("владение передано не участнику")
	}
	st.s.Store.PutPushToken("bob", "d-b", "fcm-token-bob-0123456789")
	st.verified(tid, "anna", "bob", "owner")
	w = st.as("anna", "POST", "/v1/spaces/"+tid+"/members", `{"jws":"x.y.z"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `{"nick":"bob","role":"owner"}`) || !strings.Contains(w.Body.String(), `{"nick":"anna","role":"editor"}`) {
		t.Fatalf("передача владения: %d %s", w.Code, w.Body)
	}
	if tm, _ := st.s.Store.Team(tid); tm.Owner != "bob" || st.sp.m[tid].Owner != "bob" {
		t.Fatalf("владелец в базе и в Space: %+v %+v", tm, st.sp.m[tid])
	}
	// Состав теперь меняет Боб, а не Анна.
	st.verified(tid, "anna", "carol", "editor")
	if w := st.as("anna", "POST", "/v1/spaces/"+tid+"/members", `{"jws":"x.y.z"}`); w.Code != 403 {
		t.Fatalf("бывший владелец меняет состав: %d", w.Code)
	}

	// Боб удаляет аккаунт: пространство уходит старшему редактору (Анне), Боб исключается.
	s = st.sp.m["bob"]
	s.Name, s.Owner, s.DeleteKind, s.DeleteRequested, s.DeleteAt = "bob", "bob", "account", true, st.now.Add(-time.Minute).Format(time.RFC3339)
	st.sp.m["bob"] = s
	st.s.FinishAccountDeletions(context.Background())
	tm, _ := st.s.Store.Team(tid)
	ms, _ := st.s.Store.Members(tid)
	if tm.Owner != "anna" || len(ms) != 1 || ms[0].Role != "owner" {
		t.Fatalf("наследник: %+v %+v", tm, ms)
	}

	// Неактивность: напоминание за неделю, за день, затем просьба удалить; вход всё отменяет.
	st.s.Cfg.InactiveDays = 30
	t0 := st.now
	st.s.Store.PutPushToken("carol", "d-c", "fcm-token-carol-0123456789")
	st.s.Store.Seen("carol", st.now.Add(-24*24*time.Hour))
	st.sp.m["carol"] = SpaceInfo{Name: "carol", Owner: "carol", Phase: "Sleeping", Suspended: true}
	st.s.CheckInactive(context.Background())
	st.s.CheckInactive(context.Background())
	if n := strings.Count(strings.Join(push.sent, ","), "fcm-token-carol-0123456789|inactive"); n != 1 {
		t.Fatalf("напоминание за неделю — один раз: %v", push.sent)
	}
	st.now = st.now.Add(5*24*time.Hour + 12*time.Hour)
	st.s.CheckInactive(context.Background())
	if n := strings.Count(strings.Join(push.sent, ","), "carol-0123456789|inactive"); n != 2 || st.sp.m["carol"].InactiveDelete {
		t.Fatalf("напоминание за день: %v", push.sent)
	}
	st.now = st.now.Add(24 * time.Hour)
	st.s.CheckInactive(context.Background())
	if !st.sp.m["carol"].InactiveDelete {
		t.Fatal("через 30 дней не попросили удалить")
	}
	st.now = t0 // сертификат устройства стенда действует сутки — входим «сегодня»
	if w := st.as("carol", "GET", "/v1/me", ""); w.Code != 200 {
		t.Fatalf("вход: %d %s", w.Code, w.Body)
	}
	if st.sp.m["carol"].InactiveDelete {
		t.Fatal("вход не отменил удаление по неактивности")
	}
	if u, _ := st.s.Store.SeenUsers(); len(u) == 0 {
		t.Fatal("вход не отмечен")
	}
}
