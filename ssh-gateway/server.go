package sshgateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Config struct {
	MaxServers      int // серверов на пространство
	MaxCommandsHour int // команд агента в час (на пространство и агента)
}

// Gateway — HTTP-сервис шлюза.
type Gateway struct {
	Cfg    Config
	Auth   Auth
	Verify Verifier
	Store  Store
	Run    Runner
	Signer CertSigner
	Log    *log.Logger
	Now    func() time.Time
	// ControlPlane — кто передаёт подписанные действия с телефона (сам он их ни проверить, ни подделать не может).
	ControlPlane Caller
	// Journal — журнал команд (nil — не ведётся). Owners — владельцы общих пространств (nil — общие не обслуживаются).
	Journal Journal
	Owners  Owners

	mu      sync.Mutex
	busy    map[string]bool                       // "<пространство>/<сервер>": на сервере одна команда за раз
	count   map[string][]time.Time                // "<пространство>/<агент>": время недавних команд
	running map[string]map[int]context.CancelFunc // пространство → идущие команды (остановка их обрывает)
	runSeq  int
}

func (g *Gateway) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func ok(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func (g *Gateway) caller(r *http.Request) (Caller, error) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return Caller{}, ErrUnauthenticated
	}
	return g.Auth.Authenticate(r.Context(), strings.TrimPrefix(h, "Bearer "))
}

func body(w http.ResponseWriter, r *http.Request, v any) bool {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32<<10))
	if err != nil || json.Unmarshal(b, v) != nil {
		fail(w, http.StatusBadRequest, "json")
		return false
	}
	return true
}

// spaceOf — пространство вызывающего: под агента в deck-u-<ник> — это u-<ник>, в deck-t-<id> — t-<id>.
func spaceOf(c Caller) (string, bool) {
	if c.ServiceAccount != "space" {
		return "", false
	}
	if strings.HasPrefix(c.Namespace, "deck-u-") {
		return "u-" + strings.TrimPrefix(c.Namespace, "deck-u-"), true
	}
	if strings.HasPrefix(c.Namespace, "deck-t-") {
		return strings.TrimPrefix(c.Namespace, "deck-"), true
	}
	return "", false
}

// owns — владелец ли пространства user. Личное названо ником владельца; владельца общего шлюз узнаёт сам из
// объекта Space (Owners), а не со слов control-plane.
func (g *Gateway) owns(ctx context.Context, space, user string) bool {
	if user == "" {
		return false
	}
	if strings.HasPrefix(space, "u-") {
		return space == "u-"+user
	}
	if !strings.HasPrefix(space, "t-") || g.Owners == nil {
		return false
	}
	o, err := g.Owners.Owner(ctx, space)
	return err == nil && o == user
}

func str(a map[string]any, k string) string { s, _ := a[k].(string); return s }

// Principal — имя, под которым агент входит на сервер; владелец вписывает его в AuthorizedPrincipalsFile.
func Principal(space, agent string) string { return "deck-" + space + "-" + agent }

func (g *Gateway) verified(w http.ResponseWriter, r *http.Request, jws string, types ...string) (Verified, bool) {
	if jws == "" || len(jws) > 8192 {
		fail(w, http.StatusBadRequest, "нужно подписанное действие")
		return Verified{}, false
	}
	v, err := g.Verify.Verify(r.Context(), jws)
	if errors.Is(err, ErrRejected) {
		fail(w, http.StatusForbidden, err.Error())
		return v, false
	}
	if err != nil {
		g.Log.Printf("event=keyguard.unreachable err=%q", err.Error())
		fail(w, http.StatusBadGateway, "не удалось проверить подпись — повторите")
		return v, false
	}
	t := str(v.Action, "type")
	for _, want := range types {
		if t == want {
			if !g.owns(r.Context(), str(v.Action, "space"), v.User) {
				fail(w, http.StatusForbidden, "подписать это может только владелец пространства")
				return v, false
			}
			return v, true
		}
	}
	fail(w, http.StatusForbidden, "подписано действие другого типа")
	return v, false
}

func (g *Gateway) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	m.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if _, err := g.Signer.CAPublicKey(r.Context()); err != nil {
			http.Error(w, "OpenBao недоступен: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok"))
	})
	// ---- от control-plane: подписанные действия с телефона и то, что показать в приложении ----
	m.HandleFunc("/v1/servers", g.cp(g.addServer))
	m.HandleFunc("/v1/servers/remove", g.cp(g.removeServer))
	m.HandleFunc("/v1/rights", g.cp(g.setRights))
	m.HandleFunc("/v1/state", g.cp(g.state))
	m.HandleFunc("/v1/journal", g.cp(g.journal))
	m.HandleFunc("/v1/pause", g.cp(g.pause))
	// ---- от агента в пространстве ----
	m.HandleFunc("/v1/agent/servers", g.space(g.agentServers))
	m.HandleFunc("/v1/agent/check", g.space(g.check))
	m.HandleFunc("/v1/agent/exec", g.space(g.exec))
	return m
}

func (g *Gateway) cp(h func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c, err := g.caller(r); err != nil || c != g.ControlPlane {
			fail(w, http.StatusForbidden, "только control-plane")
			return
		}
		if r.Method != http.MethodPost {
			fail(w, http.StatusMethodNotAllowed, "POST")
			return
		}
		h(w, r)
	}
}

func (g *Gateway) space(h func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := g.caller(r)
		if err != nil {
			fail(w, http.StatusUnauthorized, "не опознан")
			return
		}
		sp, okSp := spaceOf(c)
		if !okSp || (strings.HasPrefix(sp, "t-") && g.Owners == nil) {
			fail(w, http.StatusForbidden, "серверы доступны только агенту пространства")
			return
		}
		if r.Method != http.MethodPost {
			fail(w, http.StatusMethodNotAllowed, "POST")
			return
		}
		h(w, r, sp)
	}
}

// addServer — действие server_add: адрес, пользователь и отпечаток ключа хоста, которые человек видел и подписал.
func (g *Gateway) addServer(w http.ResponseWriter, r *http.Request) {
	var q struct {
		JWS string `json:"jws"`
	}
	if !body(w, r, &q) {
		return
	}
	v, okV := g.verified(w, r, q.JWS, "server_add")
	if !okV {
		return
	}
	a, space := v.Action, str(v.Action, "space")
	port, _ := a["port"].(float64)
	s := Server{ID: str(a, "server"), Host: strings.ToLower(str(a, "host")), Port: int(port), User: str(a, "user"),
		HostKey: str(a, "host_key"), AddedBy: v.User, Device: v.DeviceID, Added: g.now().UTC()}
	if s.ID == "" || s.Host == "" || s.Port < 1 || s.Port > 65535 || s.User == "" || !strings.HasPrefix(s.HostKey, "SHA256:") {
		fail(w, http.StatusBadRequest, "неполное описание сервера")
		return
	}
	if s.User == "root" {
		fail(w, http.StatusBadRequest, "вход под root не принимается: заведите на сервере отдельного пользователя с нужными правами")
		return
	}
	if ip := net.ParseIP(s.Host); ip != nil && !publicIP(ip) {
		if sr, isSSH := g.Run.(*SSHRunner); !isSSH || !sr.AllowPrivate {
			fail(w, http.StatusBadRequest, "адрес сервера должен быть публичным")
			return
		}
	}
	servers, _, err := g.Store.List(space)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "временно недоступно")
		return
	}
	known := false
	for _, x := range servers {
		known = known || x.ID == s.ID
	}
	if !known && len(servers) >= g.Cfg.MaxServers {
		fail(w, http.StatusConflict, "слишком много серверов в пространстве")
		return
	}
	if err := g.Store.PutServer(space, s); err != nil {
		g.Log.Printf("event=state.failed op=server_add err=%q", err.Error())
		fail(w, http.StatusServiceUnavailable, "не удалось сохранить — повторите с новой подписью")
		return
	}
	g.Log.Printf("event=server.added space=%s server=%s host=%s port=%d user=%s by=%s device=%s", space, s.ID, s.Host, s.Port, s.User, v.User, v.DeviceID)
	ok(w, s)
}

// removeServer — убрать сервер. Это уменьшение прав, подписи не требует; control-plane называет пользователя,
// а шлюз проверяет, что тот — владелец пространства.
func (g *Gateway) removeServer(w http.ResponseWriter, r *http.Request) {
	var q struct{ Space, Server, User string }
	if !body(w, r, &q) {
		return
	}
	if !g.owns(r.Context(), q.Space, q.User) {
		fail(w, http.StatusForbidden, "убрать сервер может только владелец пространства")
		return
	}
	if err := g.Store.DeleteServer(q.Space, q.Server); errors.Is(err, ErrNotFound) {
		fail(w, http.StatusNotFound, "сервер не найден")
		return
	} else if err != nil {
		fail(w, http.StatusServiceUnavailable, "временно недоступно")
		return
	}
	g.Log.Printf("event=server.removed space=%s server=%s by=%s", q.Space, q.Server, q.User)
	ok(w, map[string]bool{"ok": true})
}

// setRights — действие agent_rights: к каким серверам допущен агент и можно ли ему читать без подтверждения.
func (g *Gateway) setRights(w http.ResponseWriter, r *http.Request) {
	var q struct {
		JWS string `json:"jws"`
	}
	if !body(w, r, &q) {
		return
	}
	v, okV := g.verified(w, r, q.JWS, "agent_rights")
	if !okV {
		return
	}
	a, space := v.Action, str(v.Action, "space")
	rt := Rights{Agent: str(a, "agent"), SignedBy: v.User, Device: v.DeviceID, Signed: g.now().UTC(), Servers: []string{}}
	rt.ReadWithoutConfirm, _ = a["read_without_confirm"].(bool)
	// Авто-write со сроком (поля необязательные — старое приложение их не шлёт; keyguard уже проверил, что при
	// write_without_confirm=true срок задан). Danger этим не покрывается — он всегда с подписью.
	if rt.WriteWithoutConfirm, _ = a["write_without_confirm"].(bool); rt.WriteWithoutConfirm {
		if u, okU := a["write_auto_until"].(float64); okU {
			rt.WriteAutoUntil = int64(u)
		}
	}
	list, _ := a["servers"].([]any)
	for _, x := range list {
		id, _ := x.(string)
		if _, err := g.Store.Server(space, id); err != nil {
			fail(w, http.StatusBadRequest, "в правах назван сервер, которого нет: "+id)
			return
		}
		rt.Servers = append(rt.Servers, id)
	}
	if rt.Agent == "" {
		fail(w, http.StatusBadRequest, "не назван агент")
		return
	}
	if err := g.Store.PutRights(space, rt); err != nil {
		g.Log.Printf("event=state.failed op=agent_rights err=%q", err.Error())
		fail(w, http.StatusServiceUnavailable, "не удалось сохранить — повторите с новой подписью")
		return
	}
	g.Log.Printf("event=rights.set space=%s agent=%s servers=%d read_without_confirm=%v write_without_confirm=%v write_auto_until=%d by=%s device=%s", space, rt.Agent, len(rt.Servers), rt.ReadWithoutConfirm, rt.WriteWithoutConfirm, rt.WriteAutoUntil, v.User, v.DeviceID)
	ok(w, rt)
}

// state — серверы и права пространства для экрана приложения, плюс то, что нужно для настройки сервера:
// публичный ключ CA и имена (principal), под которыми входят агенты.
func (g *Gateway) state(w http.ResponseWriter, r *http.Request) {
	var q struct{ Space, User string }
	if !body(w, r, &q) {
		return
	}
	if !g.owns(r.Context(), q.Space, q.User) {
		fail(w, http.StatusNotFound, "пространство не найдено")
		return
	}
	servers, rights, err := g.Store.List(q.Space)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "временно недоступно")
		return
	}
	ca, err := g.Signer.CAPublicKey(r.Context())
	if err != nil {
		g.Log.Printf("event=openbao.unreachable err=%q", err.Error())
		ca = ""
	}
	ok(w, map[string]any{"servers": servers, "rights": rights, "ca_public_key": ca, "principal_prefix": "deck-" + q.Space + "-",
		"paused": g.Store.Paused(q.Space)})
}

func (g *Gateway) agentServers(w http.ResponseWriter, r *http.Request, space string) {
	var q struct{ Agent string }
	if !body(w, r, &q) {
		return
	}
	rt, _ := g.Store.Rights(space, q.Agent)
	out := []map[string]any{}
	for _, id := range rt.Servers {
		if s, err := g.Store.Server(space, id); err == nil {
			out = append(out, map[string]any{"id": s.ID, "host": s.Host, "user": s.User})
		}
	}
	ok(w, map[string]any{"servers": out, "read_without_confirm": rt.ReadWithoutConfirm,
		"write_without_confirm": rt.WriteAuto(g.now()), "write_auto_until": rt.WriteAutoUntil})
}

type execReq struct {
	Agent   string `json:"agent"`
	Server  string `json:"server"`
	Command string `json:"command"`
	JWS     string `json:"jws"`
	// Preview — пробный прогон перед подтверждением изменения: только команда чтения, которой подпись не нужна.
	Preview bool `json:"preview"`
}

// plan — что нужно для команды: уровень и подпись какого вида. Ошибка — команда не может быть выполнена вовсе.
func (g *Gateway) plan(space string, q execReq) (Server, Level, string, int, string) {
	if g.Store.Paused(space) {
		return Server{}, "", "", http.StatusLocked, "владелец остановил агента на серверах — команды не выполняются, пока он не возобновит"
	}
	if q.Command == "" || len(q.Command) > 2000 || strings.ContainsRune(q.Command, 0) {
		return Server{}, "", "", http.StatusBadRequest, "команда пустая, длиннее 2000 знаков или содержит нулевой байт"
	}
	rt, err := g.Store.Rights(space, q.Agent)
	if err != nil || !rt.Allows(q.Server) {
		// Нет подписанной привязки «агент ↔ сервер»: для агента этого сервера не существует.
		return Server{}, "", "", http.StatusForbidden, "у агента нет подписанного владельцем доступа к этому серверу"
	}
	s, err := g.Store.Server(space, q.Server)
	if err != nil {
		return Server{}, "", "", http.StatusForbidden, "у агента нет подписанного владельцем доступа к этому серверу"
	}
	level := Classify(q.Command)
	writeAuto := rt.WriteAuto(g.now()) // владелец разрешил изменения без подписи (до срока); покрывает и чтение
	need := ""
	switch level {
	case Danger:
		need = "ssh_danger" // опасное — подпись всегда, авто-write его не покрывает
	case Write:
		if !writeAuto {
			need = "ssh_write"
		}
	default: // чтение
		if !rt.ReadWithoutConfirm && !writeAuto {
			need = "ssh_write"
		}
	}
	if q.Preview && need != "" {
		return Server{}, "", "", http.StatusPreconditionFailed, "пробный прогон — только команда чтения, которую можно выполнить без подтверждения"
	}
	return s, level, need, 0, ""
}

// check — агент спрашивает, что понадобится для команды, чтобы показать человеку правильную карточку.
func (g *Gateway) check(w http.ResponseWriter, r *http.Request, space string) {
	var q execReq
	if !body(w, r, &q) {
		return
	}
	s, level, need, code, why := g.plan(space, q)
	if code != 0 {
		fail(w, code, why)
		return
	}
	ok(w, map[string]any{"level": level, "need": need, "server": map[string]any{"id": s.ID, "host": s.Host, "user": s.User}})
}

func (g *Gateway) exec(w http.ResponseWriter, r *http.Request, space string) {
	var q execReq
	if !body(w, r, &q) {
		return
	}
	s, level, need, code, why := g.plan(space, q)
	if code != 0 {
		fail(w, code, why)
		return
	}
	signer := ""
	if need != "" {
		if q.JWS == "" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusPreconditionRequired)
			json.NewEncoder(w).Encode(map[string]any{"error": "нужна подпись человека на эту команду", "need": need, "level": level})
			return
		}
		v, okV := g.verified(w, r, q.JWS, need)
		if !okV {
			return
		}
		a := v.Action
		// Подписано ровно это: пространство, агент, сервер и команда — байт в байт.
		if str(a, "space") != space || str(a, "agent") != q.Agent || str(a, "server") != q.Server || str(a, "command") != q.Command {
			fail(w, http.StatusForbidden, "подписана другая команда, другой сервер или другой агент")
			return
		}
		if need == "ssh_danger" && str(a, "typed_server") != q.Server {
			fail(w, http.StatusForbidden, "имя сервера, введённое при подтверждении, не совпало")
			return
		}
		signer = v.User
	}
	if !g.take(space, q.Agent, q.Server, w) {
		return
	}
	defer g.release(space, q.Server)
	ctx, done := g.track(r.Context(), space)
	defer done()
	start := g.now()
	res, err := g.Run.Run(ctx, s, Principal(space, q.Agent), q.Command)
	entry := Entry{Time: start.UTC(), Space: space, Agent: q.Agent, Server: q.Server, Command: q.Command, Level: level,
		Signer: signer, Auto: level == Write && signer == "", Exit: res.ExitCode, Millis: res.Millis, Stdout: res.Stdout,
		Stderr: res.Stderr, TimedOut: res.TimedOut, Preview: q.Preview, Stopped: ctx.Err() != nil && r.Context().Err() == nil}
	if err != nil {
		entry.Error = err.Error()
	}
	if g.Journal != nil {
		if jerr := g.Journal.Append(entry); jerr != nil {
			g.Log.Printf("event=journal.failed space=%s err=%q", space, jerr.Error())
		}
	}
	if entry.Stopped {
		fail(w, http.StatusLocked, "владелец остановил агента на серверах — команда оборвана")
		return
	}
	if err != nil {
		g.Log.Printf("event=ssh.failed space=%s agent=%s server=%s level=%s signer=%q err=%q", space, q.Agent, q.Server, level, signer, err.Error())
		code := http.StatusBadGateway
		if errors.Is(err, ErrForbiddenAddress) {
			code = http.StatusForbidden
		}
		fail(w, code, "команда не выполнена: "+err.Error())
		return
	}
	g.Log.Printf("event=ssh.exec space=%s agent=%s server=%s level=%s signer=%q exit=%d ms=%d truncated=%v timed_out=%v cmd=%q",
		space, q.Agent, q.Server, level, signer, res.ExitCode, res.Millis, res.Truncated, res.TimedOut, q.Command)
	ok(w, map[string]any{"level": level, "signed_by": signer, "result": res})
}

// take занимает сервер (одна команда за раз) и учитывает команду в лимите агента. false — ответ уже отправлен.
func (g *Gateway) take(space, agent, server string, w http.ResponseWriter) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.busy == nil {
		g.busy, g.count = map[string]bool{}, map[string][]time.Time{}
	}
	k := space + "/" + agent
	now := g.now()
	recent := g.count[k][:0]
	for _, t := range g.count[k] {
		if now.Sub(t) < time.Hour {
			recent = append(recent, t)
		}
	}
	if len(recent) >= g.Cfg.MaxCommandsHour {
		g.count[k] = recent
		w.Header().Set("Retry-After", "600")
		fail(w, http.StatusTooManyRequests, "агент исчерпал лимит команд в час")
		return false
	}
	if g.busy[space+"/"+server] {
		g.count[k] = recent
		fail(w, http.StatusConflict, "на этом сервере уже выполняется команда — дождитесь её окончания")
		return false
	}
	g.busy[space+"/"+server] = true
	g.count[k] = append(recent, now)
	return true
}

func (g *Gateway) release(space, server string) {
	g.mu.Lock()
	delete(g.busy, space+"/"+server)
	g.mu.Unlock()
}

// track регистрирует идущую команду: остановка агента (pause) её обрывает.
func (g *Gateway) track(parent context.Context, space string) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	g.mu.Lock()
	if g.running == nil {
		g.running = map[string]map[int]context.CancelFunc{}
	}
	if g.running[space] == nil {
		g.running[space] = map[int]context.CancelFunc{}
	}
	g.runSeq++
	id := g.runSeq
	g.running[space][id] = cancel
	g.mu.Unlock()
	return ctx, func() {
		g.mu.Lock()
		delete(g.running[space], id)
		g.mu.Unlock()
		cancel()
	}
}

// pause — «Остановить агента на серверах»: новые команды не выполняются, идущие обрываются; paused=false — возобновить.
// Остановить — уменьшение прав, подписи не требует; control-plane называет пользователя, шлюз проверяет владельца.
func (g *Gateway) pause(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Space, User string
		Paused      bool
	}
	if !body(w, r, &q) {
		return
	}
	if !g.owns(r.Context(), q.Space, q.User) {
		fail(w, http.StatusForbidden, "остановить агента может только владелец пространства")
		return
	}
	if err := g.Store.SetPaused(q.Space, q.Paused); err != nil {
		fail(w, http.StatusServiceUnavailable, "временно недоступно")
		return
	}
	stopped := 0
	if q.Paused {
		g.mu.Lock()
		for _, cancel := range g.running[q.Space] {
			cancel()
			stopped++
		}
		g.mu.Unlock()
	}
	g.Log.Printf("event=agent.paused space=%s paused=%v stopped=%d by=%s", q.Space, q.Paused, stopped, q.User)
	ok(w, map[string]any{"paused": q.Paused, "stopped": stopped})
}

// journal — журнал команд пространства для экрана приложения (только владельцу).
func (g *Gateway) journal(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Space, User string
		Limit       int
	}
	if !body(w, r, &q) {
		return
	}
	if !g.owns(r.Context(), q.Space, q.User) {
		fail(w, http.StatusNotFound, "пространство не найдено")
		return
	}
	if g.Journal == nil {
		ok(w, map[string]any{"entries": []Entry{}})
		return
	}
	if q.Limit <= 0 || q.Limit > JournalMax {
		q.Limit = 100
	}
	es, err := g.Journal.List(q.Space, q.Limit)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "временно недоступно")
		return
	}
	ok(w, map[string]any{"entries": es, "keep_days": int(JournalKeep.Hours() / 24)})
}
