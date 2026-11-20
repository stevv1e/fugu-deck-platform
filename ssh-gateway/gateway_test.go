package sshgateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// ---------- стенд: настоящий SSH-сервер, свой CA, подменные keyguard и вызывающие ----------

// localCA подписывает сертификаты так же, как роль agent в OpenBao: пользовательский, на 10 минут, с одним principal.
type localCA struct {
	signer ssh.Signer
	ttl    time.Duration
	issued []string
	fail   bool
}

func newCA(t *testing.T) *localCA {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return &localCA{signer: s, ttl: 10 * time.Minute}
}

func (c *localCA) Sign(_ context.Context, publicKey, principal string) (string, error) {
	if c.fail {
		return "", errors.New("OpenBao недоступен")
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		return "", err
	}
	cert := &ssh.Certificate{Key: pk, CertType: ssh.UserCert, KeyId: principal, ValidPrincipals: []string{principal},
		ValidAfter: uint64(time.Now().Add(-time.Minute).Unix()), ValidBefore: uint64(time.Now().Add(c.ttl).Unix()),
		Permissions: ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}}}
	if err := cert.SignCert(rand.Reader, c.signer); err != nil {
		return "", err
	}
	c.issued = append(c.issued, principal)
	return string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(cert))), nil
}

func (c *localCA) CAPublicKey(context.Context) (string, error) {
	return string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(c.signer.PublicKey()))), nil
}

// sshServer — сервер пользователя: доверяет только CA, пускает только названные principal, «выполняет» команды из таблицы.
type sshServer struct {
	ln         net.Listener
	hostKey    ssh.Signer
	principals map[string]bool
	mu         sync.Mutex
	ran        []string
	run        func(cmd string, stdout, stderr io.Writer) int
}

func newSSHServer(t *testing.T, ca *localCA, principals ...string) *sshServer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	hk, _ := ssh.NewSignerFromKey(priv)
	s := &sshServer{hostKey: hk, principals: map[string]bool{}}
	for _, p := range principals {
		s.principals[p] = true
	}
	s.run = func(cmd string, stdout, _ io.Writer) int { fmt.Fprintf(stdout, "вывод: %s\n", cmd); return 0 }
	checker := &ssh.CertChecker{IsUserAuthority: func(k ssh.PublicKey) bool { return bytes.Equal(k.Marshal(), ca.signer.PublicKey().Marshal()) }}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		cert, ok := key.(*ssh.Certificate)
		if !ok {
			return nil, errors.New("принимаются только сертификаты")
		}
		if !checker.IsUserAuthority(cert.SignatureKey) {
			return nil, errors.New("сертификат подписан не доверенным CA")
		}
		// как AuthorizedPrincipalsFile в sshd: сертификат должен быть выписан на один из разрешённых principal
		// (имя пользователя на сервере — deck-agent — в сертификате не значится); срок и подпись проверяет CheckCert
		for _, p := range cert.ValidPrincipals {
			if s.principals[p] {
				if err := checker.CheckCert(p, cert); err != nil {
					return nil, err
				}
				return &ssh.Permissions{}, nil
			}
		}
		return nil, errors.New("principal не разрешён на этом сервере")
	}}
	cfg.AddHostKey(hk)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.ln = ln
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c, cfg)
		}
	}()
	return s
}

func (s *sshServer) serve(c net.Conn, cfg *ssh.ServerConfig) {
	defer c.Close()
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "только session")
			continue
		}
		ch, rq, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			defer ch.Close()
			for r := range rq {
				if r.Type != "exec" {
					r.Reply(false, nil) // ни оболочки, ни терминала, ни проброса
					continue
				}
				var p struct{ Cmd string }
				ssh.Unmarshal(r.Payload, &p)
				r.Reply(true, nil)
				s.mu.Lock()
				s.ran = append(s.ran, p.Cmd)
				run := s.run
				s.mu.Unlock()
				code := run(p.Cmd, ch, ch.Stderr())
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
				return
			}
		}()
	}
}

func (s *sshServer) setRun(f func(cmd string, stdout, stderr io.Writer) int) {
	s.mu.Lock()
	s.run = f
	s.mu.Unlock()
}

func (s *sshServer) addr() (string, int) {
	h, p, _ := net.SplitHostPort(s.ln.Addr().String())
	n, _ := strconv.Atoi(p)
	return h, n
}

func (s *sshServer) commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.ran...)
}

// fakeKG — keyguard: подпись — это JSON действия; каждая принимается один раз, «подписавший» — поле by.
type fakeKG struct {
	seen map[string]bool
	down bool
}

func (f *fakeKG) Verify(_ context.Context, jws string) (Verified, error) {
	if f.down {
		return Verified{}, errors.New("connection refused")
	}
	if f.seen[jws] {
		return Verified{}, fmt.Errorf("%w: повтор", ErrRejected)
	}
	var v struct {
		By     string         `json:"by"`
		Action map[string]any `json:"action"`
	}
	if json.Unmarshal([]byte(jws), &v) != nil || v.By == "" {
		return Verified{}, fmt.Errorf("%w: подпись", ErrRejected)
	}
	f.seen[jws] = true
	return Verified{Action: v.Action, User: v.By, DeviceID: "d-" + v.By}, nil
}

var nonce int

func signed(by string, action map[string]any) string {
	nonce++
	action["nonce"] = nonce
	b, _ := json.Marshal(map[string]any{"by": by, "action": action})
	return string(b)
}

type stand struct {
	t   *testing.T
	gw  *Gateway
	ts  *httptest.Server
	ca  *localCA
	kg  *fakeKG
	srv *sshServer
	now time.Time
}

func newStand(t *testing.T) *stand {
	t.Helper()
	st := &stand{t: t, ca: newCA(t), kg: &fakeKG{seen: map[string]bool{}}, now: time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)}
	st.srv = newSSHServer(t, st.ca, "deck-u-anna-fugu")
	store, _ := OpenFileStore("")
	st.gw = &Gateway{Cfg: Config{MaxServers: 3, MaxCommandsHour: 50},
		Auth: StaticAuth{"tok-cp": {"deck-system", "control-plane"}, "tok-anna": {"deck-u-anna", "space"}, "tok-bob": {"deck-u-bob", "space"},
			"tok-team": {"deck-t-shop000001", "space"}, "tok-other": {"deck-u-anna", "default"}},
		Verify: st.kg, Store: store, Signer: st.ca, Log: log.New(io.Discard, "", 0), Now: func() time.Time { return st.now },
		ControlPlane: Caller{"deck-system", "control-plane"},
		Run:          &SSHRunner{Signer: st.ca, Timeout: 3 * time.Second, MaxOutput: 4096, AllowPrivate: true}}
	st.ts = httptest.NewServer(st.gw.Handler())
	t.Cleanup(st.ts.Close)
	return st
}

func (st *stand) post(tok, path string, body any) (int, map[string]any) {
	st.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", st.ts.URL+path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+tok)
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		st.t.Fatal(err)
	}
	defer r.Body.Close()
	var out map[string]any
	json.NewDecoder(r.Body).Decode(&out)
	return r.StatusCode, out
}

func (st *stand) serverAdd(by, space, id string, over map[string]any) string {
	h, p := st.srv.addr()
	a := map[string]any{"type": "server_add", "space": space, "server": id, "host": h, "port": p, "user": "deck-agent",
		"host_key": ssh.FingerprintSHA256(st.srv.hostKey.PublicKey())}
	for k, v := range over {
		a[k] = v
	}
	return signed(by, a)
}

func (st *stand) setup() {
	st.t.Helper()
	if c, b := st.post("tok-cp", "/v1/servers", map[string]string{"jws": st.serverAdd("anna", "u-anna", "prod-1", nil)}); c != 200 {
		st.t.Fatalf("добавление сервера: %d %v", c, b)
	}
	if c, b := st.post("tok-cp", "/v1/rights", map[string]string{"jws": signed("anna", map[string]any{"type": "agent_rights", "space": "u-anna",
		"agent": "fugu", "servers": []string{"prod-1"}, "read_without_confirm": true, "limit_usd_month": nil})}); c != 200 {
		st.t.Fatalf("права агента: %d %v", c, b)
	}
}

func cmd(agent, server, command string) map[string]string {
	return map[string]string{"agent": agent, "server": server, "command": command}
}

// ---------- тесты ----------

func TestServersAndRightsNeedOwnerSignature(t *testing.T) {
	st := newStand(t)
	jws := func(by string, over map[string]any) map[string]string {
		return map[string]string{"jws": st.serverAdd(by, "u-anna", "prod-1", over)}
	}
	deny := map[string]func() (int, map[string]any){
		"не от control-plane":  func() (int, map[string]any) { return st.post("tok-anna", "/v1/servers", jws("anna", nil)) },
		"подписал не владелец": func() (int, map[string]any) { return st.post("tok-cp", "/v1/servers", jws("bob", nil)) },
		"вход под root": func() (int, map[string]any) {
			return st.post("tok-cp", "/v1/servers", jws("anna", map[string]any{"user": "root"}))
		},
		"действие другого типа": func() (int, map[string]any) {
			return st.post("tok-cp", "/v1/servers", jws("anna", map[string]any{"type": "agent_rights"}))
		},
		"общее пространство": func() (int, map[string]any) {
			return st.post("tok-cp", "/v1/servers", jws("anna", map[string]any{"space": "t-shop000001"}))
		},
		"не подписано": func() (int, map[string]any) {
			return st.post("tok-cp", "/v1/servers", map[string]string{"jws": "мусор"})
		},
		"права на несуществующий сервер": func() (int, map[string]any) {
			return st.post("tok-cp", "/v1/rights", map[string]string{"jws": signed("anna", map[string]any{"type": "agent_rights", "space": "u-anna", "agent": "fugu", "servers": []string{"nope"}})})
		},
	}
	for name, f := range deny {
		if c, b := f(); c == 200 {
			t.Errorf("%s: принято (%v)", name, b)
		}
	}
	if s, _, _ := st.gw.Store.List("u-anna"); len(s) != 0 {
		t.Fatalf("после отказов что-то сохранено: %v", s)
	}
	st.kg.down = true
	if c, _ := st.post("tok-cp", "/v1/servers", jws("anna", nil)); c != 502 {
		t.Fatalf("keyguard недоступен: %d", c)
	}
	st.kg.down = false
	one := jws("anna", nil)
	if c, b := st.post("tok-cp", "/v1/servers", one); c != 200 || b["added_by"] != "anna" || b["user"] != "deck-agent" {
		t.Fatalf("добавление: %d %v", c, b)
	}
	if c, _ := st.post("tok-cp", "/v1/servers", one); c != 403 {
		t.Fatalf("та же подпись второй раз: %d", c)
	}
	// лимит серверов на пространство
	for _, id := range []string{"s2", "s3"} {
		st.post("tok-cp", "/v1/servers", map[string]string{"jws": st.serverAdd("anna", "u-anna", id, nil)})
	}
	if c, _ := st.post("tok-cp", "/v1/servers", map[string]string{"jws": st.serverAdd("anna", "u-anna", "s4", nil)}); c != 409 {
		t.Fatalf("сверх лимита: %d", c)
	}
	// состояние для приложения — только владельцу; в нём ключ CA и имя, под которым входит агент
	c, b := st.post("tok-cp", "/v1/state", map[string]string{"space": "u-anna", "user": "anna"})
	if c != 200 || len(b["servers"].([]any)) != 3 || !strings.HasPrefix(b["ca_public_key"].(string), "ssh-ed25519 ") || b["principal_prefix"] != "deck-u-anna-" {
		t.Fatalf("состояние: %d %v", c, b)
	}
	if c, _ := st.post("tok-cp", "/v1/state", map[string]string{"space": "u-anna", "user": "bob"}); c != 404 {
		t.Fatalf("чужое состояние: %d", c)
	}
	// сервер убран — право агента на него исчезает вместе с ним
	st.post("tok-cp", "/v1/rights", map[string]string{"jws": signed("anna", map[string]any{"type": "agent_rights", "space": "u-anna", "agent": "fugu", "servers": []string{"prod-1", "s2"}})})
	if c, _ := st.post("tok-cp", "/v1/servers/remove", map[string]string{"space": "u-anna", "server": "prod-1", "user": "bob"}); c != 403 {
		t.Fatalf("чужой убирает сервер: %d", c)
	}
	if c, _ := st.post("tok-cp", "/v1/servers/remove", map[string]string{"space": "u-anna", "server": "prod-1", "user": "anna"}); c != 200 {
		t.Fatalf("удаление: %d", c)
	}
	if r, _ := st.gw.Store.Rights("u-anna", "fugu"); r.Allows("prod-1") || !r.Allows("s2") {
		t.Fatalf("права после удаления сервера: %+v", r)
	}
}

func TestExecOverRealSSH(t *testing.T) {
	st := newStand(t)
	st.setup()
	// чтение без подтверждения (владелец разрешил подписью): настоящий SSH, сертификат на 10 минут, ключ хоста сверен
	c, b := st.post("tok-anna", "/v1/agent/exec", cmd("fugu", "prod-1", "journalctl -u app -n 5"))
	res, _ := b["result"].(map[string]any)
	if c != 200 || b["level"] != "read" || b["signed_by"] != "" || res["stdout"] != "вывод: journalctl -u app -n 5\n" || res["exit_code"] != float64(0) {
		t.Fatalf("чтение: %d %v", c, b)
	}
	if len(st.ca.issued) != 1 || st.ca.issued[0] != "deck-u-anna-fugu" {
		t.Fatalf("сертификат: %v", st.ca.issued)
	}
	// ненулевой код выхода — результат команды, а не сбой
	st.srv.setRun(func(c string, _, stderr io.Writer) int {
		io.WriteString(stderr, "нет такого файла")
		return 2
	})
	c, b = st.post("tok-anna", "/v1/agent/exec", cmd("fugu", "prod-1", "cat /nope"))
	if res = b["result"].(map[string]any); c != 200 || res["exit_code"] != float64(2) || res["stderr"] != "нет такого файла" {
		t.Fatalf("код выхода: %d %v", c, b)
	}
	// длинный вывод обрезается
	st.srv.setRun(func(c string, stdout, _ io.Writer) int { stdout.Write(bytes.Repeat([]byte("x"), 10000)); return 0 })
	_, b = st.post("tok-anna", "/v1/agent/exec", cmd("fugu", "prod-1", "cat big"))
	if res = b["result"].(map[string]any); len(res["stdout"].(string)) != 4096 || res["truncated"] != true {
		t.Fatalf("обрезка вывода: %d %v", len(res["stdout"].(string)), res["truncated"])
	}
	// зависшая команда обрывается по таймауту
	st.srv.setRun(func(c string, _, _ io.Writer) int { time.Sleep(6 * time.Second); return 0 })
	t0 := time.Now()
	_, b = st.post("tok-anna", "/v1/agent/exec", cmd("fugu", "prod-1", "tail -f /var/log/app"))
	if res = b["result"].(map[string]any); res["timed_out"] != true || time.Since(t0) > 5*time.Second {
		t.Fatalf("таймаут: %v за %s", res, time.Since(t0))
	}
	st.srv.setRun(func(c string, stdout, _ io.Writer) int { fmt.Fprint(stdout, "ok"); return 0 })

	n := len(st.srv.commands())
	deny := map[string]func() (int, map[string]any){
		"агент чужого пространства": func() (int, map[string]any) { return st.post("tok-bob", "/v1/agent/exec", cmd("fugu", "prod-1", "ls")) },
		"общее пространство": func() (int, map[string]any) {
			return st.post("tok-team", "/v1/agent/exec", cmd("fugu", "prod-1", "ls"))
		},
		"не агент (другой ServiceAccount)": func() (int, map[string]any) {
			return st.post("tok-other", "/v1/agent/exec", cmd("fugu", "prod-1", "ls"))
		},
		"control-plane выполняет команды": func() (int, map[string]any) { return st.post("tok-cp", "/v1/agent/exec", cmd("fugu", "prod-1", "ls")) },
		"агент без подписанных прав": func() (int, map[string]any) {
			return st.post("tok-anna", "/v1/agent/exec", cmd("other", "prod-1", "ls"))
		},
		"сервер не из подписанного списка": func() (int, map[string]any) {
			return st.post("tok-anna", "/v1/agent/exec", cmd("fugu", "prod-2", "ls"))
		},
		"пустая команда": func() (int, map[string]any) { return st.post("tok-anna", "/v1/agent/exec", cmd("fugu", "prod-1", "")) },
		"нулевой байт": func() (int, map[string]any) {
			return st.post("tok-anna", "/v1/agent/exec", cmd("fugu", "prod-1", "ls\x00rm"))
		},
	}
	for name, f := range deny {
		if c, b := f(); c == 200 {
			t.Errorf("%s: выполнено (%v)", name, b)
		}
	}
	if len(st.srv.commands()) != n {
		t.Fatalf("отклонённое дошло до сервера: %v", st.srv.commands()[n:])
	}
}

func TestWriteAndDangerNeedSignatureOnExactCommand(t *testing.T) {
	st := newStand(t)
	st.setup()
	st.srv.setRun(func(c string, stdout, _ io.Writer) int { fmt.Fprint(stdout, "готово"); return 0 })
	restart := "sudo systemctl restart app"
	sign := func(by, typ, command string, over map[string]any) string {
		a := map[string]any{"type": typ, "space": "u-anna", "agent": "fugu", "server": "prod-1", "command": command}
		for k, v := range over {
			a[k] = v
		}
		return signed(by, a)
	}
	ex := func(command, jws string) (int, map[string]any) {
		q := cmd("fugu", "prod-1", command)
		q["jws"] = jws
		return st.post("tok-anna", "/v1/agent/exec", q)
	}
	// агент сначала спрашивает, что нужно, — чтобы человеку показали правильную карточку
	for command, want := range map[string][2]string{"df -h": {"read", ""}, restart: {"write", "ssh_write"}, "rm -rf /var/lib/app": {"danger", "ssh_danger"}} {
		if c, b := st.post("tok-anna", "/v1/agent/check", cmd("fugu", "prod-1", command)); c != 200 || b["level"] != want[0] || b["need"] != want[1] {
			t.Errorf("check %q: %d %v", command, c, b)
		}
	}
	n := len(st.srv.commands())
	c, b := ex(restart, "")
	if c != http.StatusPreconditionRequired || b["need"] != "ssh_write" {
		t.Fatalf("запись без подписи: %d %v", c, b)
	}
	deny := map[string]string{
		"подписана другая команда":           sign("anna", "ssh_write", "sudo systemctl restart nginx", nil),
		"подписан другой сервер":             sign("anna", "ssh_write", restart, map[string]any{"server": "prod-2"}),
		"подписан другой агент":              sign("anna", "ssh_write", restart, map[string]any{"agent": "other"}),
		"подписано для другого пространства": sign("bob", "ssh_write", restart, map[string]any{"space": "u-bob"}),
		"подписал не владелец":               sign("bob", "ssh_write", restart, nil),
		"подпись другого типа":               sign("anna", "agent_rights", restart, nil),
		"команда с лишним пробелом":          sign("anna", "ssh_write", restart+" ", nil),
	}
	for name, jws := range deny {
		if c, b := ex(restart, jws); c == 200 {
			t.Errorf("%s: выполнено (%v)", name, b)
		}
	}
	if len(st.srv.commands()) != n {
		t.Fatalf("команда без верной подписи дошла до сервера: %v", st.srv.commands()[n:])
	}
	good := sign("anna", "ssh_write", restart, nil)
	if c, b := ex(restart, good); c != 200 || b["signed_by"] != "anna" || b["level"] != "write" {
		t.Fatalf("запись с подписью: %d %v", c, b)
	}
	if c, _ := ex(restart, good); c != 403 {
		t.Fatalf("та же подпись второй раз: %d", c)
	}
	// опасная команда: подписи «записи» мало, нужно действие ssh_danger с введённым именем сервера
	rm := "rm -rf /var/lib/app/cache"
	if c, _ := ex(rm, sign("anna", "ssh_write", rm, nil)); c == 200 {
		t.Fatal("опасная команда выполнена по подписи обычной записи")
	}
	if c, _ := ex(rm, sign("anna", "ssh_danger", rm, map[string]any{"typed_server": "prod-2"})); c == 200 {
		t.Fatal("опасная команда выполнена с чужим именем сервера")
	}
	if c, b := ex(rm, sign("anna", "ssh_danger", rm, map[string]any{"typed_server": "prod-1"})); c != 200 || b["level"] != "danger" {
		t.Fatalf("опасная команда с подписью: %d %v", c, b)
	}
	if got := st.srv.commands()[n:]; len(got) != 2 || got[0] != restart || got[1] != rm {
		t.Fatalf("на сервере выполнено: %v", got)
	}
	// владелец не разрешал читать без подтверждения — тогда и чтение требует подписи
	st.post("tok-cp", "/v1/rights", map[string]string{"jws": signed("anna", map[string]any{"type": "agent_rights", "space": "u-anna", "agent": "fugu", "servers": []string{"prod-1"}, "read_without_confirm": false})})
	if c, b := ex("df -h", ""); c != http.StatusPreconditionRequired || b["need"] != "ssh_write" {
		t.Fatalf("чтение без разрешения читать: %d %v", c, b)
	}
	if c, _ := ex("df -h", sign("anna", "ssh_write", "df -h", nil)); c != 200 {
		t.Fatalf("чтение с подписью: %d", c)
	}
}

func TestWriteAutoWithoutConfirm(t *testing.T) {
	st := newStand(t)
	j, _ := OpenFileJournal("", func() time.Time { return st.now })
	st.gw.Journal = j
	st.setup()
	st.srv.setRun(func(c string, stdout, _ io.Writer) int { fmt.Fprint(stdout, "готово"); return 0 })
	restart := "sudo systemctl restart app"
	rm := "rm -rf /var/lib/app/cache"
	ex := func(command string) (int, map[string]any) {
		return st.post("tok-anna", "/v1/agent/exec", cmd("fugu", "prod-1", command))
	}
	chk := func(command string) (int, map[string]any) {
		return st.post("tok-anna", "/v1/agent/check", cmd("fugu", "prod-1", command))
	}
	// Владелец разрешил изменения без подписи на час вперёд.
	until := st.now.Add(time.Hour).Unix()
	if c, b := st.post("tok-cp", "/v1/rights", map[string]string{"jws": signed("anna", map[string]any{"type": "agent_rights",
		"space": "u-anna", "agent": "fugu", "servers": []string{"prod-1"}, "read_without_confirm": true,
		"write_without_confirm": true, "write_auto_until": until})}); c != 200 {
		t.Fatalf("права с авто-write: %d %v", c, b)
	}
	// Запись больше не требует подписи; опасное — по-прежнему требует.
	if c, b := chk(restart); c != 200 || b["need"] != "" || b["level"] != "write" {
		t.Fatalf("check записи при авто-write: %d %v", c, b)
	}
	if c, b := chk(rm); c != 200 || b["need"] != "ssh_danger" {
		t.Fatalf("check опасного при авто-write: %d %v", c, b)
	}
	n := len(st.srv.commands())
	if c, b := ex(restart); c != 200 || b["signed_by"] != "" || b["level"] != "write" {
		t.Fatalf("авто-write без подписи: %d %v", c, b)
	}
	if c, _ := ex(rm); c != http.StatusPreconditionRequired {
		t.Fatalf("опасное прошло без подписи при авто-write: %d", c)
	}
	if got := st.srv.commands()[n:]; len(got) != 1 || got[0] != restart {
		t.Fatalf("на сервере выполнено: %v", got)
	}
	// В журнале запись помечена auto и без подписанта.
	_, b := st.post("tok-cp", "/v1/journal", map[string]any{"space": "u-anna", "user": "anna"})
	es, _ := b["entries"].([]any)
	if len(es) != 1 || es[0].(map[string]any)["auto"] != true || es[0].(map[string]any)["signer"] != nil {
		t.Fatalf("журнал авто-write: %v", b)
	}
	// Срок истёк — запись снова требует подписи.
	st.now = st.now.Add(2 * time.Hour)
	if c, b := ex(restart); c != http.StatusPreconditionRequired || b["need"] != "ssh_write" {
		t.Fatalf("после истечения срока: %d %v", c, b)
	}
}

func TestServerIdentityAndPrincipal(t *testing.T) {
	st := newStand(t)
	st.setup()
	// на сервере подменили ключ хоста (или это другой сервер по тому же адресу): шлюз не входит и ничего не выполняет
	other := newSSHServer(t, st.ca, "deck-u-anna-fugu")
	h, p := other.addr()
	st.post("tok-cp", "/v1/servers", map[string]string{"jws": st.serverAdd("anna", "u-anna", "prod-1", map[string]any{"host": h, "port": p})})
	c, b := st.post("tok-anna", "/v1/agent/exec", cmd("fugu", "prod-1", "ls"))
	if c == 200 || !strings.Contains(fmt.Sprint(b["error"]), "ключ хоста") || len(other.commands()) != 0 {
		t.Fatalf("чужой ключ хоста: %d %v", c, b)
	}
	// сервер, который не вписал principal агента, сертификат не принимает
	strict := newSSHServer(t, st.ca, "deck-u-anna-reviewer")
	h, p = strict.addr()
	st.post("tok-cp", "/v1/servers", map[string]string{"jws": st.serverAdd("anna", "u-anna", "prod-1",
		map[string]any{"host": h, "port": p, "host_key": ssh.FingerprintSHA256(strict.hostKey.PublicKey())})})
	if c, b := st.post("tok-anna", "/v1/agent/exec", cmd("fugu", "prod-1", "ls")); c == 200 || len(strict.commands()) != 0 {
		t.Fatalf("сервер без principal агента принял вход: %d %v", c, b)
	}
	// OpenBao недоступен — сертификата нет, команды нет
	st.setup()
	st.ca.fail = true
	if c, _ := st.post("tok-anna", "/v1/agent/exec", cmd("fugu", "prod-1", "ls")); c != 502 {
		t.Fatalf("без OpenBao: %d", c)
	}
}

func TestLimits(t *testing.T) {
	st := newStand(t)
	st.setup()
	st.gw.Cfg.MaxCommandsHour = 3
	hold := make(chan struct{})
	st.srv.setRun(func(c string, stdout, _ io.Writer) int {
		if c == "tail slow" {
			<-hold
		}
		return 0
	})
	done := make(chan int)
	go func() { c, _ := st.post("tok-anna", "/v1/agent/exec", cmd("fugu", "prod-1", "tail slow")); done <- c }()
	for i := 0; i < 100 && len(st.srv.commands()) == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if c, _ := st.post("tok-anna", "/v1/agent/exec", cmd("fugu", "prod-1", "ls")); c != 409 {
		t.Fatalf("вторая команда на занятом сервере: %d", c)
	}
	close(hold)
	if c := <-done; c != 200 {
		t.Fatalf("первая команда: %d", c)
	}
	st.post("tok-anna", "/v1/agent/exec", cmd("fugu", "prod-1", "ls"))
	st.post("tok-anna", "/v1/agent/exec", cmd("fugu", "prod-1", "ls"))
	if c, _ := st.post("tok-anna", "/v1/agent/exec", cmd("fugu", "prod-1", "ls")); c != 429 {
		t.Fatalf("сверх лимита в час: %d", c)
	}
	st.now = st.now.Add(61 * time.Minute)
	if c, _ := st.post("tok-anna", "/v1/agent/exec", cmd("fugu", "prod-1", "ls")); c != 200 {
		t.Fatalf("через час: %d", c)
	}
}

func TestOnlyPublicAddresses(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8": true, "13.238.197.69": true, "2606:4700:4700::1111": true,
		"127.0.0.1": false, "10.42.0.5": false, "10.43.0.1": false, "172.16.3.4": false, "192.168.1.1": false, "169.254.169.254": false,
		"100.64.0.1": false, "0.0.0.0": false, "::1": false, "fe80::1": false, "fd00::1": false, "224.0.0.1": false, "198.18.0.1": false,
	} {
		if got := publicIP(net.ParseIP(ip)); got != want {
			t.Errorf("%s: %v, ожидалось %v", ip, got, want)
		}
	}
	// боевой режим: частный адрес не принимается ни буквой, ни именем, которое на него указывает
	r := &SSHRunner{Timeout: time.Second, Resolve: func(_ context.Context, h string) ([]net.IP, error) {
		return map[string][]net.IP{"inside.example": {net.ParseIP("10.43.0.1")}, "mixed.example": {net.ParseIP("8.8.8.8"), net.ParseIP("10.0.0.1")}}[h], nil
	}}
	for _, host := range []string{"10.42.0.5", "169.254.169.254", "inside.example", "mixed.example"} {
		if _, err := r.Run(context.Background(), Server{Host: host, Port: 22, User: "x"}, "p", "ls"); !errors.Is(err, ErrForbiddenAddress) {
			t.Errorf("%s: %v", host, err)
		}
	}
	st := newStand(t)
	st.gw.Run.(*SSHRunner).AllowPrivate = false
	if c, _ := st.post("tok-cp", "/v1/servers", map[string]string{"jws": st.serverAdd("anna", "u-anna", "prod-1", nil)}); c != 400 {
		t.Fatalf("сервер с адресом 127.0.0.1 принят: %d", c)
	}
}

func TestFileStoreSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	a, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	a.PutServer("u-anna", Server{ID: "prod-1", Host: "h", Port: 22, User: "deck-agent", HostKey: "SHA256:x"})
	a.PutRights("u-anna", Rights{Agent: "fugu", Servers: []string{"prod-1"}, ReadWithoutConfirm: true})
	b, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err1 := b.Server("u-anna", "prod-1")
	r, err2 := b.Rights("u-anna", "fugu")
	if err1 != nil || err2 != nil || s.User != "deck-agent" || !r.Allows("prod-1") || !r.ReadWithoutConfirm {
		t.Fatalf("после перезапуска: %+v %+v %v %v", s, r, err1, err2)
	}
	if _, err := b.Server("u-bob", "prod-1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("сервер виден из чужого пространства")
	}
}

func testPub(t *testing.T) string {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(k)))
}

func certExtensions(t *testing.T, line string) []string {
	t.Helper()
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for e := range k.(*ssh.Certificate).Permissions.Extensions {
		out = append(out, e)
	}
	return out
}

func TestJournalPausePreviewTeam(t *testing.T) {
	st := newStand(t)
	j, _ := OpenFileJournal("", func() time.Time { return st.now })
	st.gw.Journal = j
	st.gw.Owners = StaticOwners{"t-shop000001": "bob"}
	st.setup()

	if c, b := st.post("tok-anna", "/v1/agent/exec", cmd("fugu", "prod-1", "cat /etc/привет")); c != 200 {
		t.Fatalf("чтение: %d %v", c, b)
	}
	c, b := st.post("tok-cp", "/v1/journal", map[string]any{"space": "u-anna", "user": "anna"})
	es, _ := b["entries"].([]any)
	if c != 200 || len(es) != 1 || es[0].(map[string]any)["command"] != "cat /etc/привет" || !strings.Contains(es[0].(map[string]any)["stdout"].(string), "привет") {
		t.Fatalf("журнал: %d %v", c, b)
	}
	if c, _ := st.post("tok-cp", "/v1/journal", map[string]any{"space": "u-anna", "user": "bob"}); c != 404 {
		t.Fatalf("чужой журнал: %d", c)
	}

	// Пробный прогон — только чтение без подтверждения.
	p := cmd("fugu", "prod-1", "touch /tmp/x")
	p["preview"] = "true"
	var pv map[string]any
	json.Unmarshal(must(json.Marshal(map[string]any{"agent": "fugu", "server": "prod-1", "command": "touch /tmp/x", "preview": true})), &pv)
	if c, _ := st.post("tok-anna", "/v1/agent/exec", pv); c != 412 {
		t.Fatalf("пробный прогон изменением: %d", c)
	}

	// Остановка: новые команды не выполняются, журнал хранит прежние; возобновление.
	if c, _ := st.post("tok-cp", "/v1/pause", map[string]any{"space": "u-anna", "user": "bob", "paused": true}); c != 403 {
		t.Fatalf("остановил не владелец: %d", c)
	}
	if c, b := st.post("tok-cp", "/v1/pause", map[string]any{"space": "u-anna", "user": "anna", "paused": true}); c != 200 {
		t.Fatalf("остановка: %d %v", c, b)
	}
	if c, _ := st.post("tok-anna", "/v1/agent/exec", cmd("fugu", "prod-1", "uptime")); c != 423 {
		t.Fatalf("команда при остановленном агенте: %d", c)
	}
	if _, b := st.post("tok-cp", "/v1/state", map[string]any{"space": "u-anna", "user": "anna"}); b["paused"] != true {
		t.Fatalf("состояние не показывает остановку: %v", b)
	}
	st.post("tok-cp", "/v1/pause", map[string]any{"space": "u-anna", "user": "anna", "paused": false})
	if c, _ := st.post("tok-anna", "/v1/agent/exec", cmd("fugu", "prod-1", "uptime")); c != 200 {
		t.Fatalf("после возобновления: %d", c)
	}

	// Общее пространство: серверы и права подписывает его владелец (Боб), не участник.
	if c, _ := st.post("tok-cp", "/v1/servers", map[string]string{"jws": st.serverAdd("anna", "t-shop000001", "shop-1", nil)}); c != 403 {
		t.Fatalf("сервер общего пространства добавил не владелец: %d", c)
	}
	if c, b := st.post("tok-cp", "/v1/servers", map[string]string{"jws": st.serverAdd("bob", "t-shop000001", "shop-1", nil)}); c != 200 {
		t.Fatalf("сервер общего пространства от владельца: %d %v", c, b)
	}
	st.post("tok-cp", "/v1/rights", map[string]string{"jws": signed("bob", map[string]any{"type": "agent_rights", "space": "t-shop000001",
		"agent": "fugu", "servers": []string{"shop-1"}, "read_without_confirm": false, "limit_usd_month": nil})})
	if c, b := st.post("tok-team", "/v1/agent/check", cmd("fugu", "shop-1", "uptime")); c != 200 || b["need"] != "ssh_write" {
		t.Fatalf("агент общего пространства: %d %v", c, b)
	}
	if c, _ := st.post("tok-team", "/v1/agent/check", cmd("fugu", "prod-1", "uptime")); c != 403 {
		t.Fatalf("агент общего пространства видит сервер личного: %d", c)
	}
}

func must(b []byte, _ error) []byte { return b }
