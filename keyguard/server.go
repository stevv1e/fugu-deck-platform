package keyguard

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	pathpkg "path"
	"strconv"
	"strings"
	"sync"
	"time"
)

const HPKEInfo = "fugu-deck key-intake v1"

// KeyPutAAD — AAD шифротекста ключа API. Приложение считает его так же (device_id — отпечаток ключа сессии).
func KeyPutAAD(deviceID, provider, nonce string) string {
	return "key_put|" + deviceID + "|" + provider + "|" + nonce
}

// Price — USD за 1M токенов. LongAbove > 0: запрос, вход которого длиннее LongAbove токенов, целиком по LongIn/LongOut
// (так Sakana считает Ultra: дороже при контексте больше 272K).
type Price struct {
	InPerM, OutPerM float64
	LongAbove       int64
	LongIn, LongOut float64
}

// rates — ставки для запроса с таким входом.
func (p Price) rates(inTok int64) (in, out float64) {
	if p.LongAbove > 0 && inTok > p.LongAbove {
		return p.LongIn, p.LongOut
	}
	return p.InPerM, p.OutPerM
}

type Provider struct {
	Name              string
	BaseURL           string // фиксирован: клиент не влияет на хост (нет SSRF)
	Path              string // единственный разрешённый путь
	ProbePath         string // проверка ключа при вводе
	ProbeAuthHeader   string // если проверка использует другой заголовок (Gemini: x-goog-api-key)
	AuthHeader        string // "x-api-key" или "authorization"
	Prices            map[string]Price
	MediaPerMinute    map[string]float64 // транскрибация: USD за минуту, ключ — ID модели
	ImagePerImage     map[string]float64 // генерация: резерв USD за изображение, ключ — ID модели
	HTTP              *http.Client       // отдельный egress провайдера; пусто — общий Upstream
	OAuthClientID     string             // Google Drive: обновление OAuth refresh token
	OAuthClientSecret string
	OAuthRedirect     string
	OAuthTokenURL     string // пусто — https://oauth2.googleapis.com/token; переопределение для тестов
	Style             string // "anthropic" | "openai"
	Kind              string // "" (модель) | "git"
	GitRules          []gitRule
}

// GitHub/GitLab для keyguard: белые списки вызовов — git.go.
func GitHubProvider(base string) *Provider {
	return &Provider{Name: "github", BaseURL: base, ProbePath: "/user", AuthHeader: "authorization", Kind: "git", GitRules: githubRules}
}
func GitLabProvider(base string) *Provider {
	return &Provider{Name: "gitlab", BaseURL: base, ProbePath: "/api/v4/user", AuthHeader: "private-token", Kind: "git", GitRules: gitlabRules}
}

type Server struct {
	Providers    map[string]*Provider
	Store        KeyStore
	Verifier     *Verifier
	Auth         Authenticator
	Ledger       *Ledger
	Grants       *Grants
	HPKEKey      *ecdh.PrivateKey // до старта; позже — SetHPKEKey
	hpkeMu       sync.RWMutex
	Upstream     *http.Client
	Log          *log.Logger
	Now          func() time.Time
	MaxBody      int64
	ControlPlane Caller // кто может вводить ключи и разрешения
	// Исполнители, которые проверяют подписи действий через keyguard (architecture.md 3.4): кто → какие типы.
	ActionVerifiers map[Caller][]string
	Enroll          *EnrollConfig // регистрация устройств (nil — выключена)
	Attest          *AttestPolicy // проверка аттестации при регистрации (nil — как Mode "off")
	Certs           CertIssuer    // выпуск сертификатов устройств (OpenBao pki-device)
	// MCP (mcp.go): какие адреса можно (по умолчанию — только интернет) и транспорт — для тестов.
	MCPAllowIP   func(net.IP) bool
	MCPTransport *http.Transport
	mcpOnce      sync.Once
	mcpClient    *http.Client
	driveMu      sync.Mutex
	driveTokens  map[string]driveAccess
}

func (s *Server) SetHPKEKey(k *ecdh.PrivateKey) { s.hpkeMu.Lock(); s.HPKEKey = k; s.hpkeMu.Unlock() }
func (s *Server) hpkeKey() *ecdh.PrivateKey {
	s.hpkeMu.RLock()
	defer s.hpkeMu.RUnlock()
	return s.HPKEKey
}

func (s *Server) Handler() http.Handler {
	if s.Verifier != nil && s.Verifier.OnUser == nil {
		s.Verifier.OnUser = s.markSeen
	}
	m := http.NewServeMux()
	m.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	m.HandleFunc("/v1/keys", s.handleKeyPut)
	m.HandleFunc("/v1/keys/delete", s.handleKeyDelete)
	m.HandleFunc("/v1/keys/status", s.handleKeyStatus)
	m.HandleFunc("/v1/keys/mine", s.handleKeysMine)
	m.HandleFunc("/v1/drive/oauth/exchange", s.handleDriveOAuthExchange)
	m.HandleFunc("/v1/limits", s.handleSpendLimit)
	m.HandleFunc("/v1/account/purge", s.handleAccountPurge)
	m.HandleFunc("/v1/account/cancel", s.handleAccountCancel)
	m.HandleFunc("/v1/grants", s.handleGrant)
	m.HandleFunc("/v1/grants/activate", s.handleActivate(true))
	m.HandleFunc("/v1/grants/deactivate", s.handleActivate(false))
	m.HandleFunc("/v1/grants/revoke", s.handleRevoke)
	m.HandleFunc("/v1/grants/member-left", s.handleMemberLeft)
	m.HandleFunc("/v1/actions/verify", s.handleVerifyAction)
	m.HandleFunc("/llm/", s.handleLLM)
	m.HandleFunc("/media/openai/audio/transcriptions", s.handleMediaTranscribe("openai"))
	m.HandleFunc("/media/google/transcribe", s.handleMediaTranscribe("google"))
	m.HandleFunc("/media/openai/image", s.handleImageGenerate("openai"))
	m.HandleFunc("/media/google/image", s.handleImageGenerate("google"))
	m.HandleFunc("/drive/", s.handleDrive)
	m.HandleFunc("/git/", s.handleGit)
	m.HandleFunc("/v1/mcp", s.handleMcpPut)
	m.HandleFunc("/v1/mcp/delete", s.handleMcpDelete)
	m.HandleFunc("/v1/mcp/list", s.handleMcpList)
	m.HandleFunc("/v1/mcp/mine", s.handleMcpMine)
	m.HandleFunc("/mcp/", s.handleMcp)
	m.HandleFunc("/v1/egress", s.handleEgressSet)
	m.HandleFunc("/v1/egress/list", s.handleEgressList)
	m.HandleFunc("/v1/egress/mine", s.handleEgressMine)
	m.HandleFunc("/egress/fetch", s.handleEgressFetch)
	m.HandleFunc("/v1/devices", s.handleEnroll)
	m.HandleFunc("/v1/devices/challenge", s.handleChallenge)
	m.HandleFunc("/v1/devices/confirm", s.handleDeviceAction("confirm"))
	m.HandleFunc("/v1/devices/revoke", s.handleDeviceAction("revoke"))
	m.HandleFunc("/v1/devices/status", s.handleDeviceStatus)
	m.HandleFunc("/v1/devices/list", s.handleDeviceList)
	m.HandleFunc("/v1/devices/revoked", s.handleDeviceRevoked)
	// Не-каноничный путь ("//", "/./", "/../") отклоняется сразу: ServeMux ответил бы редиректом на очищенный путь
	// (с Go 1.26 — 307, клиент повторяет POST), и «обходной» путь тихо становился бы рабочим.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != pathpkg.Clean(r.URL.Path) {
			fail(w, 404, "нет такого пути")
			return
		}
		m.ServeHTTP(w, r)
	})
}

// uid — идентификатор пользователя для журнала: журнал аудита не удаляется 90 дней (Object Lock, COMPLIANCE),
// поэтому в нём только хеши id (architecture.md, 9) — иначе удаление аккаунта не убирает его из журнала.
func uid(x string) string {
	h := sha256.Sum256([]byte("deck-log-uid|" + x))
	return hex.EncodeToString(h[:6])
}

// logNS — namespace личного пространства содержит id пользователя (deck-u-<id>): в журнал — с хешем.
func logNS(ns string) string {
	if u, ok := strings.CutPrefix(ns, "deck-u-"); ok {
		return "deck-u-#" + uid(u)
	}
	return ns
}

// stateFail — хранилище состояния недоступно: изменение не записано, запрос отклонён (persist.go).
func (s *Server) stateFail(w http.ResponseWriter, op string, err error) {
	s.Log.Printf("event=state.error op=%s err=%q", op, err.Error())
	fail(w, 503, "хранилище состояния недоступно, повторите позже")
}

type apiErr struct {
	code int
	msg  string
}

func fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// токен вызывающего: в x-api-key (SDK Anthropic) или Authorization: Bearer (SDK OpenAI)
func callerToken(r *http.Request) string {
	if t := r.Header.Get("x-api-key"); t != "" {
		return t
	}
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		return strings.TrimPrefix(a, "Bearer ")
	}
	return ""
}

func (s *Server) caller(r *http.Request) (Caller, error) {
	return s.Auth.Authenticate(r.Context(), callerToken(r))
}

func (s *Server) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.MaxBody))
	if err != nil {
		fail(w, http.StatusRequestEntityTooLarge, "тело слишком большое")
		return nil, false
	}
	return b, true
}

// ---------------- ввод ключа API ----------------

type keyPutReq struct {
	SignedAction
	Enc string `json:"enc"`
	Ct  string `json:"ct"`
}

func validKey(k string) bool {
	if len(k) < 8 || len(k) > 512 {
		return false
	}
	for _, c := range k {
		if c < 0x21 || c > 0x7e { // никаких пробелов, CR/LF (инъекция заголовков), не-ASCII
			return false
		}
	}
	return true
}

func mask(k string) string {
	if len(k) < 12 {
		return "…"
	}
	return k[:7] + "…" + k[len(k)-4:]
}

func (s *Server) handleKeyPut(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, 405, "POST")
		return
	}
	if c, err := s.caller(r); err != nil || c != s.ControlPlane {
		fail(w, 403, "только control-plane")
		return
	}
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	var req keyPutReq
	if err := json.Unmarshal(body, &req); err != nil {
		fail(w, 400, "json")
		return
	}
	a, dev, err := s.Verifier.Verify(req.SignedAction, "key_put")
	if err != nil {
		fail(w, 403, err.Error())
		return
	}
	user, prov := dev.User, s_(a, "provider") // чей ключ — определяет устройство, а не поле в запросе
	p := s.Providers[prov]
	if p == nil || !safeSeg(user) {
		fail(w, 400, "провайдер/пользователь")
		return
	}
	enc, e1 := base64.StdEncoding.DecodeString(req.Enc)
	ct, e2 := base64.StdEncoding.DecodeString(req.Ct)
	if e1 != nil || e2 != nil {
		fail(w, 400, "base64")
		return
	}
	// подпись покрывает хеш шифротекста: control-plane не может подменить шифротекст
	h := sha256.Sum256(append(append([]byte{}, enc...), ct...))
	if s_(a, "ct_sha256") != hex.EncodeToString(h[:]) {
		fail(w, 403, "шифротекст не соответствует подписи")
		return
	}
	// AAD привязывает шифротекст к устройству, провайдеру и этой подписи: чужой шифротекст в свой слот не встанет
	aad := []byte(KeyPutAAD(dev.ID, prov, s_(a, "nonce")))
	hk := s.hpkeKey()
	if hk == nil {
		fail(w, 503, "ключ HPKE ещё не загружен")
		return
	}
	pt, err := HPKEOpen(hk, enc, []byte(HPKEInfo), aad, ct)
	if err != nil {
		fail(w, 403, "не удалось расшифровать")
		return
	}
	key := string(pt)
	if !validKey(key) {
		fail(w, 422, "недопустимый формат ключа")
		return
	}
	// человек видел на экране «Ключ: …abcd» и подписал именно это — расшифрованный ключ обязан так заканчиваться
	if !strings.HasSuffix(key, s_(a, "key_hint")) || len(s_(a, "key_hint")) != 4 {
		fail(w, 403, "ключ не совпадает с показанным при подписи (key_hint)")
		return
	}
	if !s.probe(r.Context(), p, key) {
		fail(w, 422, "провайдер отклонил ключ")
		return
	}
	if err := s.Store.Put(r.Context(), user, prov, key); err != nil {
		s.Log.Printf("event=key.put user=%s provider=%s result=store_error", uid(user), prov)
		fail(w, 500, "хранилище")
		return
	}
	s.Log.Printf("event=key.put user=%s provider=%s result=ok", uid(user), prov)
	json.NewEncoder(w).Encode(map[string]string{"masked": mask(key)})
}

func (s *Server) probe(ctx context.Context, p *Provider, key string) bool {
	req, _ := http.NewRequestWithContext(ctx, "GET", p.BaseURL+p.ProbePath, nil)
	if p.Kind == "drive" {
		access, err := s.driveAccessToken(ctx, p, key)
		if err != nil {
			return false
		}
		key = access
	}
	if p.ProbeAuthHeader != "" {
		req.Header.Set(p.ProbeAuthHeader, key)
	} else {
		setAuth(req, p, key)
	}
	r, err := s.providerHTTP(p).Do(req)
	if err != nil {
		if s.Log != nil {
			s.Log.Printf("event=key.probe provider=%s result=network_error", p.Name)
		}
		return false
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	if s.Log != nil {
		s.Log.Printf("event=key.probe provider=%s status=%d", p.Name, r.StatusCode)
	}
	return r.StatusCode == 200
}

func setAuth(req *http.Request, p *Provider, key string) {
	switch p.AuthHeader {
	case "x-api-key":
		req.Header.Set("x-api-key", key)
	case "private-token":
		req.Header.Set("PRIVATE-TOKEN", key)
	default:
		req.Header.Set("Authorization", "Bearer "+key)
	}
}

// ---------------- разрешения спонсоров ----------------

func (s *Server) handleGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, 405, "POST")
		return
	}
	if c, err := s.caller(r); err != nil || c != s.ControlPlane {
		fail(w, 403, "только control-plane")
		return
	}
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	var sa SignedAction
	if json.Unmarshal(body, &sa) != nil {
		fail(w, 400, "json")
		return
	}
	a, dev, err := s.Verifier.Verify(sa, "grant")
	if err != nil {
		fail(w, 403, err.Error())
		return
	}
	now := s.Now()
	// ID привязан к устройству: nonce уникален только в пределах устройства, и "g-"+nonce позволял другому
	// пользователю с тем же nonce затереть чужое разрешение и его лимит.
	gh := sha256.Sum256([]byte(dev.ID + "|" + s_(a, "nonce")))
	until, e1 := dayEnd(a, "until")
	keyUntil, e2 := dayEnd(a, "key_until")
	limit, e3 := usd(a, "limit_usd")
	perMember, e4 := usd(a, "per_member_usd_day")
	if a["per_member_usd_day"] == nil { // null — без дневного лимита на участника
		perMember, e4 = 0, true
	}
	g := &Grant{
		ID: "g-" + hex.EncodeToString(gh[:12]), Space: s_(a, "space"), Chat: s_(a, "chat"), Proposal: s_(a, "proposal"),
		Provider: s_(a, "provider"), Model: s_(a, "model"), Sponsor: dev.User, // спонсор — тот, кто подписал
		LimitUSD: limit, PerMemberUSDDay: perMember,
		Until: until, KeyUntil: keyUntil, Members: strs(a, "members"),
	}
	switch {
	case !e1 || !e2 || !e3 || !e4:
		fail(w, 400, "until/key_until/limit_usd/per_member_usd_day")
		return
	case a["limit_tokens"] != nil:
		// человек подписал бы лимит, который никто не соблюдает: учёт идёт в долларах
		fail(w, 400, "limit_tokens пока не поддерживается: задайте null")
		return
	case limit <= 0 || perMember < 0:
		fail(w, 400, "лимит обязателен и положителен")
		return
	case g.KeyUntil.After(g.Until) || g.Until.After(now.AddDate(1, 0, 1)) || !g.Until.After(now):
		fail(w, 400, "сроки: key_until ≤ until ≤ 1 год, в будущем")
		return
	case !strings.HasPrefix(g.Space, "t-") || g.Chat == "" || g.Proposal == "" || len(g.Members) == 0:
		fail(w, 400, "space/chat/proposal/members")
		return
	}
	p := s.Providers[g.Provider]
	if p == nil {
		fail(w, 400, "провайдер")
		return
	}
	if p.Kind == "git" {
		if g.Model != "git" {
			fail(w, 400, "для Git модель — \"git\"")
			return
		}
	} else if _, ok := p.Prices[g.Model]; !ok {
		fail(w, 400, "модель без цены — расход не ограничить")
		return
	}
	if _, err := s.Store.Get(r.Context(), g.Sponsor, g.Provider); err != nil {
		fail(w, 409, "у спонсора нет ключа этого провайдера")
		return
	}
	// Лимит записывается ДО разрешения: разрешение без лимита было бы безлимитным. «Once» — чтобы запрос с уже
	// существующим id не переписал лимит действующего разрешения (сам он ниже получит 409).
	if err := s.Ledger.SetLimitOnce("grant:"+g.ID, g.LimitUSD); err != nil {
		s.stateFail(w, "grant.limit", err)
		return
	}
	if ok, err := s.Grants.Put(g); err != nil {
		s.stateFail(w, "grant.put", err)
		return
	} else if !ok {
		fail(w, 409, "разрешение с таким id уже есть")
		return
	}
	s.Log.Printf("event=grant.created grant=%s space=%s sponsor=%s limit_usd=%.2f", g.ID, g.Space, uid(g.Sponsor), limit)
	json.NewEncoder(w).Encode(map[string]string{"grant_id": g.ID})
}

// Пространство сообщает, что модель утверждена. Оно может активировать ТОЛЬКО разрешение своего пространства,
// подписанное спонсором, — расширить его нельзя.
//
// Снять активность (on=false) пространство тоже может: модель чата сменилась или предложение отклонено. Это
// уменьшение прав, подпись для него не нужна; включить обратно можно, пока спонсор не отозвал разрешение.
func (s *Server) handleActivate(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			fail(w, 405, "POST")
			return
		}
		c, err := s.caller(r)
		if err != nil || !strings.HasPrefix(c.Namespace, "deck-t-") {
			fail(w, 403, "только общее пространство")
			return
		}
		body, ok := s.readBody(w, r)
		if !ok {
			return
		}
		var req struct {
			GrantID string `json:"grant_id"`
		}
		json.Unmarshal(body, &req)
		space := strings.TrimPrefix(c.Namespace, "deck-")
		okUpd := false
		var got Grant
		if _, err := s.Grants.Update(req.GrantID, func(g *Grant) {
			if g.Space == space && !g.Revoked {
				g.Active, okUpd = on, true
				got = *g
			}
		}); err != nil {
			s.stateFail(w, "grant.activate", err)
			return
		}
		if !okUpd {
			fail(w, 403, "разрешение не найдено в этом пространстве")
			return
		}
		s.Log.Printf("event=grant.%s grant=%s space=%s", map[bool]string{true: "activated", false: "deactivated"}[on], req.GrantID, space)
		// Пространство получает условия, которые подписал спонсор: чат, модель, срок и лимит оно берёт отсюда, а не из
		// того, что прислало приложение, — так показанное участникам совпадает с тем, что действительно разрешено.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "grant": map[string]any{
			"id": got.ID, "chat": got.Chat, "proposal": got.Proposal, "provider": got.Provider, "model": got.Model, "sponsor": got.Sponsor,
			"limit_usd": got.LimitUSD, "per_member_usd_day": got.PerMemberUSDDay, "members": got.Members, "active": got.Active,
			"until": got.Until.UTC().Format(time.RFC3339), "key_until": got.KeyUntil.UTC().Format(time.RFC3339)}})
	}
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, 405, "POST")
		return
	}
	if c, err := s.caller(r); err != nil || c != s.ControlPlane {
		fail(w, 403, "только control-plane")
		return
	}
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	var sa SignedAction
	json.Unmarshal(body, &sa)
	a, dev, err := s.Verifier.Verify(sa, "grant_revoke")
	if err != nil {
		fail(w, 403, err.Error())
		return
	}
	// приложение знает чат и предложение, а не внутренний id: отзываются разрешения ЭТОГО спонсора по ним
	n, err := s.Grants.Revoke(s_(a, "space"), s_(a, "chat"), s_(a, "proposal"), dev.User)
	if err != nil { // в памяти отзыв уже действует, но перезапуск его не переживёт — клиент должен повторить
		s.stateFail(w, "grant.revoke", err)
		return
	}
	if n == 0 {
		fail(w, 403, "отозвать может только спонсор")
		return
	}
	s.Log.Printf("event=grant.revoked space=%s sponsor=%s count=%d", s_(a, "space"), uid(dev.User), n)
	w.Write([]byte(`{"ok":true}`))
}

// ---------------- проверка подписей для исполнителей ----------------

// handleVerifyAction — space-operator и ssh-gateway сами ключей устройств не знают: подпись действия, которое
// они собираются выполнить (удаление пространства, команда на сервере), проверяет keyguard и возвращает
// разобранное действие и подписавшего. Каждый исполнитель может проверять только свои типы; nonce расходуется,
// так что одну подпись нельзя предъявить дважды. Взломанный control-plane не может ни подделать, ни повторить её.
func (s *Server) handleVerifyAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, 405, "POST")
		return
	}
	c, err := s.caller(r)
	types := s.ActionVerifiers[c]
	// Личное пространство проверяет разрешения своего владельца на действия агента — и только их.
	personal := err == nil && strings.HasPrefix(c.Namespace, "deck-u-") && c.ServiceAccount == "space"
	// Общее пространство — тоже, но кто из участников вправе разрешать, решает оно само: keyguard подтверждает
	// только, что подпись настоящая и сделана для этого пространства, и называет подписавшего.
	team := err == nil && strings.HasPrefix(c.Namespace, "deck-t-") && c.ServiceAccount == "space"
	if personal || team {
		types = []string{"tool_approve"}
	}
	if err != nil || len(types) == 0 {
		fail(w, 403, "только исполнители действий")
		return
	}
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	var sa SignedAction
	if json.Unmarshal(body, &sa) != nil {
		fail(w, 400, "json")
		return
	}
	a, dev, err := s.Verifier.Verify(sa, types...)
	if err != nil {
		fail(w, 403, err.Error())
		return
	}
	t := s_(a, "type")
	if t == "account_delete" && s_(a, "user") != dev.User {
		fail(w, 403, ErrWrongOwner.Error()) // удалить можно только свой аккаунт
		return
	}
	if (t == "invite_create" || t == "pair_approve") && s_(a, "user") != dev.User && !(s.Enroll != nil && contains(s.Enroll.Admins, dev.User)) {
		fail(w, 403, "действие для другого пользователя может подтвердить только администратор")
		return
	}
	if personal {
		// Подписал владелец ЭТОГО пространства и именно для него: разрешение, подписанное для другого пространства
		// или другим пользователем, здесь не действует — даже если подпись настоящая.
		owner := strings.TrimPrefix(c.Namespace, "deck-u-")
		if dev.User != owner || s_(a, "space") != "u-"+owner {
			fail(w, 403, "разрешение подписано не владельцем этого пространства или не для него")
			return
		}
	}
	if team && s_(a, "space") != strings.TrimPrefix(c.Namespace, "deck-") {
		fail(w, 403, "разрешение подписано не для этого пространства")
		return
	}
	if t == "account_delete" {
		// Запоминаем, когда подпись проверена: стереть данные аккаунта (/v1/account/purge) можно не раньше чем
		// через сутки после неё — взломанный оператор без подписи владельца чужой аккаунт не сотрёт.
		if err := s.Ledger.SetLimit(acctDelKey(dev.User), float64(s.Now().Unix())); err != nil {
			s.stateFail(w, "account.mark", err)
			return
		}
	}
	s.Log.Printf("event=action.verified type=%s by=%s/%s user=%s", s_(a, "type"), c.Namespace, c.ServiceAccount, uid(dev.User))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"action": json.RawMessage(Canonical(a)), "user": dev.User, "device_id": dev.ID})
}

// ---------------- прокси к провайдерам ----------------

// Anthropic-Beta наружу НЕ передаётся: бета-функции меняют тарификацию (длинный контекст, серверные инструменты),
// а цена в таблице одна. Нужна конкретная бета — добавляйте её здесь вместе с ценой.
var forwardHeaders = []string{"Content-Type", "Accept", "Anthropic-Version"}

// Поля тела, которые пропускаются провайдеру. Всё остальное отклоняется: неизвестное поле может включить
// то, что учёт не видит (другой тариф, несколько вариантов ответа, фоновые задачи).
var allowedFields = map[string]map[string]bool{
	"anthropic": set("model", "max_tokens", "messages", "system", "stream", "temperature", "top_p", "top_k",
		"stop_sequences", "metadata", "tools", "tool_choice", "thinking"),
	"openai": set("model", "max_tokens", "messages", "stream", "stream_options", "temperature", "top_p", "stop",
		"tools", "tool_choice", "response_format", "seed"),
}

// Инструменты, которые исполняет САМО пространство (расход — только токены). Серверные инструменты провайдера
// (web_search, web_fetch, code_execution, …) тарифицируются отдельно от токенов, и лимит их не видит.
var clientToolTypes = []string{"custom", "function", "bash_", "text_editor_", "computer_", "memory_"}

func set(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func checkBody(style string, req map[string]any) error {
	for k := range req {
		if !allowedFields[style][k] {
			return fmt.Errorf("поле %q не разрешено", k)
		}
	}
	tools, _ := req["tools"].([]any)
	for _, t := range tools {
		tm, _ := t.(map[string]any)
		typ, has := tm["type"].(string)
		if tm == nil || (has && !clientTool(typ)) {
			return fmt.Errorf("инструмент %q не разрешён: серверные инструменты тарифицируются мимо лимита", typ)
		}
	}
	return nil
}

func clientTool(typ string) bool {
	for _, p := range clientToolTypes {
		if typ == p || (strings.HasSuffix(p, "_") && strings.HasPrefix(typ, p)) {
			return true
		}
	}
	return false
}

func (s *Server) handleLLM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, 405, "POST")
		return
	}
	// /llm/<provider><path> — точное совпадение; закодированные символы и обход пути запрещены
	rest := strings.TrimPrefix(r.URL.Path, "/llm/")
	name, path, _ := strings.Cut(rest, "/")
	p := s.Providers[name]
	if p == nil || p.Kind == "git" || r.URL.RawPath != "" || "/"+path != p.Path || r.URL.RawQuery != "" {
		fail(w, 404, "нет такого пути")
		return
	}
	c, err := s.caller(r)
	if err != nil {
		fail(w, 401, "не опознан")
		return
	}
	// отказы пишем в журнал: пространство показывает их только в приложении, разобрать потом было нечем
	deny := func(code int, msg string) {
		s.Log.Printf("event=llm.denied ns=%s provider=%s status=%d reason=%q", logNS(c.Namespace), name, code, msg)
		fail(w, code, msg)
	}
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	req, err := ParseStrict(body, true)
	if err != nil {
		deny(400, "тело: "+err.Error())
		return
	}
	if err := checkBody(p.Style, req); err != nil {
		deny(400, "тело: "+err.Error())
		return
	}
	model := s_(req, "model")
	price, ok := p.Prices[model]
	if !ok {
		deny(400, "модель не разрешена")
		return
	}
	maxTok, err := strconv.ParseInt(num(req, "max_tokens"), 10, 64)
	if err != nil || maxTok <= 0 || maxTok > 128000 {
		deny(400, "max_tokens обязателен (1..128000): без него расход не ограничить")
		return
	}
	stream, _ := req["stream"].(bool)

	// кто платит
	var user string
	var budgets []string
	now := s.Now()
	switch {
	case strings.HasPrefix(c.Namespace, "deck-u-"):
		user = strings.TrimPrefix(c.Namespace, "deck-u-")
		budgets = []string{"user:" + user, monthKey(user, now)}
		if err := s.applyMonthCap(user, now); err != nil {
			s.stateFail(w, "ledger.limit", err)
			return
		}
	case strings.HasPrefix(c.Namespace, "deck-t-"):
		space := strings.TrimPrefix(c.Namespace, "deck-")
		chat, member := r.Header.Get("X-Deck-Chat"), r.Header.Get("X-Deck-Member")
		g, ok := s.Grants.Find(space, chat, name, model, now)
		if !ok {
			deny(403, "нет действующего разрешения спонсора на этот чат, провайдера и модель")
			return
		}
		if !contains(g.Members, member) {
			deny(403, "участник не допущен спонсором")
			return
		}
		user = g.Sponsor
		budgets = []string{"grant:" + g.ID}
		if g.PerMemberUSDDay > 0 {
			k := "grant:" + g.ID + ":" + member + ":" + now.UTC().Format("2006-01-02")
			if err := s.Ledger.SetLimitOnce(k, g.PerMemberUSDDay); err != nil {
				s.stateFail(w, "ledger.limit", err)
				return
			}
			budgets = append(budgets, k)
		}
	default:
		deny(403, "только пространства")
		return
	}
	key, err := s.Store.Get(r.Context(), user, name)
	if err != nil {
		deny(409, "ключ не задан")
		return
	}
	// резерв: вход оценён сверху (1 токен ≥ 1 байт тела), выход — max_tokens
	// вход оцениваем длиной тела в байтах: байтов не меньше, чем токенов, — резерв и тариф только с запасом
	rin, rout := price.rates(int64(len(body)))
	reserve := (float64(len(body))*rin + float64(maxTok)*rout) / 1e6
	res, err := s.Ledger.Reserve(budgets, reserve)
	if errors.Is(err, ErrState) { // расход не записать — запрос к провайдеру не уходит
		s.stateFail(w, "ledger.reserve", err)
		return
	}
	if err != nil {
		deny(402, err.Error())
		return
	}
	if stream && p.Style == "openai" { // без usage в потоке расход не посчитать
		so, _ := req["stream_options"].(map[string]any)
		if so == nil {
			so = map[string]any{}
		}
		so["include_usage"] = true
		req["stream_options"] = so
	}
	out := Canonical(req) // провайдер получает ровно то, что проверено

	up, _ := http.NewRequestWithContext(r.Context(), "POST", p.BaseURL+p.Path, bytes.NewReader(out))
	for _, h := range forwardHeaders {
		if v := r.Header.Get(h); v != "" {
			up.Header.Set(h, v)
		}
	}
	setAuth(up, p, key)
	resp, err := s.providerHTTP(p).Do(up)
	if err != nil {
		res.Settle(0, true)
		fail(w, 502, "провайдер недоступен")
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)

	var in, outTok int64
	var known, complete bool
	scrub := func(b []byte) []byte { return bytes.ReplaceAll(b, []byte(key), []byte("[redacted]")) }
	if stream {
		fl, _ := w.(http.Flusher)
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for sc.Scan() {
			line := sc.Bytes()
			if bytes.HasPrefix(line, []byte("data: ")) {
				if i, o, ok := usageOf(p.Style, line[6:]); ok {
					in, outTok, known = max(in, i), max(outTok, o), true
				}
				if streamEnd(p.Style, line[6:]) {
					complete = true
				}
			}
			w.Write(scrub(line))
			w.Write([]byte("\n"))
			if fl != nil {
				fl.Flush()
			}
		}
	} else {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		if i, o, ok := usageOf(p.Style, b); ok {
			in, outTok, known = i, o, true
		}
		w.Write(scrub(b))
	}
	pin, pout := price.rates(int64(in))
	cost := (float64(in)*pin + float64(outTok)*pout) / 1e6
	// Поток оборван (клиент закрыл соединение, сеть, слишком длинная строка): итоговый usage приходит в ПОСЛЕДНИХ
	// событиях, а провайдер берёт деньги за всё, что успел сгенерировать. Списываем не меньше резерва — иначе
	// пространство обрывало бы каждый поток перед концом и получало выход бесплатно, мимо лимита спонсора.
	if stream && resp.StatusCode < 400 && !complete {
		cost, known = max(cost, reserve), true
	}
	// Без usage: ошибка провайдера (4xx/5xx, не поток) — генерации не было, списывается 0;
	// успешный ответ без usage — весь резерв (fail-safe). В журнал — фактически списанное.
	if !known && resp.StatusCode >= 400 {
		cost, known = 0, true
	}
	charged := res.Settle(cost, known)
	s.Log.Printf("event=llm ns=%s payer=%s provider=%s model=%s status=%d in=%d out=%d usage_known=%t charged_usd=%.6f",
		logNS(c.Namespace), uid(user), name, model, resp.StatusCode, in, outTok, known, charged)
}

// usageOf — токены из ответа (целиком или одного события SSE).
type usageT struct {
	InputTokens      int64 `json:"input_tokens"`
	OutputTokens     int64 `json:"output_tokens"`
	CacheCreation    int64 `json:"cache_creation_input_tokens"`
	CacheRead        int64 `json:"cache_read_input_tokens"`
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
}

// billedInput — вход в «обычных» входных токенах. У Anthropic input_tokens НЕ включает кэш: запись в кэш стоит
// до ×2 входной цены (TTL 1 ч; 5 мин — ×1,25), чтение — ×0,1. Берём верхнюю ставку записи: учёт не занижается.
func (u *usageT) billedInput() int64 {
	return u.InputTokens + 2*u.CacheCreation + (u.CacheRead+9)/10
}

// streamEnd — событие, после которого поток считается дошедшим до конца (итоговый usage уже был).
func streamEnd(style string, b []byte) bool {
	if style == "openai" {
		return bytes.Equal(bytes.TrimSpace(b), []byte("[DONE]"))
	}
	var v struct {
		Type string `json:"type"`
	}
	return json.Unmarshal(b, &v) == nil && v.Type == "message_stop"
}

// usageOf — токены из ответа (целиком или одного события SSE).
// anthropic: message_start.message.usage (вход) и message_delta.usage (выход, накопительно); openai: usage.
func usageOf(style string, b []byte) (in, out int64, ok bool) {
	var v struct {
		Usage   *usageT `json:"usage"`
		Message *struct {
			Usage *usageT `json:"message_usage_unused"`
			U     *usageT `json:"usage"`
		} `json:"message"`
	}
	if json.Unmarshal(b, &v) != nil {
		return 0, 0, false
	}
	if v.Message != nil && v.Message.U != nil {
		return v.Message.U.billedInput(), v.Message.U.OutputTokens, true
	}
	if v.Usage != nil {
		if style == "openai" {
			return v.Usage.PromptTokens, v.Usage.CompletionTokens, v.Usage.PromptTokens+v.Usage.CompletionTokens > 0
		}
		return v.Usage.billedInput(), v.Usage.OutputTokens, true
	}
	return 0, 0, false
}

func s_(m map[string]any, k string) string { return s(m, k) }

var _ = errors.New
var _ = fmt.Sprintf

// handleMemberLeft — control-plane: участника исключили из общего пространства. Его разрешения отзываются (ключом
// спонсора, которого в пространстве больше нет, не платим), из чужих разрешений он убирается. Подписи не нужно:
// это только сужение прав, а состав пространства ведёт control-plane по подписанным role_change.
func (s *Server) handleMemberLeft(w http.ResponseWriter, r *http.Request) {
	body, ok := s.cpBody(w, r)
	if !ok {
		return
	}
	var req struct {
		Space  string `json:"space"`
		Member string `json:"member"`
	}
	if json.Unmarshal(body, &req) != nil || !strings.HasPrefix(req.Space, "t-") || !safeSeg(req.Space) || !safeSeg(req.Member) {
		fail(w, 400, "space, member")
		return
	}
	rv, tr, err := s.Grants.MemberLeft(req.Space, req.Member)
	if err != nil {
		s.stateFail(w, "grant.member_left", err)
		return
	}
	s.Log.Printf("event=grant.member_left space=%s member=%s revoked=%d trimmed=%d", req.Space, uid(req.Member), rv, tr)
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "revoked": rv, "trimmed": tr})
}
