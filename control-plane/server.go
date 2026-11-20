package controlplane

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config — адреса кластера, которые control-plane отдаёт в приглашении и по которым проверяет переходы.
type Config struct {
	APIURL       string        // https://api.<домен>
	JoinURL      string        // https://join.<домен>
	Issuer       string        // https://id.<домен>/realms/deck
	HPKEPub      string        // публичный ключ keyguard (base64url, 65 байт): на него телефон шифрует ключи API
	CookieDomain string        // общий родительский домен api/id/join: cookie приглашения должна дойти до id.<домен>
	InviteTTL    time.Duration // срок приглашения (24 ч)
	GateTTL      time.Duration // срок cookie приглашения для страниц Keycloak (30 мин)
	SleepAfter   time.Duration // усыпить пространство после стольких минут без обращений (0 — не усыплять)
	// Свежая сборка приложения: версия (1.2.3) и где её взять. Приложение сравнивает со своей и предлагает обновиться.
	AppLatest string
	AppURL    string
	// Публичный OAuth Client ID для кнопки Google Drive; secret остаётся только в keyguard.
	DriveClientID string
	// InactiveDays — удалить аккаунт после стольких дней без входа (0 — не удалять); напоминания за 7 и за 1 день.
	InactiveDays int
}

// Keyguard — вызовы keyguard от имени control-plane (проецируемый токен ServiceAccount, audience=keyguard).
type Keyguard interface {
	Post(ctx context.Context, path string, body []byte) (status int, resp []byte, err error)
}

// Directory — учётные записи в Keycloak. control-plane только создаёт пользователя под приглашение.
type Directory interface {
	EnsureUser(ctx context.Context, nick string) error
	// DeleteUser удаляет учётную запись (удаление аккаунта); её уже нет — не ошибка.
	DeleteUser(ctx context.Context, nick string) error
	// RemovePasskeys удаляет passkey пользователя (телефон потерян: новый регистрирует свой по приглашению).
	RemovePasskeys(ctx context.Context, nick string) (int, error)
}

type Server struct {
	Cfg   Config
	Store Store
	KG    Keyguard
	Users Directory
	Keys  *KeySet // ключи подписи токенов Keycloak — для входа на api.<домен>
	// SSH — ssh-gateway (тот же способ вызова, что у keyguard, но свой токен: audience=ssh-gateway). nil — выключено.
	SSH    Keyguard
	Spaces SpaceAPI
	// SpaceURL — адрес агента в namespace пространства (в тестах подменяется).
	SpaceURL func(namespace string) *url.URL
	// AgentHealth — идёт ли у агента работа и когда его ближайшее задание по расписанию (по умолчанию —
	// GET /api/health агента; в тестах подменяется).
	AgentHealth func(ctx context.Context, namespace string) (AgentHealth, error)
	// RevokedList — ID отозванных устройств (keyguard); nil — не проверять (стенды). См. revoked.go.
	RevokedList func(ctx context.Context) ([]string, error)
	// Push — отправка уведомлений (FCM). nil — уведомления выключены (нет ключа Firebase).
	Push    PushSender
	Now     func() time.Time
	Log     *log.Logger
	MaxBody int64

	dpopSeen replay
	revoked  revokedList
	spaceKey spaceSigner
	act      activity
	rosters  rosterState
	seen     seenThrottle
	outbox   struct {
		mu  sync.Mutex
		cur map[string]outboxCursor // пространство → докуда прочитана его очередь уведомлений
	}
}

const (
	inviteCookie = "deck_invite"
	inviteHeader = "X-Deck-Invite"
	nickHeader   = "X-Deck-Invite-Nick"
)

var (
	inviteRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,256}$`)
	// Ник — имя пользователя в Keycloak и сегмент путей в keyguard и OpenBao: только строчные латинские буквы,
	// цифры и дефис, чтобы не было двух визуально одинаковых ников и подстановок в пути.
	nickRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$`)
)

var ErrBadNick = errors.New("ник: 3–32 символа, строчные латинские буквы, цифры и дефис")

func ValidNick(nick string) bool { return nickRe.MatchString(nick) && !strings.Contains(nick, "--") }

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) maxBody() int64 {
	if s.MaxBody > 0 {
		return s.MaxBody
	}
	return 256 << 10 // регистрация несёт цепочку аттестации: несколько сертификатов
}

func fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// ---------- приглашения ----------

// NewInvite выпускает приглашение для ника и заводит пользователя в Keycloak. Возвращает ссылку для QR.
func (s *Server) NewInvite(ctx context.Context, nick, inviter string) (link string, expires time.Time, err error) {
	if !ValidNick(nick) {
		return "", time.Time{}, ErrBadNick
	}
	if err := s.Users.EnsureUser(ctx, nick); err != nil {
		return "", time.Time{}, err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	expires = s.now().Add(s.Cfg.InviteTTL)
	if err := s.Store.PutInvite(hashToken(token), Invite{Nick: nick, Inviter: inviter, Expires: expires}); err != nil {
		return "", time.Time{}, err
	}
	q := url.Values{"api": {s.Cfg.APIURL}, "iss": {s.Cfg.Issuer}, "join": {s.Cfg.JoinURL}, "hpke": {s.Cfg.HPKEPub}, "invite": {token}}
	s.Log.Printf("event=invite.created nick=%s inviter=%s expires=%s", nick, inviter, expires.UTC().Format(time.RFC3339))
	return "fugudeck://join?" + q.Encode(), expires, nil
}

// lookup — приглашение по токену; истёкшее не возвращается.
func (s *Server) lookup(token string) (Invite, string, error) {
	if !inviteRe.MatchString(token) {
		return Invite{}, "", ErrNotFound
	}
	h := hashToken(token)
	inv, err := s.Store.Invite(h)
	if err != nil {
		return Invite{}, "", err
	}
	if !s.now().Before(inv.Expires) {
		return Invite{}, "", ErrNotFound
	}
	return inv, h, nil
}

// Cookie приглашения: "<ник>.<истекает unix>.<HMAC>". Самого токена в ней нет — браузеру он больше не нужен.
func (s *Server) signGate(nick string, exp time.Time) (string, error) {
	key, err := s.Store.CookieKey()
	if err != nil {
		return "", err
	}
	body := nick + "." + strconv.FormatInt(exp.Unix(), 10)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil)), nil
}

func (s *Server) verifyGate(v string) (string, bool) {
	p := strings.Split(v, ".")
	if len(p) != 3 || !nickRe.MatchString(p[0]) {
		return "", false
	}
	exp, err := strconv.ParseInt(p[1], 10, 64)
	if err != nil || s.now().Unix() >= exp {
		return "", false
	}
	want, err := s.signGate(p[0], time.Unix(exp, 0))
	if err != nil || !hmac.Equal([]byte(want), []byte(v)) {
		return "", false
	}
	return p[0], true
}

// gateNick — кого пропускает проверка приглашения: токен в заголовке (приложение) или cookie (браузер).
func (s *Server) gateNick(r *http.Request) (string, bool) {
	if t := r.Header.Get(inviteHeader); t != "" {
		if inv, _, err := s.lookup(t); err == nil {
			return inv.Nick, true
		}
		return "", false
	}
	if c, err := r.Cookie(inviteCookie); err == nil {
		return s.verifyGate(c.Value)
	}
	return "", false
}

// ---------- обработчики ----------

// AuthHandler — порт 8081, только для Traefik (forwardAuth «приглашение»).
func (s *Server) AuthHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/auth/invite", func(w http.ResponseWriter, r *http.Request) {
		nick, ok := s.gateNick(r)
		if !ok {
			fail(w, http.StatusUnauthorized, "нужно действующее приглашение")
			return
		}
		w.Header().Set(nickHeader, nick)
		w.Header().Set(pairStatusHeader, s.pairStatus(r, nick))
		w.WriteHeader(http.StatusOK)
	})
	return m
}

// PublicHandler — порт 8080: адреса join.<домен> и api.<домен>.
func (s *Server) PublicHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	m.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if err := s.Store.Ping(); err != nil {
			fail(w, http.StatusServiceUnavailable, "база недоступна")
			return
		}
		w.Write([]byte("ok"))
	})
	s.registerAPI(m)
	s.registerDevices(m)
	s.registerPairing(m)
	s.registerDrive(m)
	s.registerSSH(m)
	s.registerPush(m)
	if s.Spaces != nil {
		if s.SpaceURL == nil {
			s.SpaceURL = spaceURL
		}
		s.registerSpaces(m)
		s.registerAccount(m)
		s.registerTeams(m)
		s.registerGrants(m)
	}
	m.HandleFunc("/start", s.handleStart)
	m.HandleFunc("/v1/enroll/challenge", s.enrollProxy("/v1/devices/challenge", needInvite))
	m.HandleFunc("/v1/enroll", s.enrollProxy("/v1/devices", needInvite|consumeInvite))
	// Статус — без приглашения: устройство ждёт подтверждения дольше, чем живёт приглашение, и токен приглашения
	// приложение не хранит. Запрос подписан ключом сессии устройства, его проверяет keyguard; тело маленькое.
	m.HandleFunc("/v1/enroll/status", s.enrollProxy("/v1/devices/status", 0))
	return m
}

// handleStart — первый шаг в системном браузере: проверить приглашение, поставить cookie и увести в Keycloak.
func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		fail(w, http.StatusMethodNotAllowed, "только GET")
		return
	}
	inv, _, err := s.lookup(r.URL.Query().Get("invite"))
	if err != nil || inv.Used {
		fail(w, http.StatusForbidden, "приглашение недействительно, истекло или уже использовано")
		return
	}
	// Уводим только на свой Keycloak: иначе ссылка с чужим next превращала бы join в открытый редирект.
	next := r.URL.Query().Get("next")
	if !strings.HasPrefix(next, s.Cfg.Issuer+"/") {
		fail(w, http.StatusBadRequest, "next должен вести на страницу входа этого кластера")
		return
	}
	pairID, pairSecret := r.URL.Query().Get("pair"), r.URL.Query().Get("pair_secret")
	var pairExpires time.Time
	if pairID != "" {
		p, ok := s.validPair(pairID, pairSecret, inv.Nick)
		if !ok {
			fail(w, http.StatusForbidden, "pairing недействителен или истёк")
			return
		}
		pairExpires = p.Expires
	}
	exp := s.now().Add(s.Cfg.GateTTL)
	v, err := s.signGate(inv.Nick, exp)
	if err != nil {
		s.Log.Printf("event=state.failed op=cookie_key err=%q", err.Error())
		fail(w, http.StatusServiceUnavailable, "временно недоступно")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: inviteCookie, Value: v, Domain: s.Cfg.CookieDomain, Path: "/", Expires: exp, MaxAge: int(s.Cfg.GateTTL.Seconds()),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	if pairID != "" {
		http.SetCookie(w, &http.Cookie{
			Name: pairCookie, Value: pairID + "." + pairSecret, Domain: s.Cfg.CookieDomain, Path: "/",
			Expires: pairExpires, MaxAge: int(pairExpires.Sub(s.now()).Seconds()), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
	} else {
		http.SetCookie(w, &http.Cookie{Name: pairCookie, Value: "", Domain: s.Cfg.CookieDomain, Path: "/",
			Expires: time.Unix(1, 0), MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer") // токен приглашения был в адресе этой страницы
	http.Redirect(w, r, next, http.StatusFound)
}

// tokenUser — preferred_username из токена Keycloak БЕЗ проверки подписи: подпись, издателя и привязку к ключу
// проверяет keyguard. control-plane нужно только сверить, что регистрируется тот, кого приглашали.
func tokenUser(jwt string) string {
	p := strings.Split(jwt, ".")
	if len(p) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(p[1])
	if err != nil {
		return ""
	}
	var c struct {
		User string `json:"preferred_username"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return ""
	}
	return c.User
}

// enrollProxy передаёт запрос регистрации в keyguard как есть. Приглашение проверяется здесь, а не только
// в Traefik: адрес api.<домен> ведёт на этот же порт без forwardAuth, и заголовку ника от клиента верить нельзя.
const (
	needInvite = 1 << iota
	consumeInvite
)

func (s *Server) enrollProxy(kgPath string, mode int) http.HandlerFunc {
	consume := mode&consumeInvite != 0
	limit := s.maxBody()
	if mode&needInvite == 0 {
		limit = 8 << 10
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			fail(w, http.StatusMethodNotAllowed, "только POST")
			return
		}
		var inv Invite
		var hash string
		if mode&needInvite != 0 {
			var err error
			if inv, hash, err = s.lookup(r.Header.Get(inviteHeader)); err != nil {
				fail(w, http.StatusUnauthorized, "нужно действующее приглашение")
				return
			}
		}
		// Использованное приглашение не годится ни для одного шага регистрации, включая первый (вызов для
		// аттестации): приложение по его успеху понимает, что приглашение действует, и начинает создавать ключи.
		if mode&needInvite != 0 && inv.Used {
			fail(w, http.StatusForbidden, "приглашение уже использовано")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
		if err != nil {
			fail(w, http.StatusRequestEntityTooLarge, "тело слишком большое")
			return
		}
		if consume {
			var q struct {
				AccessToken string `json:"access_token"`
			}
			if json.Unmarshal(body, &q) != nil || tokenUser(q.AccessToken) != inv.Nick {
				fail(w, http.StatusForbidden, "приглашение выпущено для другого пользователя")
				return
			}
		}
		status, resp, err := s.KG.Post(r.Context(), kgPath, body)
		if err != nil {
			s.Log.Printf("event=keyguard.unreachable path=%s err=%q", kgPath, err.Error())
			fail(w, http.StatusBadGateway, "keyguard недоступен")
			return
		}
		if consume && status == http.StatusOK {
			// keyguard уже записал устройство. Если отметка не удалась, приглашение останется годным до срока —
			// но вторая регистрация того же устройства в keyguard безвредна, а чужому токен неизвестен.
			if err := s.Store.UseInvite(hash); err != nil {
				s.Log.Printf("event=invite.use_failed nick=%s err=%q", inv.Nick, err.Error())
			} else {
				s.Log.Printf("event=invite.used nick=%s inviter=%s", inv.Nick, inv.Inviter)
			}
			// Новое устройство ждёт подтверждения: уведомляем уже подключённые устройства этого человека.
			var st struct {
				Status string `json:"status"`
			}
			if json.Unmarshal(resp, &st) == nil && st.Status == "pending" {
				go s.notify(context.Background(), inv.Nick, Notification{Title: "Новое устройство",
					Body: "Устройство ждёт подтверждения. Если это не вы — не подтверждайте и отзовите его",
					Data: map[string]string{"kind": "device"}})
			}
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		w.Write(bytes.TrimSpace(resp))
	}
}

// AdminHandler — порт 8082: только через админский вход Traefik (VPN + сертификат администратора).
// Здесь выпускается приглашение, пока приглашать из приложения ещё некому (первый пользователь, потеря устройств).
func (s *Server) AdminHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/admin/v1/invites", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			fail(w, http.StatusMethodNotAllowed, "только POST")
			return
		}
		var q struct {
			Nick string `json:"nick"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&q) != nil {
			fail(w, http.StatusBadRequest, "json")
			return
		}
		link, exp, err := s.NewInvite(r.Context(), q.Nick, "admin")
		if errors.Is(err, ErrBadNick) {
			fail(w, http.StatusBadRequest, err.Error())
			return
		}
		if err != nil {
			s.Log.Printf("event=invite.failed nick=%s err=%q", q.Nick, err.Error())
			fail(w, http.StatusBadGateway, "не удалось выпустить приглашение: "+err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(map[string]string{"nick": q.Nick, "link": link, "expires": exp.UTC().Format(time.RFC3339)})
	})
	return m
}
