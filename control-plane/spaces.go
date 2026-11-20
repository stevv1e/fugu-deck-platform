package controlplane

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Пространства. control-plane умеет две вещи: попросить о пространстве (создать объект Space — остальное делает
// space-operator, у которого нет входа из интернета) и передать запрос приложения в пространство, приложив
// собственный короткий токен. Ключей API в этой цепочке нет нигде: агент ходит к моделям через keyguard.

// SpaceInfo — то, что control-plane знает о пространстве.
type SpaceInfo struct {
	Name      string
	Owner     string
	Phase     string // Pending | Ready | Sleeping | Deleting | Failed
	Namespace string
	Message   string
	TokenKey  string // публичный ключ, записанный в аннотации
	Suspended bool   // spec.suspended: пространство усыплено (или засыпает — оператор ещё не убрал под)
	// Удаление: запрос записывает control-plane (spec), проверяет подпись и отсчитывает срок space-operator (status).
	DeleteRequested bool
	DeleteAt        string // когда оператор удалит пространство (RFC 3339); пусто — запрос ещё не принят
	DeleteError     string // оператор запрос отклонил
	DeleteKind      string // "account" — подпись account_delete, "inactive" — неактивность: удаляется весь аккаунт владельца
	InactiveDelete  bool   // control-plane попросил удалить аккаунт по неактивности
	// WakeAt — когда разбудить спящее пространство ради задания по расписанию (аннотация; нуль — не будить).
	WakeAt time.Time
}

// SpaceAPI — объекты Space в API Kubernetes (права control-plane: только Space в deck-system, без удаления).
type SpaceAPI interface {
	Get(ctx context.Context, name string) (SpaceInfo, error)
	// Ensure создаёт личное пространство или обновляет в существующем ключ токенов.
	Ensure(ctx context.Context, name, owner, tokenKeyPEM string) error
	// EnsureTeam — то же для общего пространства (kind: team) с названием для людей.
	EnsureTeam(ctx context.Context, name, owner, title, tokenKeyPEM string) error
	List(ctx context.Context) ([]SpaceInfo, error)
	// SetSuspended усыпляет пространство (под убирается, данные остаются) или будит его.
	SetSuspended(ctx context.Context, name string, suspended bool) error
	// RequestDelete записывает запрос удаления с подписью владельца; jws == "" снимает запрос (отмена).
	RequestDelete(ctx context.Context, name, jws string, at time.Time) error
	// SetWakeAt запоминает, когда разбудить пространство; нулевое время — не будить.
	SetWakeAt(ctx context.Context, name string, at time.Time) error
	// SetOwner — новый владелец общего пространства (передача владения).
	SetOwner(ctx context.Context, name, owner string) error
	// SetInactiveDelete — просьба удалить аккаунт владельца по неактивности (исполняет оператор); false — отмена.
	SetInactiveDelete(ctx context.Context, name string, on bool) error
}

var jwsRe = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

const (
	tokenKeyAnnotation = "deck.fugu/token-key"
	wakeAtAnnotation   = "deck.fugu/wake-at"
	spaceTokenTTL      = 10 * time.Minute
	spaceIssuer        = "deck-control-plane"
)

// spaceSigner — ключ ES256, которым control-plane подписывает токены входа в пространства. Пространство знает
// только публичную часть (её кладёт в под space-operator), поэтому выпустить себе токен или роль не может.
type spaceSigner struct {
	once sync.Once
	key  *ecdsa.PrivateKey
	pub  string
	err  error
}

func (s *Server) signer() (*ecdsa.PrivateKey, string, error) {
	s.spaceKey.once.Do(func() {
		der, err := s.Store.SpaceKey()
		if err != nil {
			s.spaceKey.err = err
			return
		}
		k, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			s.spaceKey.err = err
			return
		}
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok || ek.Curve != elliptic.P256() {
			s.spaceKey.err = errors.New("ключ токенов пространств: нужен P-256")
			return
		}
		spki, err := x509.MarshalPKIXPublicKey(&ek.PublicKey)
		if err != nil {
			s.spaceKey.err = err
			return
		}
		s.spaceKey.key, s.spaceKey.pub = ek, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))
	})
	return s.spaceKey.key, s.spaceKey.pub, s.spaceKey.err
}

// newSpaceKey — новый ключ в PKCS#8 (для хранилищ).
func newSpaceKey() ([]byte, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKCS8PrivateKey(k)
}

// spaceToken — токен входа в пространство: iss, aud=space:<id>, sub, nick, name, role, iat, exp (backend/app/spaceauth.py).
func (s *Server) spaceToken(space, user, role string) (string, error) {
	return s.signSpaceJWT(map[string]any{"aud": "space:" + space, "sub": user, "nick": user, "name": user, "role": role})
}

// signSpaceJWT подписывает токен control-plane ключом пространств; iss, iat и exp добавляются здесь.
func (s *Server) signSpaceJWT(claims map[string]any) (string, error) {
	key, _, err := s.signer()
	if err != nil {
		return "", err
	}
	now := s.now()
	hb, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT"})
	claims["iss"], claims["iat"], claims["exp"] = spaceIssuer, now.Unix(), now.Add(spaceTokenTTL).Unix()
	cb, _ := json.Marshal(claims)
	in := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb)
	d := sha256.Sum256([]byte(in))
	r, sg, err := ecdsa.Sign(rand.Reader, key, d[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sg.FillBytes(sig[32:])
	return in + "." + b64.EncodeToString(sig), nil
}

func (s *Server) writeSpace(w http.ResponseWriter, info SpaceInfo, exists bool) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	out := map[string]any{"exists": exists}
	if exists {
		out["id"], out["phase"], out["message"] = info.Name, info.Phase, info.Message
		out["url"] = s.Cfg.APIURL + "/s/" + info.Name
		if info.DeleteRequested {
			// delete_at появляется, когда оператор принял подпись; delete_error — когда отклонил.
			out["delete_requested"] = true
			if info.DeleteAt != "" {
				out["delete_at"] = info.DeleteAt
			}
			if info.DeleteError != "" {
				out["delete_error"] = info.DeleteError
			}
			if info.DeleteKind == "account" {
				out["delete_account"] = true
			}
		}
	}
	json.NewEncoder(w).Encode(out)
}

func (s *Server) registerSpaces(m *http.ServeMux) {
	// Личное пространство пользователя: имя объекта Space — его ник (space-operator другого не примет).
	m.HandleFunc("/v1/space", s.apiAny(func(w http.ResponseWriter, r *http.Request, id *Identity) {
		switch r.Method {
		case http.MethodGet:
			info, err := s.Spaces.Get(r.Context(), id.User)
			if errors.Is(err, ErrNotFound) {
				s.writeSpace(w, SpaceInfo{}, false)
				return
			}
			if err != nil {
				s.Log.Printf("event=space.get_failed user=%s err=%q", id.User, err.Error())
				fail(w, http.StatusBadGateway, "не удалось узнать состояние пространства")
				return
			}
			if s.healTokenKey(r.Context(), info) {
				info.Phase, info.Message = "Pending", "агент перезапускается с новым ключом"
			} else if info.Phase != "Deleting" && asleep(info) {
				// Просмотр состояния пространство не будит: будит POST (кнопка «Открыть») или запрос в него.
				info.Phase, info.Message = "Sleeping", "пространство спит — откройте его, и агент запустится"
			}
			s.writeSpace(w, info, true)
		case http.MethodPost:
			_, pub, err := s.signer()
			if err != nil {
				s.Log.Printf("event=state.failed op=space_key err=%q", err.Error())
				fail(w, http.StatusServiceUnavailable, "временно недоступно")
				return
			}
			if err := s.Spaces.Ensure(r.Context(), id.User, id.User, pub); err != nil {
				s.Log.Printf("event=space.create_failed user=%s err=%q", id.User, err.Error())
				fail(w, http.StatusBadGateway, "не удалось создать пространство")
				return
			}
			s.Log.Printf("event=space.ensure user=%s device=%s", id.User, id.DeviceID)
			info, err := s.Spaces.Get(r.Context(), id.User)
			if err != nil {
				info = SpaceInfo{Name: id.User, Phase: "Pending"}
			}
			if info.Phase != "Deleting" && asleep(info) {
				if s.wake(r.Context(), info) != nil {
					fail(w, http.StatusBadGateway, "не удалось разбудить пространство")
					return
				}
				info.Phase, info.Message = "Pending", "пространство просыпается"
			}
			if info.Phase == "" {
				info.Phase = "Pending"
			}
			s.writeSpace(w, info, true)
		default:
			fail(w, http.StatusMethodNotAllowed, "GET или POST")
		}
	}))

	// Удаление личного пространства. control-plane подпись не проверяет и удалить ничего не может: он записывает
	// запрос с подписью владельца в Space, а проверяет её (через keyguard) и удаляет space-operator — через срок,
	// который отсчитывает сам. Здесь только отсекается заведомо негодное, чтобы человек сразу увидел причину.
	m.HandleFunc("/v1/space/delete", s.api(http.MethodPost, func(w http.ResponseWriter, r *http.Request, id *Identity) {
		s.requestDelete(w, r, id, id.User, "u-"+id.User, func(info SpaceInfo) { s.writeSpace(w, info, true) })
	}))
	// Отмена удаления до истечения срока. Подписи не требует: отмена ничего не разрушает.
	m.HandleFunc("/v1/space/restore", s.api(http.MethodPost, func(w http.ResponseWriter, r *http.Request, id *Identity) {
		s.cancelDelete(w, r, id, id.User, func(info SpaceInfo) { s.writeSpace(w, info, true) })
	}))

	// Запросы приложения в пространство: /s/<id>/… → сервис space в namespace пространства.
	m.HandleFunc("/s/", s.apiAny(s.proxySpace))
}

// proxySpace передаёт запрос в пространство. Всё, чем клиент опознавал себя перед control-plane (токен Keycloak,
// DPoP, сертификат, cookie), дальше не идёт: пространство получает только токен control-plane.
func (s *Server) proxySpace(w http.ResponseWriter, r *http.Request, id *Identity) {
	rest := strings.TrimPrefix(r.URL.Path, "/s/")
	name, path, _ := strings.Cut(rest, "/")
	if r.URL.RawPath != "" || strings.Contains(path, "..") {
		fail(w, http.StatusBadRequest, "недопустимый путь")
		return
	}
	// Служебные адреса агента (резервная копия, состав участников) — не для приложения: у них свой вход,
	// и снаружи их быть не должно вовсе.
	if path == "internal" || strings.HasPrefix(path, "internal/") {
		fail(w, http.StatusNotFound, "не найдено")
		return
	}
	// Личное пространство доступно только владельцу, общее — участникам; чужое выглядит как несуществующее.
	acc, ok := s.access(id, name)
	if !ok {
		fail(w, http.StatusNotFound, "пространство не найдено")
		return
	}
	info, err := s.Spaces.Get(r.Context(), name)
	if errors.Is(err, ErrNotFound) || (err == nil && info.Owner != acc.Owner) {
		fail(w, http.StatusNotFound, "пространство не найдено")
		return
	}
	if err != nil {
		fail(w, http.StatusBadGateway, "не удалось узнать состояние пространства")
		return
	}
	// Ключ токенов в пространстве не наш (пространство создано не этим control-plane или его база пересоздана):
	// агент такие токены не примет. Записываем свой ключ — оператор перезапустит агента.
	if s.healTokenKey(r.Context(), info) {
		w.Header().Set("Retry-After", "10")
		fail(w, http.StatusServiceUnavailable, "пространство перезапускается с новым ключом — повторите через несколько секунд")
		return
	}
	if info.Phase == "Deleting" {
		fail(w, http.StatusConflict, "пространство ждёт удаления — отмените удаление, чтобы пользоваться им дальше")
		return
	}
	if asleep(info) {
		if s.wake(r.Context(), info) != nil {
			fail(w, http.StatusBadGateway, "не удалось разбудить пространство")
			return
		}
		w.Header().Set("Retry-After", "10")
		fail(w, http.StatusServiceUnavailable, "пространство просыпается — повторите через несколько секунд")
		return
	}
	if info.Phase != "Ready" || info.Namespace != acc.Namespace {
		w.Header().Set("Retry-After", "5")
		fail(w, http.StatusServiceUnavailable, "пространство ещё не готово: "+info.Phase)
		return
	}
	tok, err := s.spaceToken(name, id.User, acc.Role)
	if err != nil {
		s.Log.Printf("event=state.failed op=space_token err=%q", err.Error())
		fail(w, http.StatusServiceUnavailable, "временно недоступно")
		return
	}
	target := s.SpaceURL(info.Namespace)
	if acc.Team {
		s.syncRoster(r.Context(), name, target) // агент должен знать состав: кто голосует и кого показывать
	}
	q := r.URL.Query()
	q.Del("access_token") // агент принимает токен и в адресе: клиентский сюда попасть не должен
	p := &httputil.ReverseProxy{
		FlushInterval: -1, // потоковые ответы модели (SSE) отдаются без буферизации
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL = &url.URL{Scheme: target.Scheme, Host: target.Host, Path: "/" + path, RawQuery: q.Encode()}
			pr.Out.Host = target.Host
			for _, h := range []string{"Authorization", "Dpop", "Cookie", certHeader, "X-Forwarded-Tls-Client-Cert-Info", inviteHeader, nickHeader} {
				pr.Out.Header.Del(h)
			}
			pr.Out.Header.Set("Authorization", "Bearer "+tok)
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			// Чаще всего агент перезапускается (обновление, новый ключ): клиенту стоит повторить, а не сдаваться.
			s.Log.Printf("event=space.unreachable space=%s err=%q", name, err.Error())
			w.Header().Set("Retry-After", "5")
			fail(w, http.StatusServiceUnavailable, "пространство запускается — повторите через несколько секунд")
		},
	}
	defer s.act.enter(name, s.now)()
	p.ServeHTTP(w, r)
}

// healTokenKey записывает в Space ключ этого control-plane, если там другой. true — ключ пришлось менять.
func (s *Server) healTokenKey(ctx context.Context, info SpaceInfo) bool {
	_, pub, err := s.signer()
	if err != nil || info.TokenKey == pub {
		return false
	}
	if err := s.Spaces.Ensure(ctx, info.Name, info.Owner, pub); err != nil {
		s.Log.Printf("event=space.key_heal_failed space=%s err=%q", info.Name, err.Error())
		return false
	}
	s.Log.Printf("event=space.key_healed space=%s", info.Name)
	return true
}

// spaceURL — адрес агента в пространстве по умолчанию.
func spaceURL(namespace string) *url.URL {
	return &url.URL{Scheme: "http", Host: "space." + namespace + ".svc.cluster.local:8080"}
}

// requestDelete записывает в Space запрос удаления с подписью владельца (space_delete для пространства key).
// Вызывающий уже убедился, что пользователь — владелец пространства name.
func (s *Server) requestDelete(w http.ResponseWriter, r *http.Request, id *Identity, name, key string, write func(SpaceInfo)) {
	body, ok := readSmall(w, r)
	if !ok {
		return
	}
	var q struct {
		JWS string `json:"jws"`
	}
	if json.Unmarshal(body, &q) != nil || !jwsRe.MatchString(q.JWS) || len(q.JWS) > 4096 {
		fail(w, http.StatusBadRequest, "нужно подписанное действие space_delete")
		return
	}
	var a struct {
		Type, Space string
		DeviceID    string `json:"device_id"`
	}
	payload, err := b64.DecodeString(strings.Split(q.JWS, ".")[1])
	if err != nil || json.Unmarshal(payload, &a) != nil || a.Type != "space_delete" || a.Space != key || a.DeviceID != id.DeviceID {
		fail(w, http.StatusForbidden, "действие не об удалении вашего пространства или подписано не этим устройством")
		return
	}
	info, err := s.Spaces.Get(r.Context(), name)
	if errors.Is(err, ErrNotFound) || (err == nil && info.Owner != id.User) {
		fail(w, http.StatusNotFound, "пространство не найдено")
		return
	}
	if err != nil {
		fail(w, http.StatusBadGateway, "не удалось узнать состояние пространства")
		return
	}
	if info.DeleteRequested && info.DeleteAt != "" {
		fail(w, http.StatusConflict, "удаление уже запрошено")
		return
	}
	if err := s.Spaces.RequestDelete(r.Context(), name, q.JWS, s.now()); err != nil {
		s.Log.Printf("event=space.delete_request_failed space=%s user=%s err=%q", name, id.User, err.Error())
		fail(w, http.StatusBadGateway, "не удалось записать запрос удаления")
		return
	}
	s.Log.Printf("event=space.delete_requested space=%s user=%s device=%s", name, id.User, id.DeviceID)
	info.DeleteRequested, info.DeleteAt, info.DeleteError = true, "", ""
	write(info)
}

func (s *Server) cancelDelete(w http.ResponseWriter, r *http.Request, id *Identity, name string, write func(SpaceInfo)) {
	info, err := s.Spaces.Get(r.Context(), name)
	if errors.Is(err, ErrNotFound) || (err == nil && info.Owner != id.User) {
		fail(w, http.StatusNotFound, "пространство не найдено")
		return
	}
	if err != nil {
		fail(w, http.StatusBadGateway, "не удалось узнать состояние пространства")
		return
	}
	if info.DeleteRequested {
		if info.DeleteKind == "account" {
			// keyguard помнит проверенную подпись удаления аккаунта — после отмены она не должна ничего стереть.
			body, _ := json.Marshal(map[string]string{"user": info.Owner})
			if st, _, err := s.KG.Post(r.Context(), "/v1/account/cancel", body); err != nil || st != http.StatusOK {
				s.Log.Printf("event=account.cancel_failed user=%s status=%d err=%v", id.User, st, err)
				fail(w, http.StatusBadGateway, "не удалось отменить удаление аккаунта — повторите")
				return
			}
		}
		if err := s.Spaces.RequestDelete(r.Context(), name, "", s.now()); err != nil {
			s.Log.Printf("event=space.restore_failed space=%s user=%s err=%q", name, id.User, err.Error())
			fail(w, http.StatusBadGateway, "не удалось отменить удаление")
			return
		}
		s.act.touch(name, s.now())
		s.Log.Printf("event=space.restored space=%s user=%s device=%s", name, id.User, id.DeviceID)
	}
	info.DeleteRequested, info.DeleteAt, info.DeleteError, info.Phase, info.Message = false, "", "", "Pending", "пространство запускается"
	write(info)
}
