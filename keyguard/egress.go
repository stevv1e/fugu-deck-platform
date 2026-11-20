package keyguard

// Свои домены владельца личного пространства (D65). Пространство в интернет не выходит: Squid пускает только к общему
// списку реестров пакетов. Страницы с других сайтов агент читает через keyguard: GET /egress/fetch?url=… с токеном
// пространства. Список доменов (точные имена хостов) владелец задаёт подписанным действием egress_set — агент сам
// его не расширит. Только GET и только https:443; внутренние адреса запрещены, как у MCP (проверка после DNS);
// перенаправления выполняются, только если ведут на домен из того же списка.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	egressSlot      = "egress" // запись в хранилище ключей: JSON-список доменов пользователя
	egressMaxResp   = 2 << 20
	egressTimeout   = 30 * time.Second
	egressRedirects = 3
)

func (s *Server) egressLoad(ctx context.Context, user string) ([]string, error) {
	v, err := s.Store.Get(ctx, user, egressSlot)
	if errors.Is(err, ErrNoKey) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list []string
	if err := json.Unmarshal([]byte(v), &list); err != nil {
		return nil, err
	}
	return list, nil
}

// handleEgressSet — заменить список доменов (control-plane передаёт подписанное действие egress_set как есть).
func (s *Server) handleEgressSet(w http.ResponseWriter, r *http.Request) {
	body, ok := s.cpBody(w, r)
	if !ok {
		return
	}
	var sa SignedAction
	if json.Unmarshal(body, &sa) != nil {
		fail(w, 400, "json")
		return
	}
	a, dev, err := s.Verifier.Verify(sa, "egress_set")
	if err != nil {
		fail(w, 403, err.Error())
		return
	}
	if !safeSeg(dev.User) {
		fail(w, 400, "пользователь")
		return
	}
	var list []string
	for _, x := range a["domains"].([]any) {
		list = append(list, x.(string))
	}
	sort.Strings(list)
	if len(list) == 0 {
		err = s.Store.Delete(r.Context(), dev.User, egressSlot)
	} else {
		b, _ := json.Marshal(list)
		err = s.Store.Put(r.Context(), dev.User, egressSlot, string(b))
	}
	if err != nil {
		fail(w, 500, "хранилище")
		return
	}
	s.Log.Printf("event=egress.set user=%s domains=%d", uid(dev.User), len(list))
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "domains": nonNil(list)})
}

func nonNil(x []string) []string {
	if x == nil {
		return []string{}
	}
	return x
}

// handleEgressList — control-plane от имени пользователя: его домены.
func (s *Server) handleEgressList(w http.ResponseWriter, r *http.Request) {
	body, ok := s.cpBody(w, r)
	if !ok {
		return
	}
	var req struct {
		User string `json:"user"`
	}
	if json.Unmarshal(body, &req) != nil || !safeSeg(req.User) {
		fail(w, 400, "user")
		return
	}
	list, err := s.egressLoad(r.Context(), req.User)
	if err != nil {
		fail(w, 503, "хранилище")
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"domains": nonNil(list)})
}

// handleEgressMine — личному пространству: его домены (агенту — в описание инструмента).
func (s *Server) handleEgressMine(w http.ResponseWriter, r *http.Request) {
	user, ok := s.mcpOwner(w, r)
	if !ok {
		return
	}
	list, err := s.egressLoad(r.Context(), user)
	if err != nil {
		fail(w, 503, "хранилище")
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"domains": nonNil(list)})
}

// egressTarget — адрес допустим: https, порт 443, без логина, хост — точно из списка.
func egressTarget(raw string, allowed []string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" {
		return nil, errors.New("нужен адрес https://домен/…")
	}
	if p := u.Port(); p != "" && p != "443" {
		return nil, errors.New("только порт 443")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if net.ParseIP(host) != nil {
		return nil, errors.New("нужно имя домена, а не IP-адрес")
	}
	for _, d := range allowed {
		if host == d {
			u.Fragment = ""
			return u, nil
		}
	}
	return nil, fmt.Errorf("домена %s нет в списке владельца (экран кластера → «Домены для агента»)", host)
}

// handleEgressFetch — GET /egress/fetch?url=…: страница с домена из списка владельца. Ответ — тело как есть
// (не больше 2 МБ); статус и адрес после перенаправлений — в заголовках X-Upstream-Status и X-Final-Url.
func (s *Server) handleEgressFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		fail(w, 405, "только GET")
		return
	}
	user, ok := s.mcpOwner(w, r)
	if !ok {
		return
	}
	allowed, err := s.egressLoad(r.Context(), user)
	if err != nil {
		fail(w, 503, "хранилище")
		return
	}
	target, err := egressTarget(r.URL.Query().Get("url"), allowed)
	if err != nil {
		s.Log.Printf("event=egress ns=deck-u-%s result=denied reason=%q", uid(user), err.Error())
		fail(w, 403, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), egressTimeout)
	defer cancel()
	var resp *http.Response
	for hop := 0; ; hop++ {
		up, _ := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
		up.Header.Set("User-Agent", "FuguDeck-agent/1 (+keyguard)")
		up.Header.Set("Accept", "text/html,application/json,text/plain,*/*;q=0.5")
		resp, err = s.mcpHTTP().Do(up)
		if err != nil {
			s.Log.Printf("event=egress ns=deck-u-%s host=%s result=unreachable", uid(user), target.Hostname())
			fail(w, 502, "сайт недоступен")
			return
		}
		if resp.StatusCode < 300 || resp.StatusCode >= 400 || resp.Header.Get("Location") == "" {
			break
		}
		resp.Body.Close()
		next, perr := target.Parse(resp.Header.Get("Location"))
		if perr == nil {
			target, perr = egressTarget(next.String(), allowed)
		}
		if perr != nil || hop >= egressRedirects {
			msg := "слишком много перенаправлений"
			if perr != nil {
				msg = "перенаправление на адрес вне списка: " + perr.Error()
			}
			fail(w, 502, msg)
			return
		}
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.Header().Set("X-Upstream-Status", fmt.Sprint(resp.StatusCode))
	w.Header().Set("X-Final-Url", target.String())
	n, _ := io.Copy(w, io.LimitReader(resp.Body, egressMaxResp))
	s.Log.Printf("event=egress ns=deck-u-%s host=%s status=%d bytes=%d", uid(user), target.Hostname(), resp.StatusCode, n)
}
