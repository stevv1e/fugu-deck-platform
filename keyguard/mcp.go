package keyguard

// MCP-серверы владельца личного пространства (Streamable HTTP). Пространство в интернет не выходит (Squid по белому
// списку), поэтому к MCP оно ходит через keyguard: POST /mcp/<id> с токеном пространства, keyguard подставляет токен
// MCP-сервера и пересылает запрос. Адрес и токен владелец добавляет подписанным действием mcp_put (токен — HPKE, как
// ключи API); пространство токена не видит. Внутренние адреса запрещены дважды: сетевой политикой keyguard и здесь,
// при подключении (адрес проверяется после DNS, перенаправления не выполняются).

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	mcpSlot       = "mcp" // запись в хранилище ключей: JSON-список серверов пользователя
	mcpMaxServers = 10
	mcpMaxBody    = 1 << 20 // запрос пространства
	mcpMaxResp    = 8 << 20 // ответ сервера (в том числе поток SSE)
	mcpTimeout    = 120 * time.Second
)

type mcpServer struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	URL   string `json:"url"`
	Token string `json:"token,omitempty"`
}

// McpPutAAD — AAD шифротекста токена MCP: привязан к устройству, серверу и этой подписи.
func McpPutAAD(deviceID, id, nonce string) string {
	return "mcp_put|" + deviceID + "|" + id + "|" + nonce
}

func (s *Server) mcpLoad(ctx context.Context, user string) ([]mcpServer, error) {
	v, err := s.Store.Get(ctx, user, mcpSlot)
	if errors.Is(err, ErrNoKey) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list []mcpServer
	if err := json.Unmarshal([]byte(v), &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (s *Server) mcpSave(ctx context.Context, user string, list []mcpServer) error {
	if len(list) == 0 {
		return s.Store.Delete(ctx, user, mcpSlot)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	b, _ := json.Marshal(list)
	return s.Store.Put(ctx, user, mcpSlot, string(b))
}

// mcpURL — только https, без логина в адресе, порт 443, имя хоста (не IP): адрес проверяется ещё раз при подключении.
func mcpURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || u.Fragment != "" {
		return nil, errors.New("адрес MCP: https://имя-хоста/путь")
	}
	if p := u.Port(); p != "" && p != "443" {
		return nil, errors.New("адрес MCP: только порт 443")
	}
	if net.ParseIP(u.Hostname()) != nil || !strings.Contains(u.Hostname(), ".") {
		return nil, errors.New("адрес MCP: имя хоста, а не IP-адрес")
	}
	return u, nil
}

// publicIP — адрес в интернете: не внутренний, не служебный.
func publicIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
		for _, c := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "240.0.0.0/4"} {
			if _, n, _ := net.ParseCIDR(c); n.Contains(ip) {
				return false
			}
		}
	}
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast())
}

func (s *Server) mcpHTTP() *http.Client {
	s.mcpOnce.Do(func() {
		allow := s.MCPAllowIP
		if allow == nil {
			allow = publicIP
		}
		d := &net.Dialer{Timeout: 10 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if ip := net.ParseIP(host); err != nil || ip == nil || !allow(ip) {
				return fmt.Errorf("адрес %s не в интернете — запрещено", host)
			}
			return nil
		}}
		tr := &http.Transport{DialContext: d.DialContext, Proxy: nil, ForceAttemptHTTP2: true,
			TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: mcpTimeout, MaxIdleConnsPerHost: 4}
		if s.MCPTransport != nil {
			tr = s.MCPTransport
		}
		s.mcpClient = &http.Client{Transport: tr,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	})
	return s.mcpClient
}

type mcpPutReq struct {
	SignedAction
	Enc string `json:"enc,omitempty"`
	Ct  string `json:"ct,omitempty"`
}

// handleMcpPut — добавить или заменить MCP-сервер (control-plane передаёт подписанное действие mcp_put как есть).
func (s *Server) handleMcpPut(w http.ResponseWriter, r *http.Request) {
	body, ok := s.cpBody(w, r)
	if !ok {
		return
	}
	var req mcpPutReq
	if json.Unmarshal(body, &req) != nil {
		fail(w, 400, "json")
		return
	}
	a, dev, err := s.Verifier.Verify(req.SignedAction, "mcp_put")
	if err != nil {
		fail(w, 403, err.Error())
		return
	}
	user, id := dev.User, s_(a, "id")
	if !safeSeg(user) {
		fail(w, 400, "пользователь")
		return
	}
	u, err := mcpURL(s_(a, "url"))
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	srv := mcpServer{ID: id, Name: s_(a, "name"), URL: u.String()}
	if hint := s_(a, "token_hint"); hint != "" {
		enc, e1 := base64.StdEncoding.DecodeString(req.Enc)
		ct, e2 := base64.StdEncoding.DecodeString(req.Ct)
		if e1 != nil || e2 != nil || len(ct) == 0 {
			fail(w, 400, "base64")
			return
		}
		h := sha256.Sum256(append(append([]byte{}, enc...), ct...))
		if s_(a, "ct_sha256") != hex.EncodeToString(h[:]) {
			fail(w, 403, "шифротекст не соответствует подписи")
			return
		}
		hk := s.hpkeKey()
		if hk == nil {
			fail(w, 503, "ключ HPKE ещё не загружен")
			return
		}
		pt, err := HPKEOpen(hk, enc, []byte(HPKEInfo), []byte(McpPutAAD(dev.ID, id, s_(a, "nonce"))), ct)
		if err != nil {
			fail(w, 403, "не удалось расшифровать")
			return
		}
		tok := string(pt)
		if !validKey(tok) || !strings.HasSuffix(tok, hint) {
			fail(w, 422, "токен не совпадает с показанным при подписи или недопустим")
			return
		}
		srv.Token = tok
	}
	list, err := s.mcpLoad(r.Context(), user)
	if err != nil {
		s.Log.Printf("event=mcp.put user=%s result=store_error", uid(user))
		fail(w, 503, "хранилище")
		return
	}
	out := []mcpServer{srv}
	for _, x := range list {
		if x.ID != id {
			out = append(out, x)
		}
	}
	if len(out) > mcpMaxServers {
		fail(w, 409, fmt.Sprintf("не больше %d MCP-серверов", mcpMaxServers))
		return
	}
	if err := s.mcpSave(r.Context(), user, out); err != nil {
		fail(w, 500, "хранилище")
		return
	}
	s.Log.Printf("event=mcp.put user=%s id=%s host=%s token=%t", uid(user), id, u.Hostname(), srv.Token != "")
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "id": id, "name": srv.Name, "url": srv.URL, "has_token": srv.Token != ""})
}

func (s *Server) handleMcpDelete(w http.ResponseWriter, r *http.Request) {
	body, ok := s.cpBody(w, r)
	if !ok {
		return
	}
	var sa SignedAction
	if json.Unmarshal(body, &sa) != nil {
		fail(w, 400, "json")
		return
	}
	a, dev, err := s.Verifier.Verify(sa, "mcp_delete")
	if err != nil {
		fail(w, 403, err.Error())
		return
	}
	list, err := s.mcpLoad(r.Context(), dev.User)
	if err != nil {
		fail(w, 503, "хранилище")
		return
	}
	out := list[:0]
	for _, x := range list {
		if x.ID != s_(a, "id") {
			out = append(out, x)
		}
	}
	if err := s.mcpSave(r.Context(), dev.User, out); err != nil {
		fail(w, 500, "хранилище")
		return
	}
	s.Log.Printf("event=mcp.delete user=%s id=%s", uid(dev.User), s_(a, "id"))
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func mcpPublic(list []mcpServer) []map[string]any {
	out := []map[string]any{}
	for _, x := range list {
		out = append(out, map[string]any{"id": x.ID, "name": x.Name, "url": x.URL, "has_token": x.Token != ""})
	}
	return out
}

// handleMcpList — control-plane от имени пользователя: серверы без токенов.
func (s *Server) handleMcpList(w http.ResponseWriter, r *http.Request) {
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
	list, err := s.mcpLoad(r.Context(), req.User)
	if err != nil {
		fail(w, 503, "хранилище")
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"servers": mcpPublic(list)})
}

// mcpOwner — владелец личного пространства, которое зовёт keyguard.
func (s *Server) mcpOwner(w http.ResponseWriter, r *http.Request) (string, bool) {
	c, err := s.caller(r)
	if err != nil {
		fail(w, 401, "не опознан")
		return "", false
	}
	if !strings.HasPrefix(c.Namespace, "deck-u-") {
		fail(w, 403, "MCP и свои домены — только в личных пространствах")
		return "", false
	}
	return strings.TrimPrefix(c.Namespace, "deck-u-"), true
}

// handleMcpMine — личному пространству: его MCP-серверы (без токенов).
func (s *Server) handleMcpMine(w http.ResponseWriter, r *http.Request) {
	user, ok := s.mcpOwner(w, r)
	if !ok {
		return
	}
	list, err := s.mcpLoad(r.Context(), user)
	if err != nil {
		fail(w, 503, "хранилище")
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"servers": mcpPublic(list)})
}

var mcpReqHeaders = []string{"Content-Type", "Accept", "Mcp-Session-Id", "Mcp-Protocol-Version", "Last-Event-Id"}

// handleMcp — POST|DELETE /mcp/<id>: запрос пространства уходит его MCP-серверу с токеном владельца.
func (s *Server) handleMcp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		fail(w, 405, "POST или DELETE")
		return
	}
	user, ok := s.mcpOwner(w, r)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/mcp/")
	if !safeSeg(id) || r.URL.RawQuery != "" {
		fail(w, 404, "нет такого сервера")
		return
	}
	list, err := s.mcpLoad(r.Context(), user)
	if err != nil {
		fail(w, 503, "хранилище")
		return
	}
	var srv *mcpServer
	for i := range list {
		if list[i].ID == id {
			srv = &list[i]
		}
	}
	if srv == nil {
		fail(w, 404, "нет такого сервера")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, mcpMaxBody))
	if err != nil {
		fail(w, 413, "тело слишком большое")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), mcpTimeout)
	defer cancel()
	up, _ := http.NewRequestWithContext(ctx, r.Method, srv.URL, bytes.NewReader(body))
	for _, h := range mcpReqHeaders {
		if v := r.Header.Get(h); v != "" {
			up.Header.Set(h, v)
		}
	}
	if srv.Token != "" {
		up.Header.Set("Authorization", "Bearer "+srv.Token)
	}
	resp, err := s.mcpHTTP().Do(up)
	if err != nil {
		s.Log.Printf("event=mcp ns=deck-u-%s id=%s result=unreachable", uid(user), id)
		fail(w, 502, "MCP-сервер недоступен")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		s.Log.Printf("event=mcp ns=deck-u-%s id=%s status=%d result=redirect", uid(user), id, resp.StatusCode)
		fail(w, 502, "MCP-сервер ответил перенаправлением — укажите конечный адрес")
		return
	}
	for _, h := range []string{"Content-Type", "Mcp-Session-Id"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	fl, _ := w.(http.Flusher)
	rd := bufio.NewReader(io.LimitReader(resp.Body, mcpMaxResp))
	buf := make([]byte, 16<<10)
	var n int64
	for {
		k, err := rd.Read(buf)
		if k > 0 {
			chunk := buf[:k]
			if srv.Token != "" {
				chunk = bytes.ReplaceAll(chunk, []byte(srv.Token), []byte("[redacted]"))
			}
			w.Write(chunk)
			n += int64(k)
			if fl != nil {
				fl.Flush()
			}
		}
		if err != nil {
			break
		}
	}
	s.Log.Printf("event=mcp ns=deck-u-%s id=%s status=%d bytes=%d", uid(user), id, resp.StatusCode, n)
}
