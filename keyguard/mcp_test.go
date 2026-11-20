package keyguard

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// sealedMcpPut — то, что делает телефон: токен MCP шифруется для keyguard, действие mcp_put подписывается.
func (k *rig) sealedMcpPut(p *phone, id, url, token string) mcpPutReq {
	nonce := fmt.Sprintf("nonce-%016d", atomic.AddInt64(&nonceCtr, 1))
	a := map[string]any{"type": "mcp_put", "id": id, "name": "Тест " + id, "url": url, "token_hint": nil, "ct_sha256": nil,
		"device_id": p.dev.ID, "nonce": nonce, "ts": json.Number(fmt.Sprint(k.now().Unix()))}
	var enc, ct []byte
	if token != "" {
		enc, ct, _ = HPKESeal(k.srv.HPKEKey.PublicKey(), []byte(HPKEInfo), []byte(McpPutAAD(p.dev.ID, id, nonce)), []byte(token))
		h := sha256.Sum256(append(append([]byte{}, enc...), ct...))
		a["token_hint"], a["ct_sha256"] = token[len(token)-4:], hex.EncodeToString(h[:])
	}
	r := mcpPutReq{SignedAction: SignedAction{jwsOf(Canonical(a), p.dev.ID, p.confirm)}}
	if token != "" {
		r.Enc, r.Ct = base64.StdEncoding.EncodeToString(enc), base64.StdEncoding.EncodeToString(ct)
	}
	return r
}

func TestMCP(t *testing.T) {
	k := newRig(t)
	c := &check{t: t}
	var gotAuth, gotSession atomic.Value
	mcp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		gotSession.Store(r.Header.Get("Mcp-Session-Id"))
		b, _ := io.ReadAll(r.Body)
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "https://169.254.169.254/", http.StatusFound)
			return
		}
		w.Header().Set("Mcp-Session-Id", "sess-1")
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"echo\":%s,\"leak\":\"%s\"}}\n\n", b, gotAuth.Load())
	}))
	defer mcp.Close()
	// в тесте «mcp.example.com:443» ведёт на локальный TLS-сервер; проверка адресов — отдельно, ниже
	addr := strings.TrimPrefix(mcp.URL, "https://")
	k.srv.MCPTransport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, addr)
		}}

	put := k.sealedMcpPut(k.anna, "docs", "https://mcp.example.com/mcp", "mcp-token-SECRET1234")
	st, _ := k.do("POST", "/v1/mcp", "tok-anna", j(put), nil)
	c.ok("M1 добавить MCP — только через control-plane", st == 403, st)
	st, b := k.do("POST", "/v1/mcp", "tok-cp", j(put), nil)
	c.ok("M2 сервер добавлен по подписи, токен принят", st == 200 && strings.Contains(b, `"has_token":true`) && !strings.Contains(b, "SECRET"), st, b)
	st, _ = k.do("POST", "/v1/mcp", "tok-cp", j(put), nil)
	c.ok("M3 повтор той же подписи отклонён", st == 403, st)
	for _, bad := range []string{"http://mcp.example.com/x", "https://10.0.0.5/x", "https://mcp.example.com:8443/x", "https://user:pw@mcp.example.com/x", "https://localhost/x"} {
		st, b = k.do("POST", "/v1/mcp", "tok-cp", j(k.sealedMcpPut(k.anna, "bad", bad, "")), nil)
		c.ok("M4 недопустимый адрес отклонён: "+bad, st == 400 || st == 403, st, b)
	}

	st, b = k.do("GET", "/v1/mcp/mine", "tok-anna", nil, nil)
	c.ok("M5 пространство видит свои серверы без токена", st == 200 && strings.Contains(b, `"id":"docs"`) && !strings.Contains(b, "SECRET"), st, b)
	st, b = k.do("GET", "/v1/mcp/mine", "tok-bob", nil, nil)
	c.ok("M6 чужие серверы не видны", st == 200 && !strings.Contains(b, "docs"), st, b)
	st, _ = k.do("GET", "/v1/mcp/mine", "tok-shop", nil, nil)
	c.ok("M7 общее пространство — отказ", st == 403, st)
	st, b = k.do("POST", "/v1/mcp/list", "tok-cp", j(map[string]string{"user": "anna"}), nil)
	c.ok("M8 control-plane видит список без токена", st == 200 && strings.Contains(b, `"has_token":true`) && !strings.Contains(b, "SECRET"), st, b)

	call := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	hdr := map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "Mcp-Session-Id": "sess-0"}
	st, b = k.do("POST", "/mcp/docs", "tok-anna", call, hdr)
	c.ok("M9 запрос дошёл до MCP с токеном владельца и сессией", st == 200 && strings.Contains(b, `"echo":{"jsonrpc"`) &&
		gotAuth.Load() == "Bearer mcp-token-SECRET1234" && gotSession.Load() == "sess-0", st, b)
	c.ok("M10 токен, повторённый сервером, вычеркнут", !strings.Contains(b, "SECRET") && strings.Contains(b, "[redacted]"), b)
	st, _ = k.do("POST", "/mcp/docs", "tok-bob", call, hdr)
	c.ok("M11 чужое пространство к серверу Анны не ходит", st == 404, st)
	st, _ = k.do("POST", "/mcp/docs", "tok-shop", call, hdr)
	c.ok("M12 общее пространство — отказ", st == 403, st)
	st, _ = k.do("GET", "/mcp/docs", "tok-anna", nil, nil)
	c.ok("M13 GET не пересылается", st == 405, st)

	k.do("POST", "/v1/mcp", "tok-cp", j(k.sealedMcpPut(k.anna, "redir", "https://mcp.example.com/redirect", "")), nil)
	st, b = k.do("POST", "/mcp/redir", "tok-anna", call, hdr)
	c.ok("M14 перенаправление не выполняется", st == 502 && strings.Contains(b, "перенаправлением"), st, b)

	del := k.anna.sign(t, k, map[string]any{"type": "mcp_delete", "id": "docs"}, nil)
	st, _ = k.do("POST", "/v1/mcp/delete", "tok-cp", j(del), nil)
	c.ok("M15 сервер удалён по подписи", st == 200, st)
	st, _ = k.do("POST", "/mcp/docs", "tok-anna", call, hdr)
	c.ok("M16 после удаления — нет такого сервера", st == 404, st)

	if c.f > 0 {
		t.Fatalf("%d проверок не прошли", c.f)
	}
}

func TestMCPAddressGuard(t *testing.T) {
	for ip, want := range map[string]bool{"8.8.8.8": true, "10.1.2.3": false, "127.0.0.1": false, "169.254.169.254": false,
		"100.64.1.1": false, "192.168.1.1": false, "::1": false, "fd00::1": false, "2001:4860:4860::8888": true, "0.0.0.0": false} {
		if publicIP(net.ParseIP(ip)) != want {
			t.Errorf("publicIP(%s) != %v", ip, want)
		}
	}
	// без подмены транспорта соединение с внутренним адресом обрывается до TLS
	ts := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer ts.Close()
	s := &Server{}
	_, err := s.mcpHTTP().Get(ts.URL)
	if err == nil || !strings.Contains(err.Error(), "не в интернете") {
		t.Fatalf("внутренний адрес не запрещён: %v", err)
	}
}
