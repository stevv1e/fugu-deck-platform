package keyguard

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestEgress(t *testing.T) {
	k := newRig(t)
	c := &check{t: t}
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/moved":
			http.Redirect(w, r, "https://docs.example.com/page", http.StatusMovedPermanently)
		case "/away":
			http.Redirect(w, r, "https://evil.example.net/", http.StatusFound)
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte("<h1>" + r.Host + r.URL.Path + "</h1>"))
		}
	}))
	defer site.Close()
	// любые имена ведут на локальный TLS-сервер; проверка адресов — TestMCPAddressGuard
	addr := strings.TrimPrefix(site.URL, "https://")
	k.srv.MCPTransport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, addr)
		}}
	fetch := func(tok, u string) (int, string) {
		return k.do("GET", "/egress/fetch?url="+url.QueryEscape(u), tok, nil, nil)
	}
	set := func(domains ...string) SignedAction {
		ds := []any{}
		for _, d := range domains {
			ds = append(ds, d)
		}
		return k.anna.sign(t, k, map[string]any{"type": "egress_set", "domains": ds}, nil)
	}

	st, b := fetch("tok-anna", "https://docs.example.com/page")
	c.ok("X1 без списка — отказ", st == 403 && strings.Contains(b, "нет в списке"), st, b)
	st, _ = k.do("POST", "/v1/egress", "tok-anna", j(set("docs.example.com")), nil)
	c.ok("X2 список меняет только control-plane", st == 403, st)
	for _, bad := range [][]string{{"Docs.Example.com"}, {"*.example.com"}, {"10.0.0.1"}, {"localhost"}, {"a.com", "a.com"}} {
		st, b = k.do("POST", "/v1/egress", "tok-cp", j(set(bad...)), nil)
		c.ok("X3 недопустимый список отклонён схемой: "+strings.Join(bad, ","), st == 403, st, b)
	}
	st, b = k.do("POST", "/v1/egress", "tok-cp", j(set("docs.example.com", "api.example.org")), nil)
	c.ok("X4 список задан подписью", st == 200 && strings.Contains(b, `"api.example.org","docs.example.com"`), st, b)
	st, b = k.do("POST", "/v1/egress/list", "tok-cp", j(map[string]string{"user": "anna"}), nil)
	c.ok("X5 control-plane видит список", st == 200 && strings.Contains(b, "docs.example.com"), st, b)
	st, b = k.do("GET", "/v1/egress/mine", "tok-anna", nil, nil)
	c.ok("X6 пространство видит свой список", st == 200 && strings.Contains(b, "docs.example.com"), st, b)

	st, b = fetch("tok-anna", "https://docs.example.com/page")
	c.ok("X7 страница с разрешённого домена", st == 200 && strings.Contains(b, "docs.example.com/page"), st, b)
	st, b = fetch("tok-anna", "https://docs.example.com/moved")
	c.ok("X8 перенаправление внутри списка выполняется", st == 200 && strings.Contains(b, "/page"), st, b)
	st, b = fetch("tok-anna", "https://docs.example.com/away")
	c.ok("X9 перенаправление на чужой домен — отказ", st == 502 && strings.Contains(b, "вне списка"), st, b)
	for _, bad := range []string{"https://evil.example.net/", "http://docs.example.com/", "https://docs.example.com:8443/",
		"https://user@docs.example.com/", "https://sub.docs.example.com/", "https://127.0.0.1/"} {
		st, b = fetch("tok-anna", bad)
		c.ok("X10 недопустимый адрес: "+bad, st == 403, st, b)
	}
	st, _ = fetch("tok-bob", "https://docs.example.com/page")
	c.ok("X11 чужой список не действует", st == 403, st)
	st, _ = fetch("tok-shop", "https://docs.example.com/page")
	c.ok("X12 общее пространство — отказ", st == 403, st)
	st, _ = k.do("POST", "/egress/fetch?url="+url.QueryEscape("https://docs.example.com/page"), "tok-anna", nil, nil)
	c.ok("X13 только GET", st == 405, st)
	st, _ = k.do("POST", "/v1/egress", "tok-cp", j(set()), nil)
	st2, _ := fetch("tok-anna", "https://docs.example.com/page")
	c.ok("X14 пустой список — доступ закрыт", st == 200 && st2 == 403, st, st2)
	if c.f > 0 {
		t.Fatalf("%d проверок не прошли", c.f)
	}
}

// Тариф длинного контекста: запрос с входом больше LongAbove — целиком по длинной ставке (Ultra: 272K, $10/$45).
func TestPriceRates(t *testing.T) {
	p := Price{InPerM: 5, OutPerM: 30, LongAbove: 272_000, LongIn: 10, LongOut: 45}
	for _, c := range []struct {
		in       int64
		in_, out float64
	}{{1000, 5, 30}, {272_000, 5, 30}, {272_001, 10, 45}} {
		if i, o := p.rates(c.in); i != c.in_ || o != c.out {
			t.Errorf("rates(%d) = %v/%v, ждали %v/%v", c.in, i, o, c.in_, c.out)
		}
	}
	if i, o := (Price{InPerM: 2, OutPerM: 6}).rates(1 << 30); i != 2 || o != 6 {
		t.Errorf("без длинного тарифа ставка одна: %v/%v", i, o)
	}
}
