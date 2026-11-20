package keyguard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProviderProxyClient(t *testing.T) {
	directHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		directHits++
	}))
	defer upstream.Close()
	proxyHits := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits++
		if r.URL.Host == "" {
			t.Error("proxy получил не абсолютный URL")
		}
	}))
	defer proxy.Close()

	client, err := NewProviderProxyClient(upstream.Client(), proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{Name: "sakana", BaseURL: upstream.URL, ProbePath: "/v1/models", HTTP: client}
	s := &Server{Upstream: upstream.Client()}
	if !s.probe(context.Background(), p, "test-key") {
		t.Fatal("проба через proxy отклонена")
	}
	if proxyHits != 1 || directHits != 0 {
		t.Fatalf("proxy=%d direct=%d", proxyHits, directHits)
	}
	if s.providerHTTP(&Provider{}) != s.Upstream {
		t.Fatal("провайдер без proxy должен использовать общий client")
	}
	if _, err := NewProviderProxyClient(upstream.Client(), "socks5://127.0.0.1:1080"); err == nil {
		t.Fatal("неподдерживаемая схема proxy принята")
	}
}
