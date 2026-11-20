package keyguard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeAuthHeader(t *testing.T) {
	var gotKey, gotAuthorization string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-goog-api-key")
		gotAuthorization = r.Header.Get("authorization")
	}))
	defer upstream.Close()

	s := &Server{Upstream: upstream.Client()}
	p := &Provider{BaseURL: upstream.URL, ProbePath: "/v1beta/models", ProbeAuthHeader: "x-goog-api-key", AuthHeader: "authorization"}
	if !s.probe(context.Background(), p, "test-key") {
		t.Fatal("проба с ответом 200 отклонена")
	}
	if gotKey != "test-key" || gotAuthorization != "" {
		t.Fatalf("неверные заголовки пробы: x-goog-api-key=%q authorization=%q", gotKey, gotAuthorization)
	}
}
