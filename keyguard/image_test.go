package keyguard

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestImageGenerate(t *testing.T) {
	for _, provider := range []string{"openai", "google"} {
		t.Run(provider, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if provider == "openai" {
					if r.URL.Path != "/v1/images/generations" || r.Header.Get("Authorization") != "Bearer secret" {
						t.Error("неверный путь или ключ OpenAI")
					}
					var body map[string]any
					json.NewDecoder(r.Body).Decode(&body)
					if body["safety_identifier"] == "" || body["model"] != "gpt-image-2.5-flare" {
						t.Error("неверное тело OpenAI")
					}
					io.WriteString(w, `{"data":[{"b64_json":"aGVsbG8="}],"usage":{"input_tokens":100,"output_tokens":1120}}`)
					return
				}
				if r.URL.Path != "/v1beta/interactions" || r.Header.Get("x-goog-api-key") != "secret" || r.Header.Get("Api-Revision") != "2026-05-20" {
					t.Error("неверный запрос Gemini Interactions")
				}
				io.WriteString(w, `{"output_image":{"mime_type":"image/png","data":"aGVsbG8="}}`)
			}))
			defer up.Close()
			store := NewMemStore()
			if err := store.Put(nil, "anna", provider, "secret"); err != nil {
				t.Fatal(err)
			}
			model := "gpt-image-2.5-flare"
			body := `{"model":"gpt-image-2.5-flare","prompt":"otter","n":1,"size":"1024x1024","quality":"low","output_format":"png"}`
			if provider == "google" {
				model = "gemini-3.1-flash-lite-image"
				body = `{"model":"gemini-3.1-flash-lite-image","input":[{"type":"text","text":"otter"}]}`
			}
			s := &Server{Providers: map[string]*Provider{provider: {Name: provider, BaseURL: up.URL, AuthHeader: "authorization",
				ImagePerImage: map[string]float64{model: 0.25}}}, Store: store, Auth: StaticAuth{"tok": {Namespace: "deck-u-anna"}},
				Ledger: NewLedger(), Upstream: up.Client(), Log: log.New(io.Discard, "", 0), Now: time.Now, MaxBody: 1 << 20}
			r := httptest.NewRequest("POST", "/media/"+provider+"/image", strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer tok")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != 200 || !strings.Contains(w.Body.String(), "aGVsbG8=") {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestImageRejectsUnknownField(t *testing.T) {
	if _, _, _, err := checkImageRequest("openai", []byte(`{"model":"x","prompt":"x","n":1,"size":"1024x1024","quality":"low","output_format":"png","url":"https://evil"}`)); err == nil {
		t.Fatal("произвольное поле принято")
	}
}
