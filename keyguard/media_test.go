package keyguard

import (
	"bytes"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mediaTestServer(t *testing.T, provider string) (*Server, *httptest.Server) {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if provider == "openai" && (r.URL.Path != "/v1/audio/transcriptions" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")) {
			t.Error("неверный путь или авторизация OpenAI")
		}
		if provider == "google" && (r.URL.Path != "/v1beta/models/gemini-3.8-flash:generateContent" || r.Header.Get("x-goog-api-key") == "") {
			t.Error("неверный путь или авторизация Google")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"segments":[]}`)
	}))
	store := NewMemStore()
	if err := store.Put(nil, "anna", provider, "secret-key"); err != nil {
		t.Fatal(err)
	}
	s := &Server{Providers: map[string]*Provider{provider: {Name: provider, BaseURL: up.URL, AuthHeader: "authorization",
		MediaPerMinute: map[string]float64{"gpt-4o-transcribe-diarize": 0.01, "gemini-3.8-flash": 0.01}}},
		Store: store, Auth: StaticAuth{"tok": {Namespace: "deck-u-anna"}}, Ledger: NewLedger(), Upstream: up.Client(),
		Log: log.New(io.Discard, "", 0), Now: time.Now, MaxBody: maxMediaBody}
	t.Cleanup(up.Close)
	return s, up
}

func TestMediaTranscribeOpenAI(t *testing.T) {
	s, _ := mediaTestServer(t, "openai")
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	mw.WriteField("model", "gpt-4o-transcribe-diarize")
	mw.WriteField("response_format", "diarized_json")
	mw.WriteField("chunking_strategy", "auto")
	part, _ := mw.CreateFormFile("file", "voice.ogg")
	part.Write([]byte("audio"))
	mw.Close()
	r := httptest.NewRequest("POST", "/media/openai/audio/transcriptions", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("X-Deck-Media-Seconds", "60")
	r.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestMediaTranscribeGoogleAndRejectUnknownModel(t *testing.T) {
	s, _ := mediaTestServer(t, "google")
	r := httptest.NewRequest("POST", "/media/google/transcribe", strings.NewReader(`{"contents":[{"parts":[]}],"generationConfig":{"responseMimeType":"application/json","maxOutputTokens":16384,"responseSchema":{"type":"ARRAY","items":{"type":"OBJECT","properties":{"start":{"type":"NUMBER"},"end":{"type":"NUMBER"},"text":{"type":"STRING"},"speaker":{"type":"STRING"}},"required":["start","end","text"]}}}}`))
	r.Header.Set("X-Deck-Model", "gemini-3.8-flash")
	r.Header.Set("X-Deck-Media-Seconds", "30")
	r.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest("POST", "/media/google/transcribe", strings.NewReader(`{"contents":[]}`))
	r.Header.Set("X-Deck-Model", "unknown")
	r.Header.Set("X-Deck-Media-Seconds", "30")
	r.Header.Set("Authorization", "Bearer tok")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("неизвестная модель принята: %d", w.Code)
	}
}

func TestMediaTranscribeGoogleRejectsUnsafeGenerationConfig(t *testing.T) {
	for _, body := range []string{
		`{"contents":[{"parts":[]}],"generationConfig":{"responseMimeType":"application/json","maxOutputTokens":16385}}`,
		`{"contents":[{"parts":[]}],"generationConfig":{"responseMimeType":"application/json","maxOutputTokens":1.5}}`,
		`{"contents":[{"parts":[]}],"generationConfig":{"responseMimeType":"application/json","responseSchema":{"type":"OBJECT"}}}`,
	} {
		if err := checkTranscribeJSON([]byte(body)); err == nil {
			t.Fatalf("небезопасный generationConfig принят: %s", body)
		}
	}
}
