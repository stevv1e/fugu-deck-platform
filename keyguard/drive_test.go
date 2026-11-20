package keyguard

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDriveUpstreamAllowlist(t *testing.T) {
	for _, path := range []string{"/drive/files", "/drive/files/file-123", "/drive/files/file-123/export"} {
		if _, err := driveUpstream(path, url.Values{"fields": {"id,name"}, "supportsAllDrives": {"true"}}); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	for _, path := range []string{"/drive/about", "/drive/files/../about", "/drive/files/file/delete"} {
		if _, err := driveUpstream(path, nil); err == nil {
			t.Fatalf("путь принят: %s", path)
		}
	}
	if _, err := driveUpstream("/drive/files", url.Values{"pageSize": {"1000"}}); err == nil {
		t.Fatal("большой pageSize принят")
	}
	if _, err := driveUpstream("/drive/files/file-123", url.Values{"alt": {"other"}}); err == nil {
		t.Fatal("неизвестный alt принят")
	}
}

func TestDriveUploadCreatesFile(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			io.WriteString(w, `{"access_token":"access","expires_in":3600}`)
		case "/upload/drive/v3/files":
			if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer access" || r.URL.Query().Get("uploadType") != "multipart" {
				t.Error("неверный запрос загрузки Drive")
			}
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"name":"voice.ogg"`) || !strings.Contains(string(body), "audio-data") {
				t.Error("multipart загрузка повреждена")
			}
			io.WriteString(w, `{"id":"file-1","name":"voice.ogg"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer up.Close()
	store := NewMemStore()
	if err := store.Put(nil, "anna", "google_drive", "refresh"); err != nil {
		t.Fatal(err)
	}
	s := &Server{Providers: map[string]*Provider{"google_drive": {BaseURL: up.URL, OAuthClientID: "id", OAuthClientSecret: "secret", OAuthTokenURL: up.URL + "/token"}},
		Store: store, Auth: StaticAuth{"tok": {Namespace: "deck-u-anna"}}, Upstream: up.Client(),
		Log: log.New(io.Discard, "", 0), Now: time.Now, MaxBody: 1 << 20}
	body := "--x\r\nContent-Type: application/json\r\n\r\n{\"name\":\"voice.ogg\"}\r\n--x\r\nContent-Type: audio/ogg\r\n\r\naudio-data\r\n--x--\r\n"
	r := httptest.NewRequest("POST", "/drive/upload/files?uploadType=multipart&fields=id,name", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer tok")
	r.Header.Set("Content-Type", "multipart/related; boundary=x")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "file-1") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestDriveCreateFolder(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			io.WriteString(w, `{"access_token":"access","expires_in":3600}`)
		case "/drive/v3/files":
			if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer access" || r.URL.Query().Get("supportsAllDrives") != "true" {
				t.Error("неверный запрос создания папки")
			}
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"name":"Проекты"`) || !strings.Contains(string(body), `"parents":["folder-1"]`) {
				t.Errorf("метаданные папки повреждены: %s", body)
			}
			io.WriteString(w, `{"id":"folder-2","name":"Проекты","mimeType":"application/vnd.google-apps.folder"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer up.Close()
	store := NewMemStore()
	if err := store.Put(nil, "anna", "google_drive", "refresh"); err != nil {
		t.Fatal(err)
	}
	s := &Server{Providers: map[string]*Provider{"google_drive": {BaseURL: up.URL, OAuthClientID: "id", OAuthClientSecret: "secret", OAuthTokenURL: up.URL + "/token"}},
		Store: store, Auth: StaticAuth{"tok": {Namespace: "deck-u-anna"}}, Upstream: up.Client(),
		Log: log.New(io.Discard, "", 0), Now: time.Now, MaxBody: 1 << 20}
	body := `{"name":"Проекты","mimeType":"application/vnd.google-apps.folder","parents":["folder-1"]}`
	r := httptest.NewRequest("POST", "/drive/files?fields=id,name,mimeType&supportsAllDrives=true", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer tok")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "folder-2") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestDriveFolderMetadataAllowlist(t *testing.T) {
	for _, body := range []string{
		`{"name":"Проекты","mimeType":"text/plain"}`,
		`{"name":"Проекты","mimeType":"application/vnd.google-apps.folder","trashed":true}`,
		`{"name":"Проекты","mimeType":"application/vnd.google-apps.folder","parents":["../other"]}`,
		`{"name":"","mimeType":"application/vnd.google-apps.folder"}`,
	} {
		if err := checkDriveFolder([]byte(body)); err == nil {
			t.Fatalf("метаданные приняты: %s", body)
		}
	}
}

func TestDriveRefreshRequiresOAuthClient(t *testing.T) {
	s := &Server{Now: time.Now}
	if _, err := s.driveAccessToken(context.Background(), &Provider{}, "refresh-token"); err == nil {
		t.Fatal("без OAuth client refresh принят")
	}
}

func TestDriveOAuthExchangeStoresRefreshToken(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ParseForm() != nil || r.Form.Get("code") != "code-123" || r.Form.Get("code_verifier") != "verifier-1234567890123456789012345678901234567890" {
			t.Error("неверный OAuth exchange")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"access","refresh_token":"refresh","expires_in":3600}`)
	}))
	defer up.Close()
	store := NewMemStore()
	caller := Caller{Namespace: "deck-system", ServiceAccount: "control-plane"}
	s := &Server{Providers: map[string]*Provider{"google_drive": {OAuthClientID: "id", OAuthClientSecret: "secret",
		OAuthRedirect: "https://api.example/callback", OAuthTokenURL: up.URL}}, Store: store,
		Auth: StaticAuth{"cp": caller}, ControlPlane: caller, Upstream: up.Client(), Log: log.New(io.Discard, "", 0), MaxBody: 1 << 20}
	r := httptest.NewRequest("POST", "/v1/drive/oauth/exchange", strings.NewReader(`{"user":"anna","code":"code-123","verifier":"verifier-1234567890123456789012345678901234567890"}`))
	r.Header.Set("Authorization", "Bearer cp")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if got, err := store.Get(nil, "anna", "google_drive"); err != nil || got != "refresh" {
		t.Fatalf("refresh token не сохранён: %v", err)
	}
}
