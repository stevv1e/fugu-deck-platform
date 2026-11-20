package keyguard

// Google Drive: refresh token остаётся в OpenBao, access token живёт только в памяти keyguard.
// GET читает файлы и экспортирует Google Docs/Sheets/Slides; POST только создаёт новый файл или папку.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type driveAccess struct {
	Token   string
	Expires time.Time
}

var driveFileID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,200}$`)

func GoogleDriveProvider(base, clientID, clientSecret, redirect string) *Provider {
	return &Provider{Name: "google_drive", BaseURL: strings.TrimRight(base, "/"), ProbePath: "/drive/v3/about",
		AuthHeader: "authorization", Kind: "drive", OAuthClientID: clientID, OAuthClientSecret: clientSecret, OAuthRedirect: redirect}
}

func driveTokenURL(p *Provider) string {
	if p.OAuthTokenURL != "" {
		return p.OAuthTokenURL
	}
	return "https://oauth2.googleapis.com/token"
}

func (s *Server) driveAccessToken(ctx context.Context, p *Provider, refresh string) (string, error) {
	h := sha256.Sum256([]byte(refresh))
	key := hex.EncodeToString(h[:])
	s.driveMu.Lock()
	defer s.driveMu.Unlock()
	if got, ok := s.driveTokens[key]; ok && got.Expires.After(s.Now().Add(5*time.Minute)) {
		return got.Token, nil
	}
	if p.OAuthClientID == "" || p.OAuthClientSecret == "" {
		return "", errors.New("Google OAuth client не настроен")
	}
	form := url.Values{"client_id": {p.OAuthClientID}, "client_secret": {p.OAuthClientSecret},
		"refresh_token": {refresh}, "grant_type": {"refresh_token"}}
	req, _ := http.NewRequestWithContext(ctx, "POST", driveTokenURL(p), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.Upstream.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(raw, &out) != nil || out.AccessToken == "" || out.ExpiresIn <= 0 {
		return "", errors.New("Google отклонил refresh token")
	}
	if s.driveTokens == nil {
		s.driveTokens = map[string]driveAccess{}
	}
	got := driveAccess{Token: out.AccessToken, Expires: s.Now().Add(time.Duration(out.ExpiresIn) * time.Second)}
	s.driveTokens[key] = got
	if len(s.driveTokens) > 100 {
		s.driveTokens = map[string]driveAccess{key: got}
	}
	return got.Token, nil
}

func driveUpstream(path string, query url.Values) (string, error) {
	parts := strings.Split(strings.TrimPrefix(path, "/drive/"), "/")
	switch {
	case len(parts) == 1 && parts[0] == "files":
	case len(parts) == 2 && parts[0] == "files" && driveFileID.MatchString(parts[1]):
	case len(parts) == 3 && parts[0] == "files" && driveFileID.MatchString(parts[1]) && parts[2] == "export":
	default:
		return "", errors.New("путь Drive не разрешён")
	}
	allowed := map[string]bool{"fields": true, "q": true, "pageSize": true, "pageToken": true, "orderBy": true,
		"spaces": true, "includeItemsFromAllDrives": true, "supportsAllDrives": true, "corpora": true, "driveId": true,
		"alt": true, "mimeType": true}
	for k := range query {
		if !allowed[k] {
			return "", fmt.Errorf("параметр Drive %q не разрешён", k)
		}
	}
	if query.Get("alt") != "" && query.Get("alt") != "media" {
		return "", errors.New("alt разрешён только media")
	}
	if n := query.Get("pageSize"); n != "" {
		v, err := strconv.Atoi(n)
		if err != nil || v < 1 || v > 100 {
			return "", errors.New("pageSize: 1..100")
		}
	}
	return "/drive/v3/" + strings.Join(parts, "/"), nil
}

const maxDriveUpload = 512 << 20
const maxDriveFolderBody = 16 << 10

func checkDriveFolder(body []byte) error {
	meta, err := ParseStrict(body, true)
	if err != nil {
		return err
	}
	for k := range meta {
		if k != "name" && k != "mimeType" && k != "parents" {
			return fmt.Errorf("поле Drive %q не разрешено", k)
		}
	}
	name, ok := meta["name"].(string)
	if !ok || strings.TrimSpace(name) == "" || len([]rune(name)) > 120 {
		return errors.New("название папки: 1..120 символов")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return errors.New("управляющие символы в названии запрещены")
		}
	}
	if meta["mimeType"] != "application/vnd.google-apps.folder" {
		return errors.New("разрешено только создание папки")
	}
	if raw, exists := meta["parents"]; exists {
		parents, ok := raw.([]any)
		if !ok || len(parents) != 1 {
			return errors.New("нужна одна родительская папка")
		}
		parent, ok := parents[0].(string)
		if !ok || !driveFileID.MatchString(parent) {
			return errors.New("некорректный ID родительской папки")
		}
	}
	return nil
}

func (s *Server) handleDrive(w http.ResponseWriter, r *http.Request) {
	upload := r.URL.Path == "/drive/upload/files"
	create := r.URL.Path == "/drive/files" && r.Method == http.MethodPost
	if r.Method != http.MethodGet && !(upload && r.Method == http.MethodPost) && !create {
		fail(w, 405, "GET, POST /drive/upload/files или POST /drive/files")
		return
	}
	c, err := s.caller(r)
	if err != nil || !strings.HasPrefix(c.Namespace, "deck-u-") {
		fail(w, 403, "Drive доступен из личного пространства")
		return
	}
	p := s.Providers["google_drive"]
	if p == nil {
		fail(w, 404, "Drive не настроен")
		return
	}
	path := ""
	var body io.Reader
	switch {
	case upload:
		if r.ContentLength <= 0 || r.ContentLength > maxDriveUpload {
			fail(w, 413, "нужен известный размер загрузки до 512 МБ")
			return
		}
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "multipart/related" || r.URL.Query().Get("uploadType") != "multipart" {
			fail(w, 400, "нужен multipart/related и uploadType=multipart")
			return
		}
		for k := range r.URL.Query() {
			if k != "uploadType" && k != "fields" && k != "supportsAllDrives" {
				fail(w, 400, "параметр загрузки Drive не разрешён")
				return
			}
		}
		path = "/upload/drive/v3/files"
		body = http.MaxBytesReader(w, r.Body, maxDriveUpload)
	case create:
		if r.ContentLength <= 0 || r.ContentLength > maxDriveFolderBody {
			fail(w, 413, "нужен известный размер метаданных до 16 КБ")
			return
		}
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			fail(w, 400, "нужен application/json")
			return
		}
		for k := range r.URL.Query() {
			if k != "fields" && k != "supportsAllDrives" {
				fail(w, 400, "параметр создания папки не разрешён")
				return
			}
		}
		raw, ok := s.readBody(w, r)
		if !ok {
			return
		}
		if err := checkDriveFolder(raw); err != nil {
			fail(w, 400, err.Error())
			return
		}
		path = "/drive/v3/files"
		body = bytes.NewReader(raw)
	default:
		path, err = driveUpstream(r.URL.Path, r.URL.Query())
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
	}
	user := strings.TrimPrefix(c.Namespace, "deck-u-")
	refresh, err := s.Store.Get(r.Context(), user, "google_drive")
	if err != nil {
		fail(w, 409, "Google Drive не подключён")
		return
	}
	access, err := s.driveAccessToken(r.Context(), p, refresh)
	if err != nil {
		fail(w, 502, "не удалось обновить OAuth token")
		return
	}
	up, _ := http.NewRequestWithContext(r.Context(), r.Method, p.BaseURL+path+"?"+r.URL.Query().Encode(), body)
	up.Header.Set("Authorization", "Bearer "+access)
	if upload || create {
		up.Header.Set("Content-Type", r.Header.Get("Content-Type"))
		up.ContentLength = r.ContentLength
	}
	resp, err := s.Upstream.Do(up)
	if err != nil {
		fail(w, 502, "Google Drive недоступен")
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	if resp.Header.Get("Content-Length") != "" {
		w.Header().Set("Content-Length", resp.Header.Get("Content-Length"))
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	s.Log.Printf("event=drive ns=%s user=%s method=%s status=%d", logNS(c.Namespace), uid(user), r.Method, resp.StatusCode)
}
