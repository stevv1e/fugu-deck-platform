package keyguard

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type gitSeen struct {
	method, rawPath, query, auth, privTok, body string
}

func TestAttack_GitProxy(t *testing.T) {
	k := newRig(t)
	c := &check{t: t}
	var got []gitSeen
	evilHits := 0
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { evilHits++ }))
	defer evil.Close()
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, gitSeen{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, r.Header.Get("Authorization"), r.Header.Get("PRIVATE-TOKEN"), string(b)})
		switch {
		case r.URL.Path == "/user" && r.Header.Get("Authorization") == "Bearer ghp_ANNA_0123456789":
			w.Write([]byte(`{"login":"anna"}`))
		case r.URL.Path == "/api/v4/user" && r.Header.Get("PRIVATE-TOKEN") == "glpat-ANNA-0123456789":
			w.Write([]byte(`{"username":"anna"}`))
		case strings.HasSuffix(r.URL.Path, "/redirect-me"):
			http.Redirect(w, r, evil.URL+"/steal", 302)
		case strings.Contains(r.URL.Path, "/echo"):
			fmt.Fprintf(w, `{"debug":"%s"}`, r.Header.Get("Authorization"))
		default:
			w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer gh.Close()
	k.srv.Providers["github"] = GitHubProvider(gh.URL)
	k.srv.Providers["gitlab"] = GitLabProvider(gh.URL)
	k.srv.Store.Put(nil, "anna", "github", "ghp_ANNA_0123456789")
	k.srv.Store.Put(nil, "anna", "gitlab", "glpat-ANNA-0123456789")
	k.srv.Store.Put(nil, "bob", "github", "ghp_BOB_0123456789")
	last := func() gitSeen {
		if len(got) == 0 {
			return gitSeen{}
		}
		return got[len(got)-1]
	}
	req := func(method, path, tok, body string, hdr map[string]string) (int, string) {
		r, _ := http.NewRequest(method, k.ts.URL+path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+tok)
		for a, b := range hdr {
			r.Header.Set(a, b)
		}
		noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := noRedirect.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}

	st, _ := req("GET", "/git/github/user", "tok-anna", "", nil)
	c.ok("G1 GitHub: /user с токеном Анны (пространство не видит токен)", st == 200 && last().auth == "Bearer ghp_ANNA_0123456789", st, last().auth)
	st, _ = req("GET", "/git/github/repos/anna/demo/commits/feature%2Fx", "tok-anna", "", nil)
	c.ok("G2 закодированная ветка feature%2Fx уходит как есть", st == 200 && last().rawPath == "/repos/anna/demo/commits/feature%2Fx", last().rawPath)
	st, _ = req("GET", "/git/github/search/repositories?q=user%3Aanna&per_page=5", "tok-anna", "", nil)
	c.ok("G3 параметры запроса передаются", st == 200 && last().query == "q=user%3Aanna&per_page=5", last().query)
	st, _ = req("GET", "/git/gitlab/api/v4/projects/anna%2Fdemo/repository/files/src%2Fmain.py/raw?ref=main", "tok-anna", "", nil)
	c.ok("G4 GitLab: PRIVATE-TOKEN, ID проекта anna%2Fdemo как есть", st == 200 && last().privTok == "glpat-ANNA-0123456789" &&
		last().rawPath == "/api/v4/projects/anna%2Fdemo/repository/files/src%2Fmain.py/raw" && last().auth == "", last())
	st, _ = req("PATCH", "/git/github/repos/anna/demo/git/refs/heads/feature/x", "tok-anna", `{"sha":"abc"}`, nil)
	c.ok("G5 обновление ветки без force — проходит", st == 200, st)

	n0 := len(got)
	deny := []struct{ m, p, why string }{
		{"DELETE", "/git/github/repos/anna/demo", "удаление репозитория"},
		{"POST", "/git/github/repos/anna/demo/keys", "deploy-ключ"},
		{"POST", "/git/github/repos/anna/demo/hooks", "webhook"},
		{"PUT", "/git/github/repos/anna/demo/collaborators/mallory", "соавтор"},
		{"GET", "/git/github/repos/anna/demo/actions/secrets", "секреты Actions"},
		{"PUT", "/git/github/repos/anna/demo/branches/main/protection", "защита ветки"},
		{"PATCH", "/git/github/repos/anna/demo", "настройки репозитория (сделать публичным)"},
		{"POST", "/git/github/user/keys", "SSH-ключ в аккаунт"},
		{"GET", "/git/github/user/emails", "почта аккаунта"},
		{"GET", "/git/github/repos/anna/demo/contents/a/../../../user/keys", "обход ../"},
		{"GET", "/git/github/repos/anna/demo/commits/..%2F..%2F..%2Fuser%2Fkeys", "обход через %2F"},
		{"GET", "/git/github/repos/anna/demo/commits/%2e%2e%2f%2e%2e", "обход через %2e"},
		{"GET", "/git/github//user", "двойной слэш"},
		{"GET", "/git/github/repos/anna/demo/contents/a%5c..%5c..%5cuser", "обход через обратный слэш"},
		{"DELETE", "/git/gitlab/api/v4/projects/anna%2Fdemo", "удаление проекта GitLab"},
		{"POST", "/git/gitlab/api/v4/projects/anna%2Fdemo/deploy_keys", "deploy-ключ GitLab"},
		{"GET", "/git/gitlab/api/v4/projects/anna%2Fdemo/variables", "переменные CI GitLab"},
		{"GET", "/git/evil/user", "неизвестный провайдер"},
		{"GET", "/git/anthropic/v1/messages", "провайдер-модель через Git-прокси"},
	}
	for _, d := range deny {
		st, _ := req(d.m, d.p, "tok-anna", "{}", nil)
		// 403/404 — отказ keyguard; 301 — нормализация пути маршрутизатором (повторный запрос снова проверяется белым списком)
		c.ok("G6 запрещено: "+d.why, st == 403 || st == 404 || st == 301, st)
	}
	c.ok("G7 ни один запрещённый вызов не дошёл до провайдера", len(got) == n0, len(got)-n0)
	for _, p := range []string{"/git/github/repos/anna/demo/../../../user/keys", "/git/github//user/keys"} {
		n1 := len(got)
		r, _ := http.NewRequest("POST", k.ts.URL+p, strings.NewReader("{}"))
		r.Header.Set("Authorization", "Bearer tok-anna")
		resp, _ := http.DefaultClient.Do(r) // клиент, который ИДЁТ по редиректу нормализации
		if resp != nil {
			resp.Body.Close()
		}
		c.ok("G7b после нормализации "+p+" → /user/keys всё равно запрещён", resp != nil && resp.StatusCode != 200 && len(got) == n1, resp.StatusCode)
	}

	st, body := req("PATCH", "/git/github/repos/anna/demo/git/refs/heads/main", "tok-anna", `{"sha":"abc","force":true}`, nil)
	c.ok("G8 force-push запрещён", st == 403 && strings.Contains(body, "force"), st)
	st, _ = req("PATCH", "/git/github/repos/anna/demo/git/refs/heads/main", "tok-anna", `{"sha":"abc","force":false,"force":true}`, nil)
	c.ok("G9 force через дубликат ключа отклонён", st == 400, st)

	st, body = req("GET", "/git/github/repos/anna/demo/contents/redirect-me", "tok-anna", "", nil)
	c.ok("G10 редирект провайдера не выполняется — токен не уходит на чужой хост", st == 302 && evilHits == 0, st, evilHits)
	st, body = req("GET", "/git/github/repos/anna/demo/contents/echo", "tok-anna", "", nil)
	c.ok("G11 токен в ответе провайдера вычищен", !strings.Contains(body, "ghp_ANNA") && strings.Contains(body, "[redacted]"), body)

	st, _ = req("GET", "/git/github/user", "", "", nil)
	c.ok("G12 без токена пространства — 401", st == 401, st)
	st, _ = req("GET", "/git/github/user", "tok-random", "", nil)
	c.ok("G13 не пространство — 403", st == 403, st)
	st, _ = req("GET", "/git/github/user", "tok-bob", "", nil)
	c.ok("G14 пространство Боба получает токен Боба, а не Анны", st == 200 && last().auth == "Bearer ghp_BOB_0123456789", last().auth)

	// общее пространство: только по разрешению спонсора с моделью "git"
	c.ok("G15 общее пространство без разрешения — 403", func() bool {
		st, _ := req("GET", "/git/github/user", "tok-shop", "", map[string]string{"X-Deck-Chat": "c-1", "X-Deck-Member": "bob"})
		return st == 403
	}())
	until := k.now().Add(24 * time.Hour).Format("2006-01-02")
	gst, gbody := k.do("POST", "/v1/grants", "tok-cp", j(k.anna.sign(t, k, map[string]any{"type": "grant", "space": "t-shop", "chat": "c-1",
		"provider": "github", "model": "git", "limit_usd": json.Number("1"), "limit_tokens": nil, "until": until,
		"key_until": until, "per_member_usd_day": nil, "members": []any{"bob"}, "proposal": "p-git"}, nil)), nil)
	var gr map[string]string
	json.Unmarshal([]byte(gbody), &gr)
	k.do("POST", "/v1/grants/activate", "tok-shop", j(map[string]string{"grant_id": gr["grant_id"]}), nil)
	st, _ = req("GET", "/git/github/user", "tok-shop", "", map[string]string{"X-Deck-Chat": "c-1", "X-Deck-Member": "bob"})
	c.ok("G16 по разрешению Анны Боб в общем пространстве работает с её токеном", gst == 200 && st == 200 && last().auth == "Bearer ghp_ANNA_0123456789", gst, st)
	st, _ = req("GET", "/git/github/user", "tok-shop", "", map[string]string{"X-Deck-Chat": "c-1", "X-Deck-Member": "mallory"})
	c.ok("G17 не-участник — 403", st == 403, st)
	gst, _ = k.do("POST", "/v1/grants", "tok-cp", j(k.anna.sign(t, k, map[string]any{"type": "grant", "space": "t-shop", "chat": "c-1",
		"provider": "github", "model": "claude-x", "limit_usd": json.Number("1"), "limit_tokens": nil, "until": until,
		"key_until": until, "per_member_usd_day": nil, "members": []any{"bob"}, "proposal": "p-git"}, nil)), nil)
	c.ok("G18 разрешение на Git с моделью не \"git\" отклонено схемой", gst == 403, gst)

	// ввод токена GitHub через телефон: пробный запрос /user с правильным заголовком
	r, _ := k.sealedKeyPut(k.anna, "github", "ghp_ANNA_0123456789", nil)
	st, _ = k.do("POST", "/v1/keys", "tok-cp", j(r), nil)
	c.ok("G19 ввод токена GitHub: проверен запросом /user", st == 200 && last().rawPath == "/user", st)
	r, _ = k.sealedKeyPut(k.anna, "gitlab", "glpat-ANNA-0123456789", nil)
	st, _ = k.do("POST", "/v1/keys", "tok-cp", j(r), nil)
	c.ok("G20 ввод токена GitLab: проверен /api/v4/user с PRIVATE-TOKEN", st == 200 && last().privTok == "glpat-ANNA-0123456789", st)
	t.Logf("Git-прокси: %d/%d", c.n, c.n+c.f)
}
