package keyguard

// Git-прокси: /git/github/<путь API>, /git/gitlab/api/v4/<путь>. Пространство предъявляет свой токен (как ключ
// API своему SDK), keyguard подставляет токен владельца (или спонсора по разрешению с моделью "git").
//
// Белый список «метод + путь» — ровно вызовы бэкенда пространства (backend/app/tools/providers.py).
// TestGitRulesCoverBackend сверяет список с этим файлом: новый вызов бэкенда без правила здесь — провал теста.
// Взломанное пространство (prompt injection) НЕ может: удалить репозиторий, добавить deploy-ключ, webhook,
// соавтора, прочитать секреты Actions, сменить защиту ветки, сделать force-push.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type gitRule struct {
	method string
	re     *regexp.Regexp
}

const seg = `[^/]+`

func rules(spec [][2]string) []gitRule {
	out := make([]gitRule, 0, len(spec))
	for _, r := range spec {
		p := strings.NewReplacer("{S}", seg, "{R}", seg+"/"+seg).Replace(r[1])
		out = append(out, gitRule{r[0], regexp.MustCompile("^" + p + "$")})
	}
	return out
}

var githubRules = rules([][2]string{
	{"GET", "/user"}, {"GET", "/user/repos"}, {"GET", "/search/repositories"}, {"GET", "/search/code"},
	{"GET", "/repos/{R}"}, {"GET", "/repos/{R}/branches"}, {"GET", "/repos/{R}/actions/runs"},
	{"GET", "/repos/{R}/commits/{S}"}, {"GET", "/repos/{R}/compare/{S}"}, {"GET", "/repos/{R}/git/commits/{S}"}, {"GET", "/repos/{R}/git/trees/{S}"},
	{"GET", "/repos/{R}/git/ref/heads/.+"},
	{"GET", "/repos/{R}/contents/.+"}, {"PUT", "/repos/{R}/contents/.+"},
	{"POST", "/user/repos"}, {"POST", "/orgs/{S}/repos"},
	{"POST", "/repos/{R}/git/blobs"}, {"POST", "/repos/{R}/git/trees"}, {"POST", "/repos/{R}/git/commits"},
	{"POST", "/repos/{R}/git/refs"}, {"PATCH", "/repos/{R}/git/refs/heads/.+"}, {"POST", "/repos/{R}/pulls"},
})

var gitlabRules = rules([][2]string{
	{"GET", "/api/v4/user"}, {"GET", "/api/v4/projects"}, {"GET", "/api/v4/namespaces/{S}"},
	{"GET", "/api/v4/projects/{S}"}, {"GET", "/api/v4/projects/{S}/pipelines"}, {"GET", "/api/v4/projects/{S}/search"},
	{"GET", "/api/v4/projects/{S}/repository/branches"}, {"GET", "/api/v4/projects/{S}/repository/tree"},
	{"GET", "/api/v4/projects/{S}/repository/files/{S}/raw"}, {"HEAD", "/api/v4/projects/{S}/repository/files/{S}"},
	{"GET", "/api/v4/projects/{S}/repository/branches/{S}"}, {"GET", "/api/v4/projects/{S}/repository/compare"},
	{"POST", "/api/v4/projects"}, {"POST", "/api/v4/projects/{S}/merge_requests"},
	{"POST", "/api/v4/projects/{S}/repository/branches"}, {"POST", "/api/v4/projects/{S}/repository/commits"},
})

// safeEscapedPath: каждый сегмент (и части закодированного %2F внутри него) не "." и не "..".
func safeEscapedPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "//") || strings.ContainsAny(p, "\\") {
		return false
	}
	for _, sg := range strings.Split(p[1:], "/") {
		d, err := url.PathUnescape(sg)
		if err != nil || d == "" {
			return false
		}
		for _, part := range strings.Split(strings.ReplaceAll(d, "\\", "/"), "/") {
			if part == "." || part == ".." {
				return false
			}
		}
	}
	return true
}

func allowed(rs []gitRule, method, p string) bool {
	for _, r := range rs {
		if r.method == method && r.re.MatchString(p) {
			return true
		}
	}
	return false
}

var gitForward = []string{"Accept", "Content-Type", "X-Github-Api-Version"}

func (s *Server) handleGit(w http.ResponseWriter, r *http.Request) {
	esc := r.URL.EscapedPath()
	rest := strings.TrimPrefix(esc, "/git/")
	name, path, _ := strings.Cut(rest, "/")
	p := s.Providers[name]
	if p == nil || p.Kind != "git" {
		fail(w, 404, "нет такого провайдера")
		return
	}
	path = "/" + path
	if !safeEscapedPath(path) || !allowed(p.GitRules, r.Method, path) {
		s.Log.Printf("event=git.denied provider=%s method=%s path=%q", name, r.Method, path)
		fail(w, 403, "вызов не разрешён для агента")
		return
	}
	c, err := s.caller(r)
	if err != nil {
		fail(w, 401, "не опознан")
		return
	}
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	if r.Method == "PATCH" && len(body) > 0 { // force-push запрещён: бэкенд его не использует
		m, err := ParseStrict(body, true)
		if err != nil {
			fail(w, 400, "тело: "+err.Error())
			return
		}
		if f, _ := m["force"].(bool); f {
			fail(w, 403, "force-push запрещён")
			return
		}
		body = Canonical(m)
	}
	var user string
	switch {
	case strings.HasPrefix(c.Namespace, "deck-u-"):
		user = strings.TrimPrefix(c.Namespace, "deck-u-")
	case strings.HasPrefix(c.Namespace, "deck-t-"):
		space := strings.TrimPrefix(c.Namespace, "deck-")
		g, ok := s.Grants.Find(space, r.Header.Get("X-Deck-Chat"), name, "git", s.Now())
		if !ok || !contains(g.Members, r.Header.Get("X-Deck-Member")) {
			fail(w, 403, "нет разрешения спонсора на Git в этом чате")
			return
		}
		user = g.Sponsor
	default:
		fail(w, 403, "только пространства")
		return
	}
	key, err := s.Store.Get(r.Context(), user, name)
	if err != nil {
		fail(w, 409, "токен не задан")
		return
	}
	target := p.BaseURL + path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	up, err := http.NewRequestWithContext(r.Context(), r.Method, target, bytes.NewReader(body))
	if err != nil {
		fail(w, 400, "адрес")
		return
	}
	up.URL.RawPath = path // закодированные %2F (ветки, ID проектов GitLab) уходят как есть
	for _, h := range gitForward {
		if v := r.Header.Get(h); v != "" {
			up.Header.Set(h, v)
		}
	}
	setAuth(up, p, key)
	resp, err := s.gitClient().Do(up)
	if err != nil {
		fail(w, 502, "провайдер недоступен")
		return
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	for _, h := range []string{"Content-Type", "Link", "X-Total", "X-Next-Page"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(bytes.ReplaceAll(b, []byte(key), []byte("[redacted]")))
	s.Log.Printf("event=git ns=%s payer=%s provider=%s method=%s status=%d", c.Namespace, user, name, r.Method, resp.StatusCode)
}

// gitClient — без следования редиректам: Location отдаётся пространству как есть, токен на чужой хост не уходит.
func (s *Server) gitClient() *http.Client {
	c := *s.Upstream
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

var _ = json.Marshal
