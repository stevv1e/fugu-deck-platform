package keyguard

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Белый список git-прокси обязан покрывать все вызовы бэкенда пространства. Однажды он отстал: бэкенд читал ветку
// (GET …/git/ref/heads/<ветка>) в обход своего _req, правила для этого не было — агент получал 403 на любую запись.
// Тест читает вызовы прямо из providers.py, поэтому новый вызов без правила проваливает сборку, а не работу агента.
func TestGitRulesCoverBackend(t *testing.T) {
	const src = "../fugu-deck-app/backend/app/tools/providers.py"
	raw, err := os.ReadFile(src)
	if err != nil {
		if os.Getenv("CI") != "" && os.Getenv("DECK_IMAGE_BUILD") == "" {
			t.Fatalf("нет %s: %v", src, err)
		}
		t.Skipf("нет %s (сборка вне монорепозитория)", src)
	}
	gh, gl, ok := strings.Cut(string(raw), "class GitLabProvider")
	if !ok {
		t.Fatal("в providers.py не найден class GitLabProvider")
	}
	call := regexp.MustCompile(`(?:_req\(\s*"([A-Z]+)",\s*|self\.http\.(get|head|post|put|patch|delete)\(\s*)f?"(/[^"]*)"`)
	hole := regexp.MustCompile(`\{[^{}]*\}`)
	check := func(text, prefix, repo string, rs []gitRule) (n int) {
		for _, m := range call.FindAllStringSubmatch(text, -1) {
			method := m[1]
			if method == "" {
				method = strings.ToUpper(m[2])
			}
			path := prefix + hole.ReplaceAllStringFunc(m[3], func(h string) string {
				if strings.Contains(h, "repo") {
					return repo
				}
				return "x"
			})
			n++
			if !safeEscapedPath(path) || !allowed(rs, method, path) {
				t.Errorf("вызов бэкенда не разрешён в keyguard: %s %s (в коде: %s)", method, path, m[3])
			}
		}
		return n
	}
	// Адрес создания репозитория бэкенд собирает в переменную — эти два вызова регулярное выражение не видит.
	for _, p := range []string{"/user/repos", "/orgs/acme/repos"} {
		if !allowed(githubRules, "POST", p) {
			t.Errorf("вызов бэкенда не разрешён в keyguard: POST %s", p)
		}
	}
	nGH := check(gh, "", "anna/demo", githubRules)
	nGL := check(gl, "/api/v4", "anna%2Fdemo", gitlabRules)
	// Если разбор перестал находить вызовы (бэкенд переписан иначе), тест не должен молча проходить.
	if nGH < 18 || nGL < 13 {
		t.Fatalf("найдено вызовов: GitHub %d, GitLab %d — меньше, чем было; обновите разбор в этом тесте", nGH, nGL)
	}
}
