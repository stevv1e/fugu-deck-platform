package spaceoperator

import (
	"encoding/json"
	"strings"
	"testing"
)

const testKey = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEq1cLhqVJ0fYc2m9cJm1b1sQmF2m3o0m1X8l3p2sVQh5y\nS3mJm0pQy8a0b7z9bq0mXh4kH0ZkQx2P0J8m5bq1Yw==\n-----END PUBLIC KEY-----\n"

func TestCheck(t *testing.T) {
	ok := Space{Name: "anna", Owner: "anna", Kind: "personal", TokenKey: testKey}
	if err := ok.Check(); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*Space){
		"имя ≠ владелец":            func(s *Space) { s.Name = "bob" },
		"общее с именем-ником":      func(s *Space) { s.Kind = "team" },
		"общее с коротким id":       func(s *Space) { s.Kind, s.Name = "team", "t-ab" },
		"общее с именем как личное": func(s *Space) { s.Kind, s.Name = "team", "u-anna12" },
		"неизвестный вид":           func(s *Space) { s.Kind = "shared" },
		"нет ключа":                 func(s *Space) { s.TokenKey = "" },
		"мусор вместо ключа":        func(s *Space) { s.TokenKey = "ssh-rsa AAAA" },
		"ник с точкой":              func(s *Space) { s.Name, s.Owner = "a.b", "a.b" },
		"ник с заглавной":           func(s *Space) { s.Name, s.Owner = "Anna", "Anna" },
		"память в свободной форме":  func(s *Space) { s.Memory = "много" },
		"том с инъекцией":           func(s *Space) { s.Storage = "2Gi\"}" },
	} {
		s := ok
		edit(&s)
		if s.Check() == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

func TestRender(t *testing.T) {
	cfg := Config{SpaceImage: "img:1", RuntimeClass: "gvisor", KeyguardURL: "http://kg", SquidURL: "http://squid", SpaceDNS: "10.43.0.53", StorageClass: "local-path"}
	objs := Render(Space{Name: "anna", Owner: "anna", Kind: "personal", TokenKey: testKey}, cfg)
	raw, _ := json.Marshal(objs)
	js := string(raw)
	if objs[0]["kind"] != "Namespace" {
		t.Fatal("namespace должен применяться первым")
	}
	for _, o := range objs[1:] {
		if md := o["metadata"].(obj); md["namespace"] != "deck-u-anna" {
			t.Errorf("%v %v вне namespace пространства", o["kind"], md["name"])
		}
		if _, err := objectPath(o); err != nil {
			t.Error(err)
		}
	}
	// в поде нет ни одного секрета и ни одного токена, кроме проецируемого для keyguard
	for _, bad := range []string{`"secret"`, `"secretKeyRef"`, `"hostPath"`, `"hostNetwork"`, `"privileged"`, `ANTHROPIC`, `SAKANA_API_KEY`} {
		if strings.Contains(js, bad) {
			t.Errorf("в объектах пространства есть %s", bad)
		}
	}
	for _, want := range []string{`"runtimeClassName":"gvisor"`, `"automountServiceAccountToken":false`, `"dnsPolicy":"None"`,
		`"readOnlyRootFilesystem":true`, `"audience":"keyguard"`, `"DECK_MODE"`, `"replicas":1`} {
		if !strings.Contains(js, want) {
			t.Errorf("нет %s", want)
		}
	}
	slept, _ := json.Marshal(Render(Space{Name: "anna", Owner: "anna", Kind: "personal", TokenKey: testKey, Suspended: true}, cfg))
	if !strings.Contains(string(slept), `"replicas":0`) {
		t.Error("остановленное пространство: реплик не 0")
	}
}

func TestDeploymentReady(t *testing.T) {
	d := func(gen, observed, replicas, updated, available float64) map[string]any {
		return map[string]any{"metadata": map[string]any{"generation": gen},
			"status": map[string]any{"observedGeneration": observed, "replicas": replicas, "updatedReplicas": updated, "availableReplicas": available}}
	}
	if !deploymentReady(d(2, 2, 1, 1, 1)) {
		t.Error("запущенный под с текущим описанием не считается готовым")
	}
	for name, x := range map[string]map[string]any{
		"контроллер ещё не видел изменения": d(3, 2, 1, 1, 1),
		"старый под ещё числится":           d(2, 2, 2, 1, 1),
		"новый под не запустился":           d(2, 2, 1, 1, 0),
		"подов нет":   d(2, 2, 0, 0, 0),
		"нет статуса": {"metadata": map[string]any{"generation": 1.0}},
	} {
		if deploymentReady(x) {
			t.Errorf("%s: считается готовым", name)
		}
	}
}
