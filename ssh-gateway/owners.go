package sshgateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Владелец общего пространства. В общем пространстве серверы добавляет, права агенту выдаёт и команды подтверждает
// его владелец. Кто владелец, шлюз узнаёт сам — из объекта Space в API Kubernetes (spec.owner), а не со слов
// control-plane: того шлюз проверяющим не считает.

type Owners interface {
	Owner(ctx context.Context, space string) (string, error)
}

// StaticOwners — для тестов: пространство (t-…) → владелец.
type StaticOwners map[string]string

func (s StaticOwners) Owner(_ context.Context, space string) (string, error) {
	o, ok := s[space]
	if !ok {
		return "", ErrNotFound
	}
	return o, nil
}

// KubeOwners — чтение Space из API Kubernetes (роль: get на spaces в namespace пространств). Кэш на минуту.
type KubeOwners struct {
	APIServer string
	Namespace string // deck-system
	Token     func() (string, error)
	HTTP      *http.Client

	mu    sync.Mutex
	cache map[string]ownerCached
}

type ownerCached struct {
	owner string
	at    time.Time
}

func InClusterOwners(namespace string) (*KubeOwners, error) {
	sa := "/var/run/secrets/kubernetes.io/serviceaccount"
	ca, err := os.ReadFile(sa + "/ca.crt")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" {
		return nil, errors.New("не в кластере")
	}
	return &KubeOwners{APIServer: "https://" + host + ":" + port, Namespace: namespace,
		HTTP: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}},
		Token: func() (string, error) {
			b, err := os.ReadFile(sa + "/token")
			return strings.TrimSpace(string(b)), err
		}}, nil
}

func (k *KubeOwners) Owner(ctx context.Context, space string) (string, error) {
	k.mu.Lock()
	if c, ok := k.cache[space]; ok && time.Since(c.at) < time.Minute {
		k.mu.Unlock()
		return c.owner, nil
	}
	k.mu.Unlock()
	tok, err := k.Token()
	if err != nil {
		return "", err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, k.APIServer+"/apis/deck.fugu/v1alpha1/namespaces/"+k.Namespace+"/spaces/"+space, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	r, err := k.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	if r.StatusCode == http.StatusNotFound {
		return "", ErrNotFound
	}
	var o struct {
		Spec struct{ Owner, Kind string } `json:"spec"`
	}
	if r.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&o) != nil || o.Spec.Kind != "team" {
		return "", errors.New("пространство не найдено или не общее")
	}
	k.mu.Lock()
	if k.cache == nil {
		k.cache = map[string]ownerCached{}
	}
	k.cache[space] = ownerCached{o.Spec.Owner, time.Now()}
	k.mu.Unlock()
	return o.Spec.Owner, nil
}
