package spaceoperator

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Kube — те вызовы API Kubernetes, что нужны оператору. Без client-go: зависимостей у сервиса нет.
type Kube interface {
	List(ctx context.Context, path string) ([]map[string]any, error)
	Get(ctx context.Context, path string) (map[string]any, error)
	// Apply — server-side apply: объект приводится к описанному, чужие поля не трогаются.
	Apply(ctx context.Context, path string, o map[string]any) error
	// PatchStatus — merge-patch подресурса status.
	PatchStatus(ctx context.Context, path string, status map[string]any) error
	// Delete — удалить объект; отсутствующий объект — не ошибка.
	Delete(ctx context.Context, path string) error
}

var ErrNotFound = errors.New("не найдено")

type KubeHTTP struct {
	Base      string // https://kubernetes.default.svc
	TokenPath string
	HTTP      *http.Client
}

// InCluster — клиент по учётной записи пода.
func InCluster() (*KubeHTTP, error) {
	const sa = "/var/run/secrets/kubernetes.io/serviceaccount"
	ca, err := os.ReadFile(sa + "/ca.crt")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("ca.crt: нет сертификатов")
	}
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" {
		return nil, errors.New("не в кластере: нет KUBERNETES_SERVICE_HOST")
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return &KubeHTTP{Base: "https://" + host + ":" + port, TokenPath: sa + "/token",
		HTTP: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}}, nil
}

func (k *KubeHTTP) do(ctx context.Context, method, path, contentType string, body any) ([]byte, error) {
	tok, err := os.ReadFile(k.TokenPath) // читаем каждый раз: kubelet обновляет токен
	if err != nil {
		return nil, err
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, k.Base+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	r, err := k.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	out, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if r.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if r.StatusCode >= 300 {
		var st struct {
			Message string `json:"message"`
		}
		json.Unmarshal(out, &st)
		return nil, fmt.Errorf("%s %s: HTTP %d: %s", method, path, r.StatusCode, st.Message)
	}
	return out, nil
}

func (k *KubeHTTP) List(ctx context.Context, path string) ([]map[string]any, error) {
	out, err := k.do(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return nil, err
	}
	var l struct {
		Items []map[string]any `json:"items"`
	}
	return l.Items, json.Unmarshal(out, &l)
}

func (k *KubeHTTP) Get(ctx context.Context, path string) (map[string]any, error) {
	out, err := k.do(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return nil, err
	}
	var o map[string]any
	return o, json.Unmarshal(out, &o)
}

func (k *KubeHTTP) Apply(ctx context.Context, path string, o map[string]any) error {
	_, err := k.do(ctx, http.MethodPatch, path+"?fieldManager="+manager+"&force=true", "application/apply-patch+yaml", o)
	return err
}

func (k *KubeHTTP) PatchStatus(ctx context.Context, path string, status map[string]any) error {
	_, err := k.do(ctx, http.MethodPatch, path+"/status", "application/merge-patch+json", map[string]any{"status": status})
	return err
}

func (k *KubeHTTP) Delete(ctx context.Context, path string) error {
	_, err := k.do(ctx, http.MethodDelete, path, "", nil)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}
