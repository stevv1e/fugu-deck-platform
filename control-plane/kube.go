package controlplane

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

// KubeSpaces — объекты Space через API Kubernetes под учётной записью пода control-plane. Его роль даёт только
// чтение, создание и изменение Space в одном namespace; удалить пространство или тронуть что-то ещё он не может.
type KubeSpaces struct {
	Base      string
	TokenPath string
	Namespace string
	HTTP      *http.Client
}

func InClusterSpaces(namespace string) (*KubeSpaces, error) {
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
	return &KubeSpaces{Base: "https://" + host + ":" + port, TokenPath: sa + "/token", Namespace: namespace,
		HTTP: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}}, nil
}

func (k *KubeSpaces) do(ctx context.Context, method, path, contentType string, body any) (int, []byte, error) {
	tok, err := os.ReadFile(k.TokenPath)
	if err != nil {
		return 0, nil, err
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, k.Base+"/apis/deck.fugu/v1alpha1/namespaces/"+k.Namespace+"/spaces"+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	r, err := k.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer r.Body.Close()
	out, err := io.ReadAll(io.LimitReader(r.Body, 16<<20)) // список Space на сотни пространств
	return r.StatusCode, out, err
}

type spaceObject struct {
	Metadata struct {
		Name        string            `json:"name"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Owner             string `json:"owner"`
		Suspended         bool   `json:"suspended"`
		DeleteRequestedAt string `json:"deleteRequestedAt"`
		InactiveDelete    bool   `json:"inactiveDelete"`
	} `json:"spec"`
	Status struct {
		Phase       string `json:"phase"`
		Namespace   string `json:"namespace"`
		DeleteAt    string `json:"deleteAt"`
		DeleteError string `json:"deleteError"`
		DeleteKind  string `json:"deleteKind"`
		Conditions  []struct {
			Message string `json:"message"`
		} `json:"conditions"`
	} `json:"status"`
}

func (o spaceObject) info() SpaceInfo {
	info := SpaceInfo{Name: o.Metadata.Name, Owner: o.Spec.Owner, Phase: o.Status.Phase, Namespace: o.Status.Namespace,
		TokenKey: o.Metadata.Annotations[tokenKeyAnnotation], Suspended: o.Spec.Suspended,
		DeleteRequested: o.Spec.DeleteRequestedAt != "", DeleteAt: o.Status.DeleteAt, DeleteError: o.Status.DeleteError,
		DeleteKind: o.Status.DeleteKind, InactiveDelete: o.Spec.InactiveDelete}
	if len(o.Status.Conditions) > 0 {
		info.Message = o.Status.Conditions[0].Message
	}
	if t, err := time.Parse(time.RFC3339, o.Metadata.Annotations[wakeAtAnnotation]); err == nil {
		info.WakeAt = t
	}
	return info
}

func (k *KubeSpaces) SetWakeAt(ctx context.Context, name string, at time.Time) error {
	var v any // null в merge-patch убирает аннотацию
	if !at.IsZero() {
		v = at.UTC().Format(time.RFC3339)
	}
	code, out, err := k.do(ctx, http.MethodPatch, "/"+name, "application/merge-patch+json",
		map[string]any{"metadata": map[string]any{"annotations": map[string]any{wakeAtAnnotation: v}}})
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("Space %s: wake-at: HTTP %d: %.200s", name, code, out)
	}
	return nil
}

func (k *KubeSpaces) Get(ctx context.Context, name string) (SpaceInfo, error) {
	code, out, err := k.do(ctx, http.MethodGet, "/"+name, "", nil)
	if err != nil {
		return SpaceInfo{}, err
	}
	if code == http.StatusNotFound {
		return SpaceInfo{}, ErrNotFound
	}
	if code != http.StatusOK {
		return SpaceInfo{}, fmt.Errorf("Space %s: HTTP %d", name, code)
	}
	var o spaceObject
	if err := json.Unmarshal(out, &o); err != nil {
		return SpaceInfo{}, err
	}
	return o.info(), nil
}

func (k *KubeSpaces) List(ctx context.Context) ([]SpaceInfo, error) {
	code, out, err := k.do(ctx, http.MethodGet, "", "", nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("список Space: HTTP %d", code)
	}
	var l struct {
		Items []spaceObject `json:"items"`
	}
	if err := json.Unmarshal(out, &l); err != nil {
		return nil, err
	}
	res := make([]SpaceInfo, 0, len(l.Items))
	for _, o := range l.Items {
		res = append(res, o.info())
	}
	return res, nil
}

func (k *KubeSpaces) SetSuspended(ctx context.Context, name string, suspended bool) error {
	code, out, err := k.do(ctx, http.MethodPatch, "/"+name, "application/merge-patch+json",
		map[string]any{"spec": map[string]any{"suspended": suspended}})
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("Space %s: suspended=%v: HTTP %d: %.200s", name, suspended, code, out)
	}
	return nil
}

func (k *KubeSpaces) Ensure(ctx context.Context, name, owner, tokenKeyPEM string) error {
	return k.ensure(ctx, name, owner, "personal", "", tokenKeyPEM)
}

func (k *KubeSpaces) EnsureTeam(ctx context.Context, name, owner, title, tokenKeyPEM string) error {
	return k.ensure(ctx, name, owner, "team", title, tokenKeyPEM)
}

func (k *KubeSpaces) ensure(ctx context.Context, name, owner, kind, title, tokenKeyPEM string) error {
	cur, err := k.Get(ctx, name)
	switch {
	case errors.Is(err, ErrNotFound):
		ann := map[string]string{tokenKeyAnnotation: tokenKeyPEM}
		if title != "" {
			ann["deck.fugu/title"] = title
		}
		code, out, err := k.do(ctx, http.MethodPost, "", "application/json", map[string]any{
			"apiVersion": "deck.fugu/v1alpha1", "kind": "Space",
			"metadata": map[string]any{"name": name, "annotations": ann},
			"spec":     map[string]any{"kind": kind, "owner": owner}})
		if err != nil {
			return err
		}
		if code != http.StatusCreated && code != http.StatusConflict {
			return fmt.Errorf("создание Space: HTTP %d: %.200s", code, out)
		}
		return nil
	case err != nil:
		return err
	case cur.Owner != owner:
		return errors.New("пространство с этим именем принадлежит другому пользователю")
	case cur.TokenKey == tokenKeyPEM:
		return nil
	}
	// ключ токенов сменился (новая база control-plane): обновляем аннотацию, оператор перезапустит агента
	code, out, err := k.do(ctx, http.MethodPatch, "/"+name, "application/merge-patch+json",
		map[string]any{"metadata": map[string]any{"annotations": map[string]string{tokenKeyAnnotation: tokenKeyPEM}}})
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("обновление Space: HTTP %d: %.200s", code, out)
	}
	return nil
}

func (k *KubeSpaces) RequestDelete(ctx context.Context, name, jws string, at time.Time) error {
	spec := map[string]any{"deleteRequestedAt": nil, "deleteSignature": nil} // отмена
	if jws != "" {
		spec = map[string]any{"deleteRequestedAt": at.UTC().Format(time.RFC3339), "deleteSignature": jws}
	}
	code, out, err := k.do(ctx, http.MethodPatch, "/"+name, "application/merge-patch+json", map[string]any{"spec": spec})
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("Space %s: запрос удаления: HTTP %d: %.200s", name, code, out)
	}
	return nil
}

func (k *KubeSpaces) patchSpec(ctx context.Context, name string, spec map[string]any) error {
	code, out, err := k.do(ctx, http.MethodPatch, "/"+name, "application/merge-patch+json", map[string]any{"spec": spec})
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("Space %s: HTTP %d: %.200s", name, code, out)
	}
	return nil
}

func (k *KubeSpaces) SetOwner(ctx context.Context, name, owner string) error {
	return k.patchSpec(ctx, name, map[string]any{"owner": owner})
}

func (k *KubeSpaces) SetInactiveDelete(ctx context.Context, name string, on bool) error {
	var v any // null убирает поле
	if on {
		v = true
	}
	return k.patchSpec(ctx, name, map[string]any{"inactiveDelete": v})
}
