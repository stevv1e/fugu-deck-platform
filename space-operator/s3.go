package spaceoperator

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// S3 — те четыре вызова хранилища, что нужны для копий пространств: положить, взять, проверить, убрать.
// Свой клиент вместо SDK: зависимостей у сервиса нет, а подпись запроса (AWS Signature V4) — полсотни строк.
type S3 struct {
	Endpoint  string // https://s3.ap-southeast-2.amazonaws.com (адресация по пути: <endpoint>/<бакет>/<ключ>)
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
	HTTP      *http.Client
	Now       func() time.Time
}

const emptySHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func hmacSHA(key []byte, s string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(s))
	return h.Sum(nil)
}

// uriEncode — кодирование пути по правилам S3: всё, кроме незарезервированных символов и «/».
func uriEncode(p string) string {
	var b strings.Builder
	for _, c := range []byte(p) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~', c == '/':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// sign добавляет заголовки Authorization, X-Amz-Date и X-Amz-Content-Sha256.
func (s *S3) sign(r *http.Request, payloadSHA string) {
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	amzDate, day := now.UTC().Format("20060102T150405Z"), now.UTC().Format("20060102")
	r.Header.Set("X-Amz-Date", amzDate)
	r.Header.Set("X-Amz-Content-Sha256", payloadSHA)
	headers := map[string]string{"host": r.URL.Host}
	for k, v := range r.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-") || lk == "content-type" {
			headers[lk] = strings.TrimSpace(v[0])
		}
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var canon strings.Builder
	for _, k := range names {
		canon.WriteString(k + ":" + headers[k] + "\n")
	}
	signed := strings.Join(names, ";")
	creq := strings.Join([]string{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, canon.String(), signed, payloadSHA}, "\n")
	scope := day + "/" + s.Region + "/s3/aws4_request"
	sum := sha256.Sum256([]byte(creq))
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
	key := hmacSHA(hmacSHA(hmacSHA(hmacSHA([]byte("AWS4"+s.SecretKey), day), s.Region), "s3"), "aws4_request")
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+s.AccessKey+"/"+scope+
		", SignedHeaders="+signed+", Signature="+hex.EncodeToString(hmacSHA(key, toSign)))
}

func (s *S3) do(ctx context.Context, method, key string, body io.Reader, size int64, payloadSHA string) (*http.Response, error) {
	u, err := url.Parse(strings.TrimRight(s.Endpoint, "/"))
	if err != nil {
		return nil, err
	}
	u.Path = "/" + s.Bucket + "/" + key
	u.RawPath = uriEncode(u.Path)
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = size
		req.Header.Set("Content-Type", "application/octet-stream")
		// Бакет с блокировкой удаления (Object Lock) принимает объект только с контрольной суммой в заголовке.
		if raw, err := hex.DecodeString(payloadSHA); err == nil {
			req.Header.Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(raw))
		}
	}
	s.sign(req, payloadSHA)
	return s.HTTP.Do(req)
}

func s3Err(op string, r *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(r.Body, 600))
	return fmt.Errorf("S3 %s: HTTP %d: %s", op, r.StatusCode, strings.Join(strings.Fields(string(b)), " "))
}

// Put кладёт объект; sha — SHA-256 содержимого (оно подписывается, подменить тело в пути нельзя).
func (s *S3) Put(ctx context.Context, key string, body io.Reader, size int64, sha string) error {
	r, err := s.do(ctx, http.MethodPut, key, body, size, sha)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return s3Err("PUT", r)
	}
	return nil
}

// Get отдаёт содержимое объекта; ErrNotFound — объекта нет (или он удалён).
func (s *S3) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	r, err := s.do(ctx, http.MethodGet, key, nil, 0, emptySHA)
	if err != nil {
		return nil, err
	}
	if r.StatusCode == http.StatusNotFound {
		r.Body.Close()
		return nil, ErrNotFound
	}
	if r.StatusCode != http.StatusOK {
		defer r.Body.Close()
		return nil, s3Err("GET", r)
	}
	return r.Body, nil
}

// Exists — есть ли объект.
func (s *S3) Exists(ctx context.Context, key string) (bool, error) {
	r, err := s.do(ctx, http.MethodHead, key, nil, 0, emptySHA)
	if err != nil {
		return false, err
	}
	defer r.Body.Close()
	switch r.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	}
	return false, errors.New("S3 HEAD: HTTP " + r.Status)
}

// Delete убирает объект. В бакете с версиями это метка удаления: прежние версии доживают свой срок хранения
// и исчезают по правилу жизненного цикла — стереть историю копий этим ключом нельзя.
func (s *S3) Delete(ctx context.Context, key string) error {
	r, err := s.do(ctx, http.MethodDelete, key, nil, 0, emptySHA)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusNoContent && r.StatusCode != http.StatusOK && r.StatusCode != http.StatusNotFound {
		return s3Err("DELETE", r)
	}
	return nil
}
