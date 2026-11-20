package spaceoperator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

// Клиент S3 на настоящем хранилище: подпись запросов проверяет только оно. Нужны S3_TEST_ENDPOINT, S3_TEST_REGION,
// S3_TEST_BUCKET, S3_TEST_ACCESS_KEY, S3_TEST_SECRET_KEY; объект кладётся под ключом spaces/_selftest/ и убирается.
// Бакет брать С БЛОКИРОВКОЙ УДАЛЕНИЯ (как боевой бакет копий): он требует контрольную сумму в заголовке, и на
// бакете без блокировки её отсутствие не заметить — так ошибка однажды дошла до кластера.
func TestS3OnRealStorage(t *testing.T) {
	if os.Getenv("S3_TEST_BUCKET") == "" {
		t.Skip("нужен S3_TEST_BUCKET")
	}
	s := &S3{Endpoint: os.Getenv("S3_TEST_ENDPOINT"), Region: os.Getenv("S3_TEST_REGION"), Bucket: os.Getenv("S3_TEST_BUCKET"),
		AccessKey: os.Getenv("S3_TEST_ACCESS_KEY"), SecretKey: os.Getenv("S3_TEST_SECRET_KEY"), HTTP: &http.Client{Timeout: time.Minute}}
	ctx := context.Background()
	key := "spaces/_selftest/проверка подписи +&=.sqlite3" // пробел, не-ASCII и служебные символы в ключе
	body := bytes.Repeat([]byte("fugu deck "), 20000)
	sum := sha256.Sum256(body)
	if ok, err := s.Exists(ctx, key); err != nil || ok {
		t.Fatalf("до загрузки: %v %v", ok, err)
	}
	if _, err := s.Get(ctx, key); err != ErrNotFound {
		t.Fatalf("GET отсутствующего: %v", err)
	}
	if err := s.Put(ctx, key, bytes.NewReader(body), int64(len(body)), hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	defer s.Delete(ctx, key)
	if ok, err := s.Exists(ctx, key); err != nil || !ok {
		t.Fatalf("после загрузки: %v %v", ok, err)
	}
	r, err := s.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r)
	r.Close()
	if !bytes.Equal(got, body) {
		t.Fatalf("прочитано %d байт, записано %d", len(got), len(body))
	}
	// Тело, не совпадающее с подписанным хешем, хранилище не принимает.
	if err := s.Put(ctx, key, bytes.NewReader([]byte("подмена")), int64(len("подмена")), hex.EncodeToString(sum[:])); err == nil {
		t.Fatal("принято тело с чужим хешем")
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.Exists(ctx, key); err != nil || ok {
		t.Fatalf("после удаления: %v %v", ok, err)
	}
	bad := *s
	bad.SecretKey = "wrong"
	if _, err := bad.Exists(ctx, key); err == nil {
		t.Fatal("неверный ключ принят")
	}
}
