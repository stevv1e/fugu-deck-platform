package keyguard

// Те же атаки на перезапуск — на настоящем Postgres, плюс единственность экземпляра.
// Запуск: KG_TEST_PG_DSN="postgres://keyguard:пароль@127.0.0.1:5432/keyguard?sslmode=disable" go test -run Postgres ./...
// (одноразовая база: тест удаляет таблицы kg_*). Без переменной тест пропускается; scripts/pg_test.sh поднимает базу сам.

import (
	"context"
	"database/sql"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestIntegration_Postgres(t *testing.T) {
	dsn := os.Getenv("KG_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("нужен KG_TEST_PG_DSN (одноразовый Postgres) — см. scripts/pg_test.sh")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.Exec(`DROP TABLE IF EXISTS kg_devices, kg_nonces, kg_grants, kg_ledger`); err != nil {
		t.Fatalf("база недоступна: %v", err)
	}
	old := lockCheckEvery
	lockCheckEvery = 200 * time.Millisecond
	defer func() { lockCheckEvery = old }()

	var cur *PGState
	var lost atomic.Int32
	open := func() Persister { // новый процесс: прежний завершился (соединения закрыты, блокировка свободна)
		if cur != nil {
			cur.Close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		p, err := OpenPGState(ctx, dsn, nil, func(error) { lost.Add(1) })
		if err != nil {
			t.Fatalf("OpenPGState: %v", err)
		}
		cur = p
		return p
	}
	t.Run("перезапуск", func(t *testing.T) {
		restartSuite(t, open, func() { cur.Close(); cur = nil }, nil)
	})

	c := &check{t: t}
	first := open().(*PGState)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	waited := false
	_, err = OpenPGState(ctx, dsn, func() { waited = true }, nil)
	cancel()
	c.ok("P1 второй keyguard не стартует, пока жив первый (блокировка экземпляра)", err != nil && waited, err)

	// nonce: проверка и запись — одно действие в базе, даже мимо рабочей копии в памяти
	a, _ := first.UseNonce("dev", "n-1", time.Now())
	b, _ := first.UseNonce("dev", "n-1", time.Now())
	d, _ := first.UseNonce("dev2", "n-1", time.Now())
	c.ok("P2 повтор nonce отклоняет сама база; тот же nonce другого устройства — отдельный", a && !b && d, a, b, d)
	first.SetLimit("k", 5, false)
	first.SetLimit("k", 9, true)
	first.AddSpent([]string{"k", "k2"}, 1.5)
	first.AddSpent([]string{"k"}, -0.5)
	snap, err := first.Load(context.Background())
	c.ok("P3 лимит «once» не перезаписывает; расход складывается по всем бюджетам; бюджет без лимита — без лимита",
		err == nil && snap.Limits["k"] == 5 && snap.Spent["k"] == 1 && snap.Spent["k2"] == 1.5 && func() bool { _, ok := snap.Limits["k2"]; return !ok }(), snap)
	old1 := time.Now().Add(-time.Hour)
	first.UseNonce("dev", "old", old1)
	first.PruneNonces(time.Now().Add(-10 * time.Minute))
	fresh, _ := first.UseNonce("dev", "old", time.Now())
	again, _ := first.UseNonce("dev", "n-1", time.Now())
	c.ok("P4 чистка удаляет только nonce старше окна", fresh && !again, fresh, again)

	// соединение с блокировкой оборвано извне (сбой сети, переключение базы) → keyguard обязан узнать и завершиться
	lost.Store(0)
	if _, err := admin.Exec(`SELECT pg_terminate_backend(pid) FROM pg_locks WHERE locktype = 'advisory' AND pid <> pg_backend_pid()`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50 && lost.Load() == 0; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	c.ok("P5 потеря соединения с блокировкой замечена (процесс завершится)", lost.Load() == 1, lost.Load())
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	second, err := OpenPGState(ctx, dsn, nil, nil)
	cancel()
	c.ok("P6 после этого блокировку берёт новый экземпляр", err == nil, err)
	if second != nil {
		second.Close()
	}
	first.Close()
	cur = nil
	t.Logf("postgres: %d/%d", c.n, c.n+c.f)
}
