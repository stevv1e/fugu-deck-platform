package controlplane

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// Общее состояние реплик на настоящем Postgres: DECK_TEST_PG=postgres://… go test -run TestPGShared
func TestPGShared(t *testing.T) {
	dsn := os.Getenv("DECK_TEST_PG")
	if dsn == "" {
		t.Skip("нужен DECK_TEST_PG")
	}
	a, err := OpenPG(dsn)
	if err != nil {
		t.Fatal(err)
	}
	b, err := OpenPG(dsn)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	key := fmt.Sprintf("jkt/jti-%d", now.UnixNano()) // база могла остаться от прошлого прогона
	if ok, err := a.UseNonce(key, now, now.Add(time.Minute)); !ok || err != nil {
		t.Fatalf("первый раз: %v %v", ok, err)
	}
	if ok, _ := b.UseNonce(key, now, now.Add(time.Minute)); ok {
		t.Fatal("повтор через другую реплику принят")
	}
	if ok, _ := b.UseNonce(key, now.Add(2*time.Minute), now.Add(3*time.Minute)); !ok {
		t.Fatal("ключ после своего срока снова доступен")
	}
	at := now.Truncate(time.Second)
	a.TouchSpace("u-anna", at)
	b.TouchSpace("u-anna", at.Add(-time.Hour)) // более старое не затирает
	if got, _ := b.SpaceActivity("u-anna"); !got.Equal(at) {
		t.Fatalf("активность: %v, ждали %v", got, at)
	}
	pairID := fmt.Sprintf("pair-%d", now.UnixNano())
	pairCode := fmt.Sprintf("%08d", now.UnixNano()%100000000)
	pair := Pairing{ID: pairID, Code: pairCode, Nick: "anna", Name: "PC", SessionJKT: "s", ConfirmJKT: "c", SecretHash: "h", Expires: now.Add(15 * time.Minute)}
	if err := a.PutPairing(pair); err != nil {
		t.Fatal(err)
	}
	defer a.DB.Exec(`DELETE FROM cp_pairings WHERE id=$1`, pairID)
	if got, err := b.ApprovePairing(pairID, "anna", now); err != nil || !got.Approved {
		t.Fatalf("pairing через другую реплику: %+v %v", got, err)
	}
	if _, err := a.ApprovePairing(pairID, "anna", now); err == nil {
		t.Fatal("другая реплика подтвердила pairing повторно")
	}
	if got, err := a.PairingByCode(pairCode); err != nil || !got.Approved {
		t.Fatalf("pairing по коду: %+v %v", got, err)
	}
	if !a.Leader("sleeper") || b.Leader("sleeper") {
		t.Fatal("ведущей должна быть ровно одна реплика")
	}
	if !a.Leader("sleeper") || !b.Leader("push") {
		t.Fatal("ведущая остаётся ведущей; другой цикл может вести другая реплика")
	}
	// реплика A «упала»: соединение с блокировкой оборвалось — Postgres снимает блокировку сам
	var pid int
	if err := a.leaders["sleeper"].QueryRowContext(t.Context(), `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	b.DB.Exec(`SELECT pg_terminate_backend($1)`, pid)
	time.Sleep(200 * time.Millisecond)
	if !b.Leader("sleeper") {
		t.Fatal("после потери ведущей цикл подхватывает другая реплика")
	}
	if a.Leader("sleeper") {
		t.Fatal("реплика с оборванным соединением не должна считать себя ведущей")
	}
}
