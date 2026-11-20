package spaceoperator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Удаление пространства. Запрос приходит через control-plane, который доступен из интернета, поэтому одного его
// слова мало: в Space.spec.deleteSignature лежит действие space_delete, подписанное на телефоне владельца ключом
// подтверждения. Оператор отдаёт подпись на проверку keyguard и сам отсчитывает срок — ни момент удаления, ни сам
// факт control-plane подделать не может. До истечения срока владелец отменяет удаление (control-plane убирает
// запрос из spec); пространство на это время остановлено, данные на месте.

// Verified — ответ keyguard на /v1/actions/verify.
type Verified struct {
	Action struct {
		Type  string `json:"type"`
		Space string `json:"space"`
	} `json:"action"`
	User     string `json:"user"`
	DeviceID string `json:"device_id"`
}

// ErrRejected — keyguard подпись не принял (в отличие от «keyguard недоступен», повторять бессмысленно).
var ErrRejected = errors.New("подпись не принята")

// KeyguardVerifier — проверка подписи через keyguard по токену ServiceAccount оператора (audience=keyguard).
func KeyguardVerifier(baseURL, tokenPath string, hc *http.Client) func(ctx context.Context, jws string) (Verified, error) {
	return func(ctx context.Context, jws string) (Verified, error) {
		var v Verified
		tok, err := os.ReadFile(tokenPath)
		if err != nil {
			return v, err
		}
		body, _ := json.Marshal(map[string]string{"jws": jws})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v1/actions/verify", bytes.NewReader(body))
		if err != nil {
			return v, err
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
		req.Header.Set("Content-Type", "application/json")
		r, err := hc.Do(req)
		if err != nil {
			return v, err
		}
		defer r.Body.Close()
		out, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		switch {
		case r.StatusCode == http.StatusOK:
			return v, json.Unmarshal(out, &v)
		case r.StatusCode == http.StatusBadRequest || r.StatusCode == http.StatusForbidden:
			var e struct {
				Error string `json:"error"`
			}
			json.Unmarshal(out, &e)
			return v, fmt.Errorf("%w: %s", ErrRejected, e.Error)
		}
		return v, fmt.Errorf("keyguard: HTTP %d", r.StatusCode)
	}
}

// KeyguardPurger — стереть данные удалённого аккаунта в keyguard (/v1/account/purge).
func KeyguardPurger(baseURL, tokenPath string, hc *http.Client) func(ctx context.Context, user, reason string) error {
	return func(ctx context.Context, user, reason string) error {
		tok, err := os.ReadFile(tokenPath)
		if err != nil {
			return err
		}
		body, _ := json.Marshal(map[string]string{"user": user, "reason": reason})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v1/account/purge", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
		req.Header.Set("Content-Type", "application/json")
		r, err := hc.Do(req)
		if err != nil {
			return err
		}
		defer r.Body.Close()
		if r.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(io.LimitReader(r.Body, 400))
			return fmt.Errorf("keyguard: HTTP %d: %s", r.StatusCode, b)
		}
		return nil
	}
}

func sigHash(jws string) string {
	h := sha256.Sum256([]byte(jws))
	return hex.EncodeToString(h[:])
}

// deletion ведёт запрос удаления пространства. Возвращает пространство (с отметкой «остановлено», если оно ждёт
// удаления), поля для status и gone=true, когда пространство удалено или удаляется прямо сейчас.
func (op *Operator) deletion(ctx context.Context, s Space) (Space, map[string]any, bool) {
	if !s.Deleting && s.InactiveDelete && op.Cfg.InactiveAfter > 0 && s.Kind != "team" {
		return op.inactiveDeletion(ctx, s)
	}
	if !s.Deleting {
		if s.DeleteVerified != "" || s.DeleteAt != "" {
			// Запрос снят (отмена): забываем о нём. Та же подпись второй раз не пройдёт — keyguard помнит её номер.
			op.Log.Printf("event=space.delete_cancelled space=%s", s.Name)
			return s, map[string]any{"deleteVerified": nil, "deleteAt": nil, "deleteError": nil, "deleteKind": nil}, false
		}
		return s, nil, false
	}
	sum := sigHash(s.DeleteSig)
	if s.DeleteVerified == "rejected:"+sum {
		return s, nil, false // эту подпись уже отклонили: пространство работает как работало
	}
	if s.DeleteVerified != sum || s.DeleteAt == "" {
		if op.Verify == nil || s.Check() != nil {
			return s, nil, false
		}
		v, err := op.Verify(ctx, s.DeleteSig)
		// space_delete — для этого пространства; account_delete — весь аккаунт владельца, и с ним его личное
		// пространство (keyguard уже сверил, что удаляемый аккаунт — того, кто подписал).
		space := v.Action.Type == "space_delete" && v.Action.Space == s.Key()
		account := v.Action.Type == "account_delete" && s.Kind != "team"
		if err == nil && (v.User != s.Owner || !(space || account)) {
			err = fmt.Errorf("%w: действие подписано не владельцем или не для этого пространства", ErrRejected)
		}
		if errors.Is(err, ErrRejected) {
			op.Log.Printf("event=space.delete_rejected space=%s err=%q", s.Name, err.Error())
			return s, map[string]any{"deleteVerified": "rejected:" + sum, "deleteAt": nil, "deleteError": err.Error()}, false
		}
		if err != nil { // keyguard недоступен — повторим на следующем проходе, пространство пока работает
			op.Log.Printf("event=space.delete_verify_failed space=%s err=%q", s.Name, err.Error())
			return s, nil, false
		}
		at := op.Now().Add(op.Cfg.DeleteDelay).UTC().Format(time.RFC3339)
		op.Log.Printf("event=space.delete_accepted space=%s by=%s device=%s delete_at=%s", s.Name, v.User, v.DeviceID, at)
		s.DeleteAt, s.stopped = at, true
		st := map[string]any{"deleteVerified": sum, "deleteAt": at, "deleteError": nil, "deleteKind": nil}
		if account {
			s.DeleteKind, st["deleteKind"] = "account", "account"
		}
		return s, st, false
	}
	return op.expire(ctx, s)
}

// inactiveDeletion — удаление аккаунта по неактивности. control-plane только просит (spec.inactiveDelete); оператор
// исполняет, если сам видит пространство спящим без перерыва InactiveAfter: любое обращение будит его и сбрасывает
// отсчёт, так что подделать «30 дней без входа» control-plane не может. Дальше — те же сутки до удаления.
func (op *Operator) inactiveDeletion(ctx context.Context, s Space) (Space, map[string]any, bool) {
	if s.DeleteKind == "inactive" && s.DeleteAt != "" {
		return op.expire(ctx, s)
	}
	since, err := time.Parse(time.RFC3339, s.SleepingSince)
	if err != nil || !s.Suspended || op.Now().Sub(since) < op.Cfg.InactiveAfter {
		return s, nil, false // ещё рано, или пространство не спит — тогда просьба неправомерна, ничего не делаем
	}
	at := op.Now().Add(op.Cfg.DeleteDelay).UTC().Format(time.RFC3339)
	op.Log.Printf("event=space.inactive_delete_accepted space=%s sleeping_since=%s delete_at=%s", s.Name, s.SleepingSince, at)
	s.DeleteAt, s.DeleteKind, s.stopped = at, "inactive", true
	return s, map[string]any{"deleteAt": at, "deleteKind": "inactive", "deleteVerified": nil, "deleteError": nil}, false
}

// expire — срок удаления вышел (или ещё нет): namespace, копии, данные в keyguard, затем сам Space.
func (op *Operator) expire(ctx context.Context, s Space) (Space, map[string]any, bool) {
	at, err := time.Parse(time.RFC3339, s.DeleteAt)
	if err != nil || op.Now().Before(at) {
		s.stopped = true
		return s, nil, false
	}
	// Срок вышел. Сначала namespace (с ним уходят под, том и данные), и только когда его не стало — сам Space:
	// пока Space есть, оператор помнит, что удаление надо довести до конца.
	if s.Check() != nil {
		return s, nil, false
	}
	ns := "/api/v1/namespaces/" + s.Namespace()
	if cur, err := op.Kube.Get(ctx, ns); err == nil {
		// Удаляем только то, что сами создали как пространство этого владельца.
		if str(cur, "metadata", "labels", "deck.fugu/space") != "true" || str(cur, "metadata", "labels", "deck.fugu/owner") != s.Owner {
			op.Log.Printf("event=space.delete_refused space=%s namespace=%s reason=%q", s.Name, s.Namespace(), "namespace не помечен как пространство владельца")
			return s, nil, true
		}
		if err := op.Kube.Delete(ctx, ns); err != nil {
			op.Log.Printf("event=space.delete_failed space=%s err=%q", s.Name, err.Error())
		} else {
			op.Log.Printf("event=space.namespace_deleting space=%s namespace=%s", s.Name, s.Namespace())
		}
		return s, nil, true
	} else if !errors.Is(err, ErrNotFound) {
		op.Log.Printf("event=space.delete_failed space=%s err=%q", s.Name, err.Error())
		return s, nil, true
	}
	// Копия в хранилище уходит вместе с пространством; пока её не убрали, Space остаётся — попытка повторится.
	if op.Backup != nil {
		if err := op.deleteFiles(ctx, s.Name); err != nil {
			op.Log.Printf("event=space.backup_delete_failed space=%s what=files err=%q", s.Name, err.Error())
			return s, nil, true
		}
		if err := op.Backup.Store.Delete(ctx, backupKey(s.Name)); err != nil {
			op.Log.Printf("event=space.backup_delete_failed space=%s err=%q", s.Name, err.Error())
			return s, nil, true
		}
	}
	// Удаляется аккаунт: после пространства и копий — ключи, устройства и разрешения в keyguard. Не вышло — Space
	// остаётся, попытка повторится (keyguard повтор принимает).
	if (s.DeleteKind == "account" || s.DeleteKind == "inactive") && op.Purge != nil {
		if err := op.Purge(ctx, s.Owner, s.DeleteKind); err != nil {
			op.Log.Printf("event=account.purge_failed space=%s err=%q", s.Name, err.Error())
			return s, nil, true
		}
		op.Log.Printf("event=account.purged space=%s owner=%s", s.Name, s.Owner)
	}
	if err := op.Kube.Delete(ctx, fmt.Sprintf(spacesAPI, op.Namespace)+"/"+s.Name); err != nil {
		op.Log.Printf("event=space.delete_failed space=%s err=%q", s.Name, err.Error())
		return s, nil, true
	}
	op.Log.Printf("event=space.deleted space=%s", s.Name)
	return s, nil, true
}
