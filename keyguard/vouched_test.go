package keyguard

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Режим vouched: устройство без аттестации регистрируется, но активирует его только подпись аттестованного устройства.
func TestVouched(t *testing.T) {
	k := newRig(t)
	k.srv.Verifier.Devices = NewDevices()
	p := newIdP(t, k.now)
	k.srv.Certs = &fakeCA{}
	k.srv.Enroll = &EnrollConfig{Issuer: p.iss, JWKSURL: p.srv.URL, ClientID: "deck-app", EnrollURL: enrollURL, StatusURL: statusURL,
		Admins: []string{"admin"}, BootstrapUser: "admin", HTTP: http.DefaultClient}
	ap := NewAttestPolicy("vouched")
	ap.AndroidPackage, ap.AndroidCertDigests = "kz.fugudeck.app", [][]byte{make([]byte, 32)}
	k.srv.Attest = ap
	c := &check{t: t}
	now := k.now()
	enroll := func(d newDev, user string) (int, map[string]string) {
		tok := p.token(user, ecJWK(&d.sess.PublicKey).Thumbprint(), nil)
		st, body := k.do("POST", "/v1/devices", "tok-cp", d.req(tok, d.proof(tok, now, nil), d.enrollAction(now, nil, nil)), nil)
		var m map[string]string
		json.Unmarshal([]byte(body), &m)
		if st != 200 {
			m = map[string]string{"error": body}
		}
		return st, m
	}
	// устройство в реестре в обход регистрации: с аттестацией или без, активное или ждущее
	put := func(user, attested string, active bool) *phone {
		d := mkDev()
		dev := &Device{ID: DeviceIDFor(ecJWK(&d.conf.PublicKey).Thumbprint()), User: user, SessionPub: &d.sess.PublicKey,
			ConfirmPub: &d.conf.PublicKey, Pending: true, Name: "iPhone", Attested: attested}
		if err := k.srv.Verifier.Devices.Add(dev); err != nil {
			t.Fatal(err)
		}
		if active {
			k.srv.Verifier.Devices.Activate(dev.ID)
		}
		return &phone{dev: &Device{ID: dev.ID, User: user}, confirm: d.conf}
	}
	confirm := func(by *phone, user, target string) (int, string) {
		return k.do("POST", "/v1/devices/confirm", "tok-cp", j(by.sign(t, k, map[string]any{"type": "device_approve", "user": user, "target": target, "name": "iPhone"}, nil)), nil)
	}

	adm := mkDev()
	st, m := enroll(adm, "admin")
	c.ok("V1 первое устройство администратора без аттестации не активируется само", st == 200 && m["status"] == "pending", st, m)

	plain := put("admin", "", true)               // подтверждено раньше, без аттестации (например, до включения режима)
	chip := put("admin", "android-key/tee", true) // телефон с ключами в чипе

	anna := mkDev()
	_, m = enroll(anna, "anna")
	annaID := m["device_id"]
	st, body := confirm(plain, "anna", annaID)
	dv, _ := k.srv.Verifier.Devices.Get(annaID)
	c.ok("V2 устройство без аттестации не может подтвердить устройство без аттестации", st == 403 && strings.Contains(body, "аттестац") && dv.Pending, st, body)
	st, body = confirm(chip, "anna", annaID)
	dv, _ = k.srv.Verifier.Devices.Get(annaID)
	c.ok("V3 аттестованное устройство подтверждает устройство без аттестации", st == 200 && !dv.Pending, st, body)

	attestedPending := put("bob", "android-key/strongbox", false)
	st, body = confirm(plain, "bob", attestedPending.dev.ID)
	c.ok("V4 устройство с аттестацией подтверждается как раньше — любым допущенным устройством", st == 200, st, body)

	k.srv.Attest.Mode = "optional"
	carl := mkDev()
	_, m = enroll(carl, "carl")
	st, body = confirm(plain, "carl", m["device_id"])
	c.ok("V5 в режиме optional правило не действует", st == 200, st, body)

	k.srv.Attest.Mode = "vouched"
	bad := mkDev()
	tok := p.token("eve", ecJWK(&bad.sess.PublicKey).Thumbprint(), nil)
	req := map[string]any{}
	json.Unmarshal(bad.req(tok, bad.proof(tok, now, nil), bad.enrollAction(now, nil, nil)), &req)
	req["attestation"] = map[string]any{"session": map[string]any{"chain": []string{"AAAA"}}}
	raw, _ := json.Marshal(req)
	st, body = k.do("POST", "/v1/devices", "tok-cp", raw, nil)
	c.ok("V6 присланная, но негодная аттестация отклоняется сразу, а не уходит в ожидание", st == 403 && strings.Contains(body, "аттестация"), st, body)

	// восстановление администратора: в кластере есть действующие устройства (Анна, Боб), у администратора — нет
	for _, d := range k.srv.Verifier.Devices.List("admin") {
		k.srv.Verifier.Devices.Revoke(d.ID)
	}
	lost := mkDev()
	_, m = enroll(lost, "admin")
	c.ok("V7 без DECK_BOOTSTRAP_RECOVER новое устройство администратора ждёт подтверждения", m["status"] == "pending", m)
	k.srv.Enroll.Recover = true
	_, m = enroll(mkDev(), "admin")
	c.ok("V8 восстановление: устройство без аттестации всё равно ждёт (в vouched нужна аттестация)", m["status"] == "pending", m)
	_, m = enroll(mkDev(), "anna")
	c.ok("V9 восстановление касается только bootstrap-администратора", m["status"] == "pending", m)
	k.srv.Attest.Mode = "optional"
	_, m = enroll(mkDev(), "admin")
	c.ok("V10 восстановление в optional: устройство администратора без своих действующих активируется само", m["status"] == "active", m)
	_, m = enroll(mkDev(), "admin")
	c.ok("V11 следующее устройство администратора — снова через подтверждение", m["status"] == "pending", m)

	// список отозванных — только для control-plane и только ID
	st, body = k.do("POST", "/v1/devices/revoked", "tok-cp", []byte(`{}`), nil)
	c.ok("V12 control-plane получает ID отозванных устройств", st == 200 && strings.Contains(body, plain.dev.ID) && !strings.Contains(body, "admin"), st, body)
	st, _ = k.do("POST", "/v1/devices/revoked", "tok-anna", []byte(`{}`), nil)
	c.ok("V13 не control-plane — 403", st == 403, st)
}
