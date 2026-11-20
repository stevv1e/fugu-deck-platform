package keyguard

// Сертификат устройства для mTLS на api.<домен> (architecture.md 3.3, шаг 8): выпускает OpenBao pki-device
// по CSR, который телефон подписал КЛЮЧОМ СЕССИИ (закрытый ключ не покидает чип). Выпуск — только для
// подтверждённого устройства; ключ в CSR обязан совпасть с ключом сессии, к которому привязан токен Keycloak.
// Статус и сертификат приложение забирает запросом, подписанным тем же ключом сессии (как DPoP).

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type CertIssuer interface {
	Issue(ctx context.Context, csrPEM, deviceID string) (certPEM string, err error)
}

// BaoPKI — OpenBao pki-device/sign/device (политика keyguard.hcl разрешает ровно это).
type BaoPKI struct {
	Addr, Mount, Role, TTL string
	Token                  func(ctx context.Context) (string, error)
	HTTP                   *http.Client
}

func (b *BaoPKI) Issue(ctx context.Context, csrPEM, deviceID string) (string, error) {
	tok, err := b.Token(ctx)
	if err != nil {
		return "", err
	}
	// CN = ID устройства от keyguard (роль: use_csr_common_name=false — CN из CSR телефона игнорируется);
	// exclude_cn_from_sans — без лишнего DNS-имени в клиентском сертификате.
	body, _ := json.Marshal(map[string]any{"csr": csrPEM, "common_name": deviceID, "ttl": b.TTL, "format": "pem", "exclude_cn_from_sans": true})
	req, _ := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/v1/%s/sign/%s", b.Addr, b.Mount, b.Role), bytes.NewReader(body))
	req.Header.Set("X-Vault-Token", tok)
	r, err := b.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	var out struct {
		Data struct {
			Certificate string `json:"certificate"`
		} `json:"data"`
		Errors []string `json:"errors"`
	}
	json.NewDecoder(r.Body).Decode(&out)
	if r.StatusCode != 200 || out.Data.Certificate == "" {
		return "", fmt.Errorf("pki: %d %v", r.StatusCode, out.Errors)
	}
	return out.Data.Certificate, nil
}

// checkCSR — подпись CSR верна и ключ в нём = ключ сессии устройства.
func checkCSR(csrPEM string, session *ecdsa.PublicKey) error {
	blk, _ := pem.Decode([]byte(csrPEM))
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return errors.New("CSR: не PEM")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return errors.New("CSR: " + err.Error())
	}
	if csr.CheckSignature() != nil {
		return errors.New("CSR: подпись неверна")
	}
	pk, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pk.Equal(session) {
		return errors.New("CSR: ключ не совпадает с ключом сессии")
	}
	return nil
}

// issueFor — выпустить сертификат и сохранить в реестре; без выпуска устройство не активируется.
func (s *Server) issueFor(ctx context.Context, d *Device) error {
	if s.Certs == nil {
		return nil // выпуск выключен (одиночный режим, тесты без PKI)
	}
	cert, err := s.Certs.Issue(ctx, d.CSR, d.ID)
	if err != nil {
		return err
	}
	return s.Verifier.Devices.SetCert(d.ID, cert)
}

// POST /v1/devices/status {device_id, proof}: proof — JWS ES256 ключом сессии (typ dpop+jwt, htm POST,
// htu = StatusURL, свежий iat, одноразовый jti). Ответ: статус и, если подтверждено, сертификат.
func (s *Server) handleDeviceStatus(w http.ResponseWriter, r *http.Request) {
	if s.Enroll == nil {
		fail(w, 404, "регистрация не настроена")
		return
	}
	if c, err := s.caller(r); err != nil || c != s.ControlPlane {
		fail(w, 403, "только control-plane")
		return
	}
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	var q struct {
		DeviceID string `json:"device_id"`
		Proof    string `json:"proof"`
	}
	if json.Unmarshal(body, &q) != nil {
		fail(w, 400, "json")
		return
	}
	d, ok := s.Verifier.Devices.Get(q.DeviceID)
	if !ok {
		fail(w, 404, "устройство не найдено")
		return
	}
	now := s.Now()
	_, pc, err := verifyJWS(q.Proof, func(h map[string]any) (crypto.PublicKey, error) {
		if h["typ"] != "dpop+jwt" {
			return nil, errors.New("typ")
		}
		return d.SessionPub, nil // только ключ сессии ЭТОГО устройства
	})
	switch {
	case err != nil:
		fail(w, 403, "доказательство: "+err.Error())
		return
	case pc["htm"] != "POST" || pc["htu"] != s.Enroll.StatusURL:
		fail(w, 403, "доказательство не для этого запроса")
		return
	case abs64(now.Unix()-num64(pc["iat"])) > 300:
		fail(w, 403, "доказательство устарело")
		return
	}
	if jti, _ := pc["jti"].(string); len(jti) < 12 || !s.Verifier.Nonces.Use("status", jti, now) {
		fail(w, 403, "доказательство: повтор")
		return
	}
	s.markSeen(d.User) // приложение открывало экран кластера: человек активен
	st := map[string]string{"device_id": d.ID, "status": "active", "attested": d.Attested}
	switch {
	case d.Revoked:
		st["status"] = "revoked"
	case d.Pending:
		st["status"] = "pending"
	default:
		st["cert_pem"] = d.CertPEM
	}
	json.NewEncoder(w).Encode(st)
}

// thumb — RFC 7638 для ecdsa-ключа (для журналов и сверок).
func thumb(k *ecdsa.PublicKey) string {
	j := JWK{Kty: "EC", Crv: "P-256", X: base64.RawURLEncoding.EncodeToString(k.X.FillBytes(make([]byte, 32))),
		Y: base64.RawURLEncoding.EncodeToString(k.Y.FillBytes(make([]byte, 32)))}
	return j.Thumbprint()
}

var _ = sha256.Sum256
var _ = time.Now
