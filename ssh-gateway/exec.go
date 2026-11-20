package sshgateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Result — итог выполнения команды.
type Result struct {
	ExitCode  int    `json:"exit_code"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	Truncated bool   `json:"truncated"` // вывод обрезан по лимиту
	TimedOut  bool   `json:"timed_out"`
	Millis    int64  `json:"duration_ms"`
}

// Runner выполняет команду на сервере (в тестах подменяется).
type Runner interface {
	Run(ctx context.Context, s Server, principal, command string) (Result, error)
}

// SSHRunner — настоящее выполнение: новый ключ и сертификат на каждую команду, ключ хоста сверяется с подписанным
// отпечатком, оболочки с терминалом нет, вывод и время ограничены.
type SSHRunner struct {
	Signer       CertSigner
	Timeout      time.Duration // на всю команду (5 мин)
	MaxOutput    int           // байт на stdout и на stderr
	AllowPrivate bool          // разрешить частные адреса (только стенды и тесты)
	// Resolve — имя → адреса (в тестах подменяется).
	Resolve func(ctx context.Context, host string) ([]net.IP, error)
}

// ErrForbiddenAddress — адрес сервера ведёт внутрь кластера или в частную сеть.
var ErrForbiddenAddress = errors.New("адрес сервера не публичный")

// publicIP — можно ли шлюзу подключаться к этому адресу. Кластер, локальная сеть, loopback, link-local (метаданные
// облака 169.254.169.254) и CGNAT закрыты: иначе «сервер пользователя» стал бы способом ходить по внутренней сети.
func publicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 100 && v4[1]&0xc0 == 64: // 100.64.0.0/10 — CGNAT
			return false
		case v4[0] == 0, v4[0] >= 224: // «эта сеть», многоадресные и зарезервированные
			return false
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 0: // 192.0.0.0/24
			return false
		case v4[0] == 198 && (v4[1] == 18 || v4[1] == 19): // 198.18.0.0/15 — стенды
			return false
		}
	}
	return true
}

func (r *SSHRunner) resolve(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !r.AllowPrivate && !publicIP(ip) {
			return nil, ErrForbiddenAddress
		}
		return ip, nil
	}
	res := r.Resolve
	if res == nil {
		res = func(ctx context.Context, h string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", h)
		}
	}
	ips, err := res(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("имя %s не разрешается", host)
	}
	// Все адреса имени должны быть публичными: иначе имя с двумя записями дало бы шанс попасть внутрь.
	for _, ip := range ips {
		if !r.AllowPrivate && !publicIP(ip) {
			return nil, ErrForbiddenAddress
		}
	}
	return ips[0], nil
}

// hostKeyAlgos — виды ключа хоста в порядке попыток: сначала тот, что приложение просит указать (ed25519).
var hostKeyAlgos = [][]string{
	{ssh.KeyAlgoED25519},
	{ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521},
	{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256},
}

// errHostKey — сервер предъявил не тот ключ, чей отпечаток подписал владелец.
type errHostKey struct{ got, want string }

func (e errHostKey) Error() string {
	return "ключ хоста " + e.got + " не совпал с подписанным " + e.want
}

// capped — буфер, который принимает не больше limit байт и запоминает, что вывод был длиннее.
type capped struct {
	buf   bytes.Buffer
	limit int
	over  bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.limit - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
			c.over = true
		} else {
			c.buf.Write(p)
		}
	} else if len(p) > 0 {
		c.over = true
	}
	return len(p), nil // команду не обрываем: её вывод просто не сохраняется дальше лимита
}

func (r *SSHRunner) Run(ctx context.Context, s Server, principal, command string) (Result, error) {
	var res Result
	ip, err := r.resolve(ctx, s.Host)
	if err != nil {
		return res, err
	}
	// Ключ живёт одну команду и никуда не записывается; сертификат на него — 10 минут.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return res, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return res, err
	}
	certLine, err := r.Signer.Sign(ctx, string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(sshPub))), principal)
	if err != nil {
		return res, fmt.Errorf("сертификат: %w", err)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certLine))
	if err != nil {
		return res, fmt.Errorf("сертификат не разобран: %w", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		return res, errors.New("OpenBao вернул не сертификат")
	}
	keySigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return res, err
	}
	certSigner, err := ssh.NewCertSigner(cert, keySigner)
	if err != nil {
		return res, err
	}
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	start := time.Now()
	// У сервера несколько ключей хоста (ed25519, ecdsa, rsa), а человек подписал отпечаток одного. Какой из них сервер
	// предъявит, зависит от согласования, поэтому просим по очереди каждый вид, пока отпечаток не совпадёт.
	// Несовпадение по всем видам — отказ: «доверять при первом подключении» здесь нет.
	var client *ssh.Client
	var lastErr error
	for _, algos := range hostKeyAlgos {
		cfg := &ssh.ClientConfig{
			User: s.User, Auth: []ssh.AuthMethod{ssh.PublicKeys(certSigner)}, Timeout: 15 * time.Second, HostKeyAlgorithms: algos,
			HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
				if got := ssh.FingerprintSHA256(key); got != s.HostKey {
					return errHostKey{got: got, want: s.HostKey}
				}
				return nil
			},
		}
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(s.Port)))
		if err != nil {
			return res, fmt.Errorf("подключение: %w", err)
		}
		conn.SetDeadline(time.Now().Add(r.Timeout + 20*time.Second))
		cc, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(s.Host, strconv.Itoa(s.Port)), cfg)
		if err == nil {
			client = ssh.NewClient(cc, chans, reqs)
			break
		}
		conn.Close()
		var hk errHostKey
		if errors.As(err, &hk) || lastErr == nil {
			lastErr = err // «ключ не совпал» понятнее человеку, чем «у сервера нет ключа такого вида»
		}
		if !errors.As(err, &hk) && !strings.Contains(err.Error(), "no common algorithm for host key") {
			lastErr = err
			break // сервер предъявил нужный ключ, но не пустил (или другая ошибка): перебор видов ключа не поможет
		}
	}
	if client == nil {
		return res, fmt.Errorf("вход по SSH: %w", lastErr)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return res, fmt.Errorf("сессия SSH: %w", err)
	}
	defer sess.Close()
	out, errb := &capped{limit: r.MaxOutput}, &capped{limit: r.MaxOutput}
	sess.Stdout, sess.Stderr = out, errb // без терминала и без stdin: интерактивной оболочки нет
	done := make(chan error, 1)
	go func() { done <- sess.Run(command) }()
	select {
	case err = <-done:
	case <-ctx.Done():
		sess.Signal(ssh.SIGKILL)
		client.Close()
		res.TimedOut = true
		err = nil
		res.ExitCode = -1
	}
	res.Millis = time.Since(start).Milliseconds()
	res.Stdout, res.Stderr, res.Truncated = out.buf.String(), errb.buf.String(), out.over || errb.over
	if err != nil {
		var ee *ssh.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitStatus()
			return res, nil // ненулевой код выхода — это результат команды, а не сбой шлюза
		}
		var me *ssh.ExitMissingError
		if errors.As(err, &me) {
			res.ExitCode = -1
			return res, nil
		}
		return res, fmt.Errorf("выполнение: %w", err)
	}
	return res, nil
}
