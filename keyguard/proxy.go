package keyguard

import (
	"fmt"
	"net/http"
	"net/url"
)

func NewProviderProxyClient(base *http.Client, raw string) (*http.Client, error) {
	if base == nil {
		return nil, fmt.Errorf("базовый HTTP client не задан")
	}
	proxy, err := url.Parse(raw)
	if err != nil || (proxy.Scheme != "http" && proxy.Scheme != "https") || proxy.Host == "" {
		return nil, fmt.Errorf("proxy должен быть абсолютным HTTP(S) URL")
	}
	transport := base.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	t, ok := transport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("базовый HTTP transport не поддерживает proxy")
	}
	client := *base
	client.Transport = t.Clone()
	client.Transport.(*http.Transport).Proxy = http.ProxyURL(proxy)
	return &client, nil
}

func (s *Server) providerHTTP(p *Provider) *http.Client {
	if p.HTTP != nil {
		return p.HTTP
	}
	return s.Upstream
}
