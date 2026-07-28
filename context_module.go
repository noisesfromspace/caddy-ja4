package ja4

import (
	"context"
	"crypto/tls"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/exaring/ja4plus"
)

func init() {
	caddy.RegisterModule(HandshakeContextModule{})
}

// HandshakeContextModule computes JA4 fingerprints during the TLS handshake
// via Caddy's TLS HandshakeContext hook and stores them in the global cache
// for the HTTP handler to retrieve.
type HandshakeContextModule struct{}

// CaddyModule returns module info.
func (HandshakeContextModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.context.ja4",
		New: func() caddy.Module { return new(HandshakeContextModule) },
	}
}

// Provision sets up the module.
func (m *HandshakeContextModule) Provision(_ caddy.Context) error {
	return nil
}

// HandshakeContext is called by Caddy during each TLS handshake, before the
// HTTP request is processed. It receives the parsed ClientHelloInfo, computes
// the JA4 fingerprint via the official ja4plus library, and stores it in the
// global cache keyed by the client's remote address.
func (m *HandshakeContextModule) HandshakeContext(hello *tls.ClientHelloInfo) (context.Context, error) {
	if hello == nil || hello.Conn == nil {
		return hello.Context(), nil
	}

	fp := ja4plus.JA4(hello)
	addr := normalizeAddr(hello.Conn.RemoteAddr().String())
	cacheSet(addr, fp)

	return hello.Context(), nil
}

// normalizeAddr strips optional IPv6 brackets from remote addresses
// so cache lookups are consistent regardless of formatting.
func normalizeAddr(addr string) string {
	if addr == "" {
		return addr
	}
	addr = strings.TrimPrefix(addr, "[")
	addr = strings.TrimSuffix(addr, "]")
	return addr
}

// Interface guards.
var (
	_ caddy.Module              = (*HandshakeContextModule)(nil)
	_ caddy.Provisioner         = (*HandshakeContextModule)(nil)
	_ caddytls.HandshakeContext = (*HandshakeContextModule)(nil)
)
