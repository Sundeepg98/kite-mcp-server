package app

// client_metadata.go — HTTP middleware that captures client IP +
// User-Agent and stuffs them in the request context for downstream
// audit middleware (kc/audit/middleware.go) to record on every
// MCP tool call. SEBI Annexure-I requires both fields on every
// order-affecting invocation.

import (
	"net"
	"net/http"
	"strings"

	"github.com/zerodha/kite-mcp-server/kc/audit"
)

// withClientMetadata extracts client IP and User-Agent from the request
// and propagates them via context so the MCP audit middleware can
// record them on the tool_calls row.
//
// IP resolution prefers the leftmost X-Forwarded-For entry (Fly.io
// proxies inject it), falls back to RemoteAddr's host:port. The
// resulting string is empty only when both sources are missing/garbage,
// which on a real HTTP request shouldn't happen.
//
// UA passes through verbatim — empty string is fine and stored as-is.
func withClientMetadata(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := resolveClientIP(r)
		ua := r.UserAgent()
		ctx := r.Context()
		ctx = audit.WithClientIP(ctx, ip)
		ctx = audit.WithClientUA(ctx, ua)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// resolveClientIP returns the originating client IP, preferring the
// leftmost X-Forwarded-For value (Fly.io / load-balancer proxy header)
// over r.RemoteAddr.
//
// Returns empty string only on bizarre input (no XFF header, RemoteAddr
// unparseable). Never returns the host:port form — strips the port.
func resolveClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Leftmost entry is the original client; subsequent entries are
		// proxies. Some upstreams send "client, proxy1, proxy2".
		if i := strings.Index(xff, ","); i >= 0 {
			xff = xff[:i]
		}
		ip := strings.TrimSpace(xff)
		if ip != "" {
			return ip
		}
	}
	if r.RemoteAddr != "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err == nil {
			return host
		}
		// SplitHostPort fails when there's no port (rare with the
		// stdlib server but possible on test paths). Treat the whole
		// string as the IP.
		return r.RemoteAddr
	}
	return ""
}
