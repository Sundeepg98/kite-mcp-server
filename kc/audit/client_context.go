package audit

import "context"

// client_context.go — context keys + accessors for client metadata
// (IP, User-Agent) propagated from HTTP middleware down to the MCP
// audit middleware.
//
// SEBI Annexure-I requires every order-affecting tool invocation to
// carry a verifiable client identifier. The HTTP layer at app/ captures
// IP + UA from the request, stuffs them in the context, and the MCP
// audit middleware here pulls them back out at INSERT time.

// auditCtxKey is a package-local type for context keys to prevent
// collisions with string-typed keys elsewhere.
type auditCtxKey string

const (
	clientIPCtxKey auditCtxKey = "audit.client_ip"
	clientUACtxKey auditCtxKey = "audit.client_ua"
)

// WithClientIP returns ctx augmented with the resolved client IP.
// Empty values are stored as-is — the worker writes empty columns when
// the upstream didn't propagate an IP (stdio MCP, dev mode, etc.).
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPCtxKey, ip)
}

// WithClientUA returns ctx augmented with the User-Agent string.
func WithClientUA(ctx context.Context, ua string) context.Context {
	return context.WithValue(ctx, clientUACtxKey, ua)
}

// ClientIPFromCtx extracts the IP set by WithClientIP. Empty string when
// not set.
func ClientIPFromCtx(ctx context.Context) string {
	if v, ok := ctx.Value(clientIPCtxKey).(string); ok {
		return v
	}
	return ""
}

// ClientUAFromCtx extracts the UA set by WithClientUA. Empty string when
// not set.
func ClientUAFromCtx(ctx context.Context) string {
	if v, ok := ctx.Value(clientUACtxKey).(string); ok {
		return v
	}
	return ""
}
