package app

import (
	"net/http"

	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
)

// clientHintedResolver adapts *kc.ClientHintResolver to the mcp-go
// server.SessionIdManagerResolver interface. The kc package cannot import
// mcp-go/server (it would create an import cycle through the mcp package),
// so the thin adapter lives here in the app layer.
//
// The two hops (kc.ClientHintResolver → hintedSessionIdManager,
// app.clientHintedResolver → app.mcpSessionIdManagerAdapter) exist purely
// to keep package boundaries clean. Zero business logic lives here.
type clientHintedResolver struct {
	inner *kc.ClientHintResolver
}

func newClientHintedResolver(registry *kc.SessionRegistry) *clientHintedResolver {
	return &clientHintedResolver{inner: kc.NewClientHintResolver(registry)}
}

// ResolveSessionIdManager is the mcp-go server.SessionIdManagerResolver
// implementation. It delegates to the inner kc resolver, then wraps the
// returned shim so mcp-go sees a proper server.SessionIdManager.
func (r *clientHintedResolver) ResolveSessionIdManager(req *http.Request) server.SessionIdManager {
	return &mcpSessionIdManagerAdapter{inner: r.inner.ResolveSessionIdManager(req)}
}

// mcpSessionIdManagerAdapter bridges kc.SessionIdManagerShim to
// server.SessionIdManager. The two interfaces are structurally identical —
// the shim exists only to avoid a kc → mcp-go import.
type mcpSessionIdManagerAdapter struct {
	inner kc.SessionIdManagerShim
}

func (a *mcpSessionIdManagerAdapter) Generate() string {
	return a.inner.Generate()
}

func (a *mcpSessionIdManagerAdapter) Validate(sessionID string) (isTerminated bool, err error) {
	return a.inner.Validate(sessionID)
}

func (a *mcpSessionIdManagerAdapter) Terminate(sessionID string) (isNotAllowed bool, err error) {
	return a.inner.Terminate(sessionID)
}

// Compile-time interface checks — fail loudly at build time if the
// mcp-go interface changes out from under us.
var (
	_ server.SessionIdManagerResolver = (*clientHintedResolver)(nil)
	_ server.SessionIdManager         = (*mcpSessionIdManagerAdapter)(nil)
)
