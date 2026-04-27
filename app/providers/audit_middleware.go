package providers

import (
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc/audit"
)

// audit_middleware.go — Wave D Phase 2 Slice P2.3b. Pure function
// provider: wraps a possibly-nil *audit.Store as a possibly-nil
// server.ToolHandlerMiddleware. The composition site uses
// `if mw != nil` to decide whether to register the middleware
// (matches the existing wire.go:584 conditional).

// ProvideAuditMiddleware returns the audit middleware for the
// post-init store, or nil when the store wrapper indicates the
// chain did not complete (in-memory mode / DevMode-DB-init-failed
// mode).
//
// Consumes *InitializedAuditStore (not *audit.Store directly) so
// that Fx wires this provider downstream of InitializeAuditStore in
// the type graph — the middleware is computed from the post-init
// store, not the raw supplied store. The wrapper's nil-or-populated
// Store field signals init success.
//
// Pure function. No I/O, no goroutines. Safe to call from any
// provider context.
func ProvideAuditMiddleware(initialized *InitializedAuditStore) server.ToolHandlerMiddleware {
	if initialized == nil || initialized.Store == nil {
		return nil
	}
	return audit.Middleware(initialized.Store)
}
