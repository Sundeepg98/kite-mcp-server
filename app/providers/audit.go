package providers

import (
	"log/slog"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
)

// ProvideAuditStore wraps an opened *alerts.DB as an *audit.Store.
// Returns nil when the input DB is nil (in-memory mode), matching
// app/wire.go:178's nil-DB branch where audit middleware is simply
// not wired.
//
// CONTRACT
//
//	nil          — alertDB is nil (in-memory mode); audit chain disabled.
//	*audit.Store — alertDB is live; the returned store is constructed
//	               but NOT yet initialized. The caller (P2.3 composition)
//	               is responsible for the post-construction sequence:
//	                 1. store.InitTable()       — creates the SQL schema
//	                 2. store.SetEncryptionKey  — derived from OAUTH_JWT_SECRET
//	                 3. store.SeedChain()       — initializes hash chain head
//	                 4. store.SetLogger(logger) — wires log output
//	                 5. store.StartWorker()     — async writer goroutine
//	               And the lifecycle hook for store.Stop() on shutdown.
//
// Why is the post-construction sequence NOT inside this provider?
//
// Two reasons:
//
// (1) The sequence is policy-laden. wire.go:178-221 has:
//     - DevMode-vs-production fail-fast on InitTable failure
//     - Conditional encryption based on whether OAUTH_JWT_SECRET is set
//     - Hash-publisher startup with separate cancel context
//   Encoding all of that here would replicate ~80 LOC of branching
//   inside what is supposed to be a pure provider. Better to let
//   P2.3 (composition site with full app.Config in scope) own the
//   policy decisions; this provider just hands off the constructed
//   store.
//
// (2) Lifecycle timing differs from construction. The fx.Lifecycle
//     OnStart hook is the right home for InitTable + StartWorker;
//     OnStop owns store.Stop. Putting them inside the provider would
//     mean providers receive fx.Lifecycle, which couples every
//     provider to fx — preventing isolated provider testing.
//
// Returns *audit.Store (not the AuditStoreInterface in kc/interfaces.go)
// because the consuming composition needs the concrete methods (InitTable,
// SetEncryptionKey, StartWorker, Stop, etc.) that the interface does
// not surface. The interface is for downstream call-sites that only
// read; this provider is for the wiring path.
func ProvideAuditStore(db *alerts.DB, logger *slog.Logger) *audit.Store {
	if db == nil {
		return nil
	}
	return audit.New(db)
}
