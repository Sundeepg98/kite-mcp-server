package providers

import (
	"path/filepath"
	"testing"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// audit_middleware_test.go covers ProvideAuditMiddleware. Wave D
// Phase 2 Slice P2.3b. The provider is a pure function:
//
//	nil wrapper or wrapper with nil Store → nil middleware
//	wrapper with populated Store         → audit.Middleware(store)
//
// We don't exercise the middleware's runtime semantics (those live in
// kc/audit/middleware_test.go); we just pin the wrapping contract.

// TestProvideAuditMiddleware_NilWrapper_ReturnsNil verifies that a
// nil *InitializedAuditStore input yields a nil middleware. The
// nil-wrapper case shouldn't occur in normal Fx graph wiring (the
// provider always returns a non-nil wrapper), but the provider
// defends against it for direct-test callers.
func TestProvideAuditMiddleware_NilWrapper_ReturnsNil(t *testing.T) {
	t.Parallel()

	mw := ProvideAuditMiddleware(nil)
	if mw != nil {
		t.Errorf("expected nil middleware for nil wrapper; got %T", mw)
	}
}

// TestProvideAuditMiddleware_NilStore_ReturnsNil verifies that a
// wrapper with a nil Store field yields a nil middleware. This is
// the standard signal from InitializeAuditStore for "audit chain
// did not complete" (in-memory mode or DevMode-init-failed).
// Composition sites (wire.go) rely on this nil-middleware to gate
// registration via `if auditMiddleware != nil`.
func TestProvideAuditMiddleware_NilStore_ReturnsNil(t *testing.T) {
	t.Parallel()

	mw := ProvideAuditMiddleware(&InitializedAuditStore{Store: nil})
	if mw != nil {
		t.Errorf("expected nil middleware for nil-Store wrapper; got %T", mw)
	}
}

// TestProvideAuditMiddleware_LiveStore_ReturnsMiddleware verifies
// that a wrapper with a populated Store yields a non-nil middleware.
// We don't invoke the middleware (handler chain wiring is separate);
// we just observe the wrapping happened.
func TestProvideAuditMiddleware_LiveStore_ReturnsMiddleware(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "audit_mw_test.db")
	db, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store := ProvideAuditStore(db, testLogger())
	t.Cleanup(func() { store.Stop() })

	mw := ProvideAuditMiddleware(&InitializedAuditStore{Store: store})
	if mw == nil {
		t.Fatal("expected non-nil middleware for populated wrapper")
	}
}
