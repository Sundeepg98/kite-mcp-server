// Package providers — Fx provider declarations for the Wave D Phase 2
// Wire/fx adoption. See .research/wave-d-phase-2-wire-fx-plan.md for the
// slice plan and §3.3 for the Wire-vs-Fx rationale.
//
// providers_test.go covers Slice P2.2: declares the LEAF providers
// (logger, alertDB, audit) and proves they compile under the expected
// Fx signature. Tests construct providers in isolation; no fx.New
// graph yet — that lands in P2.3.
package providers

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// testLogger returns a discard-handler slog.Logger for tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// --- Logger provider ---

// TestProvideLogger_Passthrough verifies that ProvideLogger returns the
// caller-supplied logger unchanged. The Logger is externally supplied
// (today via NewApp(logger), tomorrow via fx.Supply) — the provider's
// only job is to expose it to the graph as a typed dependency.
func TestProvideLogger_Passthrough(t *testing.T) {
	t.Parallel()

	in := testLogger()
	out := ProvideLogger(in)

	if out == nil {
		t.Fatal("expected non-nil logger")
	}
	if out != in {
		t.Errorf("expected passthrough; got different *slog.Logger pointer")
	}
}

// TestProvideLogger_NilSupplied verifies that ProvideLogger surfaces a
// nil input as nil (it's the caller's responsibility to supply a real
// logger; the provider does not synthesize one). Matches the existing
// app.NewApp contract where a nil logger is permitted but downstream
// behaviour is undefined.
func TestProvideLogger_NilSupplied(t *testing.T) {
	t.Parallel()

	got := ProvideLogger(nil)
	if got != nil {
		t.Errorf("expected nil passthrough; got %T", got)
	}
}

// --- AlertDB provider ---

// TestProvideAlertDB_EmptyPath_ReturnsNilNoError verifies the
// "in-memory mode" contract: when AlertDBPath is empty, the provider
// returns (nil, nil). Downstream consumers must nil-check the *alerts.DB
// before using it. This matches the existing app/wire.go:62-69
// behaviour where an empty path silently disables persistence.
func TestProvideAlertDB_EmptyPath_ReturnsNilNoError(t *testing.T) {
	t.Parallel()

	got, err := ProvideAlertDB(AlertDBConfig{Path: ""}, testLogger())
	if err != nil {
		t.Fatalf("expected nil error for empty path; got %v", err)
	}
	if got != nil {
		t.Errorf("expected nil DB for empty path; got non-nil")
	}
}

// TestProvideAlertDB_FilePath_OpensDB verifies that supplying a valid
// path opens the SQLite database and returns a non-nil handle.
func TestProvideAlertDB_FilePath_OpensDB(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "test_alerts.db")
	got, err := ProvideAlertDB(AlertDBConfig{Path: dbPath}, testLogger())
	if err != nil {
		t.Fatalf("expected nil error for valid path; got %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil DB for valid path")
	}
	t.Cleanup(func() {
		_ = got.Close()
	})
}

// Note on the absent "bad path" test:
//
// We considered a third test case for ProvideAlertDB that exercises the
// open-failure path (silent downgrade per app/wire.go:62-69 contract).
// Skipped because modernc.org/sqlite's sql.Open is lazy — it does not
// touch the filesystem until first query. Triggering a real open-time
// failure requires either an OS-specific fragile setup (unwritable
// directory; varies under WSL/CI) or corrupting an existing file. The
// silent-downgrade contract IS still tested via the empty-path branch
// above; both paths return (nil, nil) and downstream consumers must
// nil-check uniformly. If P2.3 composition exposes a need to
// distinguish "no DB configured" from "DB failed to open", we'll add
// an instrumented variant — until then the provider's external
// observable is identical for both paths.

// --- AuditStore provider ---

// TestProvideAuditStore_NilDB_ReturnsNil verifies that when alertDB is
// nil (in-memory mode), the audit-store provider returns nil. This
// matches the existing app/wire.go:178 nil-DB branch where audit
// middleware is simply not wired.
func TestProvideAuditStore_NilDB_ReturnsNil(t *testing.T) {
	t.Parallel()

	got := ProvideAuditStore(nil, testLogger())
	if got != nil {
		t.Errorf("expected nil store for nil DB; got non-nil")
	}
}

// TestProvideAuditStore_LiveDB_ReturnsStore verifies that a non-nil DB
// produces a live audit.Store. The provider does NOT yet call InitTable
// or StartWorker — those side-effects are deferred to the lifecycle
// hooks that P2.3 wires via fx.Lifecycle. This separation lets the
// provider stay pure (no I/O) while lifecycle remains explicit.
func TestProvideAuditStore_LiveDB_ReturnsStore(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "audit_test.db")
	db, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	got := ProvideAuditStore(db, testLogger())
	if got == nil {
		t.Fatal("expected non-nil audit store for live DB")
	}
}
