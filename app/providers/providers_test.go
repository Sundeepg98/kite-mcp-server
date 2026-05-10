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
	"strings"
	"testing"

	"github.com/algo2go/kite-mcp-alerts"
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

// TestProvideAlertDB_DefaultDriver_IsSQLite verifies that an empty Driver
// field defaults to sqlite (preserves pre-Phase-2.3 behavior). The legacy
// AlertDBConfig had only Path — empty Driver MUST behave identically.
func TestProvideAlertDB_DefaultDriver_IsSQLite(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "default_driver.db")
	got, err := ProvideAlertDB(AlertDBConfig{Path: dbPath}, testLogger())
	if err != nil {
		t.Fatalf("expected nil error; got %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil DB")
	}
	t.Cleanup(func() { _ = got.Close() })

	if got.Dialect() != alerts.DialectSQLite {
		t.Errorf("default driver should be SQLite; got %q", got.Dialect())
	}
}

// TestProvideAlertDB_ExplicitSQLite_OpensDB verifies that an explicit
// Driver="sqlite" + Path opens the SQLite database (same as default).
func TestProvideAlertDB_ExplicitSQLite_OpensDB(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "explicit_sqlite.db")
	got, err := ProvideAlertDB(AlertDBConfig{Driver: "sqlite", Path: dbPath}, testLogger())
	if err != nil {
		t.Fatalf("expected nil error; got %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil DB")
	}
	t.Cleanup(func() { _ = got.Close() })

	if got.Dialect() != alerts.DialectSQLite {
		t.Errorf("Driver='sqlite' should yield SQLite dialect; got %q", got.Dialect())
	}
}

// TestProvideAlertDB_PostgresDriver_EmptyURL_Errors verifies that
// Driver="postgres" with an empty URL is a configuration error (the
// SQLite empty-path silent-downgrade contract does NOT apply to
// Postgres — there's no in-memory Postgres equivalent).
func TestProvideAlertDB_PostgresDriver_EmptyURL_Errors(t *testing.T) {
	t.Parallel()

	got, err := ProvideAlertDB(AlertDBConfig{Driver: "postgres", URL: ""}, testLogger())
	if err == nil {
		t.Fatal("expected error for postgres driver with empty URL")
	}
	if got != nil {
		t.Errorf("expected nil DB on config error; got non-nil")
	}
}

// TestProvideAlertDB_UnknownDriver_Errors verifies that any non-sqlite,
// non-postgres, non-turso Driver value returns an error. Unknown drivers
// are config bugs and must surface, not silently fall through.
func TestProvideAlertDB_UnknownDriver_Errors(t *testing.T) {
	t.Parallel()

	got, err := ProvideAlertDB(AlertDBConfig{Driver: "mysql", Path: "/tmp/x.db"}, testLogger())
	if err == nil {
		t.Fatal("expected error for unknown driver")
	}
	if got != nil {
		t.Errorf("expected nil DB on unknown driver; got non-nil")
	}
}

// TestProvideAlertDB_TursoDriver_EmptyURL_Errors verifies that
// Driver="turso" with an empty URL is a configuration error. Like
// Postgres, libSQL has no in-memory mode — empty URL means the
// operator forgot to set ALERT_DB_URL.
//
// Phase 2.6 Path 6 deliverable per kite-mcp-server R-10 v7 doc.
//
// Asserts the SPECIFIC turso-related error message — NOT the
// "unknown driver" default-branch error. This is the test that
// catches the missing case "turso" arm in the switch.
func TestProvideAlertDB_TursoDriver_EmptyURL_Errors(t *testing.T) {
	t.Parallel()

	got, err := ProvideAlertDB(AlertDBConfig{Driver: "turso", URL: ""}, testLogger())
	if err == nil {
		t.Fatal("expected error for turso driver with empty URL")
	}
	if got != nil {
		t.Errorf("expected nil DB on config error; got non-nil")
	}
	// Must hit the Turso-specific empty-URL branch, NOT fall through
	// to the default "unknown driver" arm.
	want := "turso driver requires URL"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("expected error containing %q (turso-specific message); got %q", want, err.Error())
	}
}

// TestProvideAlertDB_TursoDriver_InvalidURL_Errors verifies that
// Driver="turso" with an unreachable URL surfaces as error (no
// silent downgrade — symmetric with Postgres path).
//
// We use a deliberately-malformed URL that cannot reach any real
// libSQL endpoint; the error happens at sql.Open OR Ping time, both
// of which OpenLibSQL surfaces as wrapped errors.
//
// Asserts the error message comes from OpenLibSQL (libSQL-specific),
// NOT from the default-branch "unknown driver" arm.
func TestProvideAlertDB_TursoDriver_InvalidURL_Errors(t *testing.T) {
	t.Parallel()

	got, err := ProvideAlertDB(AlertDBConfig{
		Driver: "turso",
		URL:    "libsql://nonexistent.invalid-host.example.invalid?authToken=fake",
	}, testLogger())
	if err == nil {
		t.Fatal("expected error for turso driver with unreachable URL")
	}
	if got != nil {
		t.Errorf("expected nil DB on open failure; got non-nil")
	}
	// Must hit the Turso-specific arm — error wrapped by ProvideAlertDB
	// or by OpenLibSQL itself. Either way, "turso" or "libsql" must
	// appear in the error chain (NOT "unknown driver").
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "turso") && !strings.Contains(msg, "libsql") {
		t.Errorf("expected turso/libsql-specific error; got %q", err.Error())
	}
	if strings.Contains(msg, "unknown driver") {
		t.Errorf("error indicates default-branch fallthrough (case 'turso' missing): %q", err.Error())
	}
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
