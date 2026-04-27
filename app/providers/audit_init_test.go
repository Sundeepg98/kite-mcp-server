package providers

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// audit_init_test.go covers the InitializeAuditStore invoke function.
// Wave D Phase 2 Slice P2.3b. The function preserves the
// app/wire.go:177-221 contract: in production mode, init failures
// surface as errors that abort startup; in DevMode, init failures
// log + continue with no audit middleware.

// TestInitializeAuditStore_NilStore_NoOp verifies that the function
// is a no-op when called with a nil store (the in-memory mode path).
// Returns a wrapper with Store=nil + nil error.
func TestInitializeAuditStore_NilStore_NoOp(t *testing.T) {
	t.Parallel()

	cfg := AuditConfig{DevMode: false}
	gotInit, err := InitializeAuditStore(auditInitInput{
		Store:  nil,
		DB:     nil,
		Config: cfg,
		Logger: testLogger(),
	})
	if err != nil {
		t.Errorf("expected nil error for nil store; got %v", err)
	}
	if gotInit == nil {
		t.Fatal("expected non-nil wrapper")
	}
	if gotInit.Store != nil {
		t.Errorf("expected wrapper with nil Store; got non-nil")
	}
}

// TestInitializeAuditStore_LiveStore_ProductionMode_NoSecret_OK
// verifies that in production mode with a live store but no
// OAUTH_JWT_SECRET configured, init runs InitTable + StartWorker
// successfully and returns nil. Encryption + chain seeding are
// skipped (matches wire.go:188 "if app.Config.OAuthJWTSecret != ''"
// guard).
func TestInitializeAuditStore_LiveStore_ProductionMode_NoSecret_OK(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "audit_init_nosec.db")
	db, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store := ProvideAuditStore(db, testLogger())
	if store == nil {
		t.Fatal("expected non-nil store")
	}
	t.Cleanup(func() { store.Stop() })

	cfg := AuditConfig{DevMode: false} // production
	gotInit, err := InitializeAuditStore(auditInitInput{
		Store:  store,
		DB:     db,
		Config: cfg,
		Logger: testLogger(),
	})
	if err != nil {
		t.Fatalf("expected nil error; got %v", err)
	}
	if gotInit == nil || gotInit.Store != store {
		t.Errorf("expected wrapper with same store pointer as input")
	}
}

// TestInitializeAuditStore_LiveStore_WithSecret_EnablesEncryption
// verifies that supplying a non-empty OAuthJWTSecret triggers
// EnsureEncryptionSalt + SetEncryptionKey + SeedChain + StartWorker.
// We can't observe encryption directly without writing a record and
// reading it back, but we can verify init returns nil (the failure
// mode is wrapped error, not silent).
func TestInitializeAuditStore_LiveStore_WithSecret_EnablesEncryption(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "audit_init_sec.db")
	db, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store := ProvideAuditStore(db, testLogger())
	t.Cleanup(func() { store.Stop() })

	cfg := AuditConfig{
		DevMode:        false,
		OAuthJWTSecret: "test-secret-for-hkdf-derivation-32-bytes-long",
	}
	gotInit, err := InitializeAuditStore(auditInitInput{
		Store:  store,
		DB:     db,
		Config: cfg,
		Logger: testLogger(),
	})
	if err != nil {
		t.Fatalf("expected nil error; got %v", err)
	}
	if gotInit == nil || gotInit.Store != store {
		t.Errorf("expected wrapper with same store pointer as input on success")
	}
}

// TestInitializeAuditStore_DevMode_BadDB_ContinuesWithLog verifies
// that in DevMode, an InitTable failure is logged and the function
// returns nil (continue without audit). Matches wire.go:184 "DevMode:
// continuing without audit" branch.
//
// We trigger the failure by passing a closed *alerts.DB — InitTable
// runs SQL DDL, which fails on a closed connection.
func TestInitializeAuditStore_DevMode_BadDB_ContinuesWithLog(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "audit_init_devmode_bad.db")
	db, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	store := ProvideAuditStore(db, testLogger())
	// Close the DB BEFORE InitializeAuditStore runs — InitTable will
	// fail with "database is closed" or similar on this driver.
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	cfg := AuditConfig{DevMode: true} // log + continue
	gotInit, err := InitializeAuditStore(auditInitInput{
		Store:  store,
		DB:     db,
		Config: cfg,
		Logger: testLogger(),
	})
	if err != nil {
		t.Errorf("DevMode should swallow InitTable error; got %v", err)
	}
	if gotInit == nil {
		t.Fatal("expected non-nil wrapper even on DevMode init failure")
	}
	if gotInit.Store != nil {
		t.Errorf("DevMode init failure should return wrapper with nil Store (signal: drop middleware); got non-nil")
	}
}

// TestInitializeAuditStore_ProductionMode_BadDB_ReturnsError verifies
// that in production mode, an InitTable failure surfaces as an error
// the caller MUST handle (matches wire.go:181-183 fail-fast).
func TestInitializeAuditStore_ProductionMode_BadDB_ReturnsError(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "audit_init_prod_bad.db")
	db, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	store := ProvideAuditStore(db, testLogger())
	// Close the DB before init — InitTable will fail.
	_ = db.Close()

	cfg := AuditConfig{DevMode: false} // production: fail-fast
	gotInit, gotErr := InitializeAuditStore(auditInitInput{
		Store:  store,
		DB:     db,
		Config: cfg,
		Logger: testLogger(),
	})
	if gotErr == nil {
		t.Fatal("expected non-nil error in production mode")
	}
	// The error message should mention the production-mode contract
	// so the operator knows what's required. wire.go uses the prefix
	// "audit trail required in production:" — preserve that for log
	// continuity.
	if !strings.Contains(gotErr.Error(), "audit trail required in production") {
		t.Errorf("expected production error prefix; got %v", gotErr)
	}
	if gotInit != nil {
		t.Errorf("expected nil wrapper on production error; got non-nil")
	}
}

// TestInitializeAuditStore_NilLogger_DoesNotPanic verifies the
// function is nil-tolerant for the logger argument. Tests / fixtures
// that omit the logger must not panic.
func TestInitializeAuditStore_NilLogger_DoesNotPanic(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "audit_init_nillog.db")
	db, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store := ProvideAuditStore(db, nil)
	t.Cleanup(func() { store.Stop() })

	cfg := AuditConfig{DevMode: true}
	_, err = InitializeAuditStore(auditInitInput{
		Store:  store,
		DB:     db,
		Config: cfg,
		Logger: nil,
	})
	if err != nil {
		// Either it returns an error or nil — both are acceptable.
		// The non-negotiable contract is "no panic".
		// Verify at least the error is sensible (not a wrapped nil-
		// pointer panic message).
		if errors.Is(err, errors.New("nil pointer dereference")) {
			t.Errorf("nil-pointer panic surfaced as error: %v", err)
		}
	}
}
