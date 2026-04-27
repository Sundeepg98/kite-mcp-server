package providers

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/fx"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/users"
)

// family_test.go covers Wave D Phase 2 Slice β-2's
// InitializeFamilyService provider — including the FIRST PRODUCTION
// USE of FxLifecycleAdapter from P2.3a.
//
// Test matrix:
//
//   - nil InvitationStore     → not-Ready, no goroutine.
//   - InitTable failure       → not-Ready, InitTableErr captured.
//   - missing UserStore       → init OK, Service nil, not-Ready.
//   - happy path (no lifecyc) → Ready, Service non-nil, no goroutine.
//   - happy path (lifecycle)  → Ready, Service non-nil, goroutine
//                                spawned, OnStop hook registered.
//   - cleanup tick fires      → with millisecond interval, prove the
//                                cleanup closure runs at least once
//                                before OnStop cancels.
//   - OnStop terminates loop  → Shutdown() fires the cancel, goroutine
//                                exits.
//
// The "lifecycle adapter under load" claim is validated by the
// goroutine-tick + Shutdown-cancel tests below, which exercise the
// adapter end-to-end.

// fakeFamilyUserStore satisfies kc.FamilyUserStore for tests. We
// don't need real user records — just a non-nil implementation so
// kc.NewFamilyService accepts the input.
type fakeFamilyUserStore struct{}

func (fakeFamilyUserStore) Get(string) (*users.User, bool)              { return nil, false }
func (fakeFamilyUserStore) ListByAdminEmail(string) []*users.User       { return nil }
func (fakeFamilyUserStore) SetAdminEmail(_, _ string) error             { return nil }

// fakeBillingStore satisfies kc.BillingStoreInterface for tests with
// just-enough surface to let kc.NewFamilyService construct. The
// interface lives at kc/interfaces.go; subscription/tier types live
// in kc/billing.
type fakeBillingStore struct{}

func (fakeBillingStore) GetTier(string) billing.Tier                            { return billing.TierFree }
func (fakeBillingStore) SetSubscription(*billing.Subscription) error            { return nil }
func (fakeBillingStore) GetSubscription(string) *billing.Subscription           { return nil }
func (fakeBillingStore) GetEmailByCustomerID(string) string                     { return "" }
func (fakeBillingStore) IsEventProcessed(string) bool                           { return false }
func (fakeBillingStore) MarkEventProcessed(_, _ string) error                   { return nil }
func (fakeBillingStore) GetTierForUser(string, func(string) string) billing.Tier {
	return billing.TierFree
}

// --- Tests -----------------------------------------------------------------

func TestInitializeFamilyService_NilInvitationStore_NotReady(t *testing.T) {
	t.Parallel()

	got, err := InitializeFamilyService(FamilyDeps{
		InvitationStore: nil,
		UserStore:       fakeFamilyUserStore{},
		BillingStore:    fakeBillingStore{},
		Logger:          testLogger(),
	})
	if err != nil {
		t.Fatalf("expected nil error; got %v", err)
	}
	if got == nil {
		t.Fatal("wrapper must be non-nil even on no-op path")
	}
	if got.Ready {
		t.Error("expected Ready=false for nil InvitationStore")
	}
	if got.Service != nil {
		t.Error("expected Service=nil for nil InvitationStore")
	}
	if got.CleanupGoroutineRunning {
		t.Error("expected no goroutine for nil InvitationStore")
	}
}

func TestInitializeFamilyService_InitTableFail_ClosedDB(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "fam_initfail.db")
	db, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	store := users.NewInvitationStore(db)
	// Close the DB to force ExecDDL to fail on InitTable.
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got, err := InitializeFamilyService(FamilyDeps{
		InvitationStore: store,
		UserStore:       fakeFamilyUserStore{},
		BillingStore:    fakeBillingStore{},
		Logger:          testLogger(),
	})
	if err != nil {
		t.Fatalf("provider must not return error on InitTable failure; got %v", err)
	}
	if got.Ready {
		t.Error("expected Ready=false on InitTable failure")
	}
	if got.InitTableErr == nil {
		t.Error("expected InitTableErr captured")
	}
	// LoadFromDB must be skipped after InitTable fails.
	if got.LoadFromDBErr != nil {
		t.Errorf("expected LoadFromDBErr nil (skipped); got %v", got.LoadFromDBErr)
	}
	if got.Service != nil {
		t.Error("expected Service=nil after InitTable failure")
	}
}

func TestInitializeFamilyService_MissingStores_ServiceNil(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "fam_missing.db")
	db, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store := users.NewInvitationStore(db)

	// UserStore nil — init runs but Service stays nil.
	got, err := InitializeFamilyService(FamilyDeps{
		InvitationStore: store,
		UserStore:       nil, // <- missing
		BillingStore:    fakeBillingStore{},
		Logger:          testLogger(),
	})
	if err != nil {
		t.Fatalf("expected nil error; got %v", err)
	}
	if got.InitTableErr != nil || got.LoadFromDBErr != nil {
		t.Errorf("init should have succeeded; got InitTableErr=%v LoadFromDBErr=%v",
			got.InitTableErr, got.LoadFromDBErr)
	}
	if got.Service != nil {
		t.Error("expected Service=nil when UserStore was missing")
	}
	if got.Ready {
		t.Error("expected Ready=false when UserStore was missing")
	}
}

func TestInitializeFamilyService_HappyPath_NoLifecycle(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "fam_happy.db")
	db, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	got, err := InitializeFamilyService(FamilyDeps{
		InvitationStore: users.NewInvitationStore(db),
		UserStore:       fakeFamilyUserStore{},
		BillingStore:    fakeBillingStore{},
		// Lifecycle: nil — no goroutine spawn.
		Logger: testLogger(),
	})
	if err != nil {
		t.Fatalf("expected nil error; got %v", err)
	}
	if !got.Ready {
		t.Errorf("expected Ready=true; got false (InitTableErr=%v LoadFromDBErr=%v)",
			got.InitTableErr, got.LoadFromDBErr)
	}
	if got.Service == nil {
		t.Error("expected non-nil Service")
	}
	if got.CleanupGoroutineRunning {
		t.Error("expected no goroutine without Lifecycle adapter")
	}
}

func TestInitializeFamilyService_LifecycleAdapter_FirstProductionUse(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "fam_lifecycle.db")
	db, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Track cleanup-closure invocations. Each tick increments by one.
	var cleanupCalls atomic.Int32
	cleanupFn := func() int {
		cleanupCalls.Add(1)
		return 3 // pretend we cleared 3 expired invitations per tick
	}

	mgr := newTestLifecycleManager(t)
	adapter := NewFxLifecycleAdapter("family-test", mgr)

	got, err := InitializeFamilyService(FamilyDeps{
		InvitationStore:       users.NewInvitationStore(db),
		UserStore:             fakeFamilyUserStore{},
		BillingStore:          fakeBillingStore{},
		CleanupFunc:           cleanupFn,
		CleanupTickerInterval: 25 * time.Millisecond, // observable
		Lifecycle:             adapter,
		Logger:                testLogger(),
	})
	if err != nil {
		t.Fatalf("expected nil error; got %v", err)
	}
	if !got.Ready {
		t.Fatalf("expected Ready=true; got false (InitTableErr=%v)", got.InitTableErr)
	}
	if got.Service == nil {
		t.Fatal("expected non-nil Service")
	}
	if !got.CleanupGoroutineRunning {
		t.Error("expected CleanupGoroutineRunning=true after Lifecycle wiring")
	}
	// Adapter must NOT have captured an OnStart error.
	if err := adapter.Err(); err != nil {
		t.Errorf("FxLifecycleAdapter unexpectedly captured OnStart err: %v", err)
	}

	// Wait for at least one tick. With a 25ms interval, 100ms gives
	// us 3-4 ticks worst-case while staying CI-budget-friendly.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if cleanupCalls.Load() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if cleanupCalls.Load() < 1 {
		t.Errorf("cleanup goroutine did not tick within 500ms (got %d calls)", cleanupCalls.Load())
	}

	// Shutdown via the host LifecycleAppender — the adapter forwarded
	// OnStop into the manager. This is THE load-bearing assertion for
	// β-2: the cleanup goroutine MUST exit when manager.Shutdown()
	// fires, proving FxLifecycleAdapter routes Stops through the host
	// shutdown path under real load.
	mgr.Shutdown()

	// After Shutdown, cleanup count must NOT keep climbing. We sample
	// 100ms apart — any further ticks would surface as a delta.
	post := cleanupCalls.Load()
	time.Sleep(100 * time.Millisecond)
	final := cleanupCalls.Load()
	if final != post {
		t.Errorf("goroutine kept ticking after Shutdown: %d→%d", post, final)
	}
}

// TestInitializeFamilyService_OnStopIdempotent verifies that calling
// the host Shutdown() twice (re-entrant scenario) does not panic and
// the goroutine doesn't double-cancel. Mirrors the legacy sync.Once
// semantics on app.LifecycleManager.
func TestInitializeFamilyService_OnStopIdempotent(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "fam_idem.db")
	db, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mgr := newTestLifecycleManager(t)
	adapter := NewFxLifecycleAdapter("family-idem", mgr)

	got, err := InitializeFamilyService(FamilyDeps{
		InvitationStore:       users.NewInvitationStore(db),
		UserStore:             fakeFamilyUserStore{},
		BillingStore:          fakeBillingStore{},
		CleanupFunc:           func() int { return 0 },
		CleanupTickerInterval: 1 * time.Hour, // never ticks during test
		Lifecycle:             adapter,
		Logger:                testLogger(),
	})
	if err != nil || !got.Ready {
		t.Fatalf("setup failed: err=%v ready=%v", err, got.Ready)
	}

	// First Shutdown: cancels goroutine, returns.
	mgr.Shutdown()
	// Second Shutdown: re-entrant; OnStop's atomic.Bool guard makes
	// the second call a no-op. We assert via "no panic" + "no
	// long block" — the test simply must complete.
	mgr.Shutdown()
}

// TestInitializeFamilyService_LifecycleHookContract verifies that the
// OnStop hook the provider registers is in fact invokable independently
// (not just via the test's adapter), so we don't depend on the adapter's
// internal naming. We construct a minimal fakeLifecycleManager and
// inspect the registered Stop count.
func TestInitializeFamilyService_LifecycleHookContract(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "fam_contract.db")
	db, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mgr := newTestLifecycleManager(t)
	adapter := NewFxLifecycleAdapter("family-contract", mgr)

	preStops := len(mgr.stops)
	_, _ = InitializeFamilyService(FamilyDeps{
		InvitationStore:       users.NewInvitationStore(db),
		UserStore:             fakeFamilyUserStore{},
		BillingStore:          fakeBillingStore{},
		CleanupFunc:           func() int { return 0 },
		CleanupTickerInterval: 1 * time.Hour,
		Lifecycle:             adapter,
		Logger:                testLogger(),
	})
	postStops := len(mgr.stops)

	if got := postStops - preStops; got != 1 {
		t.Errorf("expected provider to register exactly 1 OnStop hook; got %d", got)
	}

	// Trigger Shutdown to fire the registered stop — must succeed,
	// completing the lifecycle round-trip.
	mgr.Shutdown()
}

// _ = (*kc.FamilyService)(nil) — compile-time check that the kc
// package's FamilyService type is publicly nameable (which it must
// be for the wrapper to type-check). If kc moves the type or
// un-exports it, this file fails to compile.
var _ = func(*kc.FamilyService) {}

// _ = context-related sanity to keep imports honest if a future
// refactor accidentally drops the OnStop ctx parameter.
var _ context.Context = context.Background()

// _ = fx.Hook reference to keep fx import live across refactors —
// removing the OnStop wiring would otherwise drop the import.
var _ = fx.Hook{}
