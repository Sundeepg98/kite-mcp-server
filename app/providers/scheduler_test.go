package providers

import (
	"path/filepath"
	"testing"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// scheduler_test.go covers BuildScheduler. Wave D Phase 2 Slice
// P2.4b (Batch 1.2). The provider takes pre-built services
// (BriefingService, PnLSnapshotService, AuditStore) and conditionally
// adds tasks to a fresh *scheduler.Scheduler. Returns wrapper with
// nil-Scheduler if no tasks were added (matches the legacy
// initScheduler "no tasks → return without starting" path at
// app/wire.go:1004-1008).

// TestBuildScheduler_NoServices_ReturnsNilSched verifies the
// "no scheduled tasks configured" path: when all conditional inputs
// are nil, the wrapper's Scheduler stays nil and the scheduler
// goroutine is not started. Matches wire.go:1005-1008 legacy.
func TestBuildScheduler_NoServices_ReturnsNilSched(t *testing.T) {
	t.Parallel()

	in := buildSchedulerInput{
		Briefing:     nil,
		PnL:          nil,
		AuditStore:   nil,
		Logger:       testLogger(),
	}
	got, err := BuildScheduler(in)
	if err != nil {
		t.Fatalf("expected nil error; got %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil wrapper")
	}
	if got.Scheduler != nil {
		t.Errorf("expected nil Scheduler when no tasks configured; got non-nil")
	}
}

// TestBuildScheduler_AuditStoreOnly_AddsCleanupTask verifies that
// supplying only an audit store produces a scheduler with the
// audit_cleanup task. The scheduler IS started (Scheduler != nil)
// because it has tasks to run.
//
// We don't trigger the task — that would require a clock-injection
// mechanism we don't expose here. We just verify the scheduler is
// constructed and started.
func TestBuildScheduler_AuditStoreOnly_AddsCleanupTask(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "scheduler_audit_test.db")
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

	in := buildSchedulerInput{
		Briefing:    nil,
		PnL:         nil,
		AuditStore:  store,
		Logger:      testLogger(),
	}
	got, err := BuildScheduler(in)
	if err != nil {
		t.Fatalf("expected nil error; got %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil wrapper")
	}
	if got.Scheduler == nil {
		t.Fatal("expected non-nil Scheduler when audit store is wired")
	}
	t.Cleanup(func() { got.Scheduler.Stop() })
}

// TestBuildScheduler_AllServicesNil_NoStart verifies the early-
// return path explicitly: when no tasks are added, BuildScheduler
// MUST NOT call sched.Start() (which spawns a goroutine). The test
// proves nil Scheduler is the signal for "no goroutine running".
func TestBuildScheduler_AllServicesNil_NoStart(t *testing.T) {
	t.Parallel()

	in := buildSchedulerInput{
		Briefing:    nil,
		PnL:         nil,
		AuditStore:  nil,
		Logger:      testLogger(),
	}
	got, err := BuildScheduler(in)
	if err != nil {
		t.Fatalf("expected nil error; got %v", err)
	}
	if got.Scheduler != nil {
		t.Error("expected nil Scheduler — scheduler.Start() should not have been called")
	}
}

// TestBuildScheduler_NilLogger_DoesNotPanic verifies the function
// is nil-tolerant for the logger argument. The scheduler.New(nil)
// path is permitted by kc/scheduler — we just make sure
// BuildScheduler doesn't dereference logger before passing it.
func TestBuildScheduler_NilLogger_DoesNotPanic(t *testing.T) {
	t.Parallel()

	in := buildSchedulerInput{
		Briefing:    nil,
		PnL:         nil,
		AuditStore:  nil,
		Logger:      nil,
	}
	// Should not panic.
	got, err := BuildScheduler(in)
	if err != nil {
		t.Fatalf("expected nil error; got %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil wrapper even with nil logger")
	}
}

// Additional fixture: testBriefingService constructs a non-nil
// *alerts.BriefingService for the "with briefing" test. We bypass
// alerts.NewBriefingService's nil-notifier guard by constructing
// the struct directly via a helper if needed — but the simpler
// approach is to use a real notifier with a no-op token. That's
// already tested in kc/alerts; here we only need the pointer to be
// non-nil so the conditional branch fires.
//
// Skip — the briefing-task path is exercised by the existing
// app/server_edge_init_test.go integration tests. Re-testing it
// here would duplicate that surface for no marginal coverage.
