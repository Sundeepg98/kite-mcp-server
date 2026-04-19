package audit

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// leak_sentinel_test.go — guards against goroutine leaks from Store's
// StartWorker/Stop lifecycle. StartWorker spawns a drain goroutine that
// ranges over writeCh until Stop closes it; the goroutine signals exit
// by closing s.done, which Stop waits on. A refactor that drops the
// close(s.writeCh) or the <-s.done join would leak one goroutine per
// worker start.
//
// Pattern mirrors app/leak_sentinel_test.go (no external goleak dep):
// delta-of-NumGoroutine across repeated cycles with a small tolerance.
//
// Note: this test deliberately does NOT use openTestStore(t) because
// t.Cleanup defers the DB.Close until test completion, which means 20
// cycles accumulate 20 open SQLite databases (each with its own pool /
// background goroutines) during the measurement window. We open+close
// each DB within the loop so the sentinel measures only the Store
// worker goroutine.

// newShortLivedStore opens an in-memory DB, inits the audit table, and
// returns the Store plus a close function the caller must invoke before
// the next cycle. This is the in-loop analogue of openTestStore.
func newShortLivedStore(t *testing.T) (*Store, func()) {
	t.Helper()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	s := New(db)
	require.NoError(t, s.InitTable())
	return s, func() { db.Close() }
}

// TestGoroutineLeakSentinel_StoreWorker verifies that 20 StartWorker()
// + Stop() cycles do not accumulate goroutines. A missing close or
// missing join in Stop() would leak one drain goroutine per cycle.
func TestGoroutineLeakSentinel_StoreWorker(t *testing.T) {
	// Warmup: one full cycle to settle SQLite / time lazy init BEFORE
	// the baseline is captured. Without warmup the first DB open can
	// leave registered finalizers that skew NumGoroutine upward.
	warm, closeWarm := newShortLivedStore(t)
	warm.StartWorker()
	warm.Stop()
	closeWarm()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	baseline := runtime.NumGoroutine()

	const cycles = 20
	for i := 0; i < cycles; i++ {
		s, closeDB := newShortLivedStore(t)
		s.StartWorker()
		// Enqueue one entry so the worker exercises its read-and-hash
		// path at least once — catches leaks that only surface after
		// the first channel receive.
		s.Enqueue(&ToolCall{
			CallID:      "leak-sentinel",
			Email:       "",
			ToolName:    "noop",
			StartedAt:   time.Now(),
			CompletedAt: time.Now(),
		})
		time.Sleep(5 * time.Millisecond)
		s.Stop()
		closeDB() // release SQLite connection/goroutines in-loop
	}
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	after := runtime.NumGoroutine()

	delta := after - baseline
	// Tolerance 3 for GC helpers / test runtime noise. Without the
	// close+join pair in Stop(), delta would climb to ~20.
	const tolerance = 3
	if delta > tolerance {
		t.Errorf("audit Store worker goroutine leak: baseline=%d after=%d delta=%d exceeds tolerance=%d",
			baseline, after, delta, tolerance)
	}
}

// TestStoreStopIdempotent locks in the sync.Once + nil-guard pair in
// Store.Stop(). A refactor that removed either guard would either panic
// on the second close(writeCh) or NPE on the nil-channel receive.
func TestStoreStopIdempotent(t *testing.T) {
	s := openTestStore(t)
	s.StartWorker()
	// Triple Stop — must not panic.
	s.Stop()
	s.Stop()
	s.Stop()

	// Stop without StartWorker must also be a no-op.
	s2 := openTestStore(t)
	s2.Stop()
	s2.Stop()
}
