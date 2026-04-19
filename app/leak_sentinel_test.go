package app

// leak_sentinel_test.go — guard against goroutine leaks from NewApp when
// the caller follows the documented cleanup pattern (t.Cleanup → metrics.Shutdown
// on the newTestApp helper, or cleanupInitializeServices when services were
// wired). Regression test for the Apr-2026 leak triad:
//   - metrics.Manager AutoCleanup (fixed via sync.Once Shutdown — was already
//     present but never called in prod shutdown / test cleanup)
//   - papertrading.Monitor background loop (fixed via sync.Once Stop)
//   - invitation-cleanup ticker goroutine (fixed via context-cancel)
//
// This test exercises NewApp specifically (the per-call leak). It does NOT
// run full initializeServices because that requires network-available
// instruments fetch in non-TestData mode; the fuller shutdown sequence is
// covered separately by TestAnomalyWiring + shutdown_test.go.

import (
	"runtime"
	"testing"
	"time"
)

// TestGoroutineLeakSentinel_NewApp verifies that 20 NewApp() calls with
// proper Shutdown() follow-up do not accumulate more than a handful of
// goroutines. Without the Shutdown call (the leak this guards), each
// NewApp leaked one metrics cleanup goroutine, so 20 calls = ~20 leaked.
func TestGoroutineLeakSentinel_NewApp(t *testing.T) {
	// Warmup: allocate one app to settle lazy runtime workers (goroutine
	// count climbs on first use of certain stdlib paths like database/sql
	// drivers, crypto/rand, signal handlers) before we take a baseline.
	warmup := NewApp(testLogger())
	warmup.metrics.Shutdown()
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	baseline := runtime.NumGoroutine()

	const cycles = 20
	for i := 0; i < cycles; i++ {
		app := NewApp(testLogger())
		// Immediately shut down the metrics routine — this is what
		// newTestApp.t.Cleanup does in production tests.
		app.metrics.Shutdown()
	}
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	after := runtime.NumGoroutine()

	delta := after - baseline
	// Tolerance 3 allows for GC helpers / test runtime noise. Without the
	// Shutdown fix, delta would be ~20.
	const tolerance = 3
	if delta > tolerance {
		t.Errorf("goroutine leak: baseline=%d after=%d delta=%d exceeds tolerance=%d",
			baseline, after, delta, tolerance)
	}
}

// TestMetricsShutdownIdempotent verifies metrics.Manager.Shutdown is safe
// to call from both cleanupInitializeServices (test cleanup) and
// setupGracefulShutdown (server shutdown) without panic. The sync.Once
// guard is already present on metrics.Manager — this test locks in that
// invariant so a refactor can't silently remove it.
func TestMetricsShutdownIdempotent(t *testing.T) {
	app := newTestApp(t) // newTestApp already arranges cleanup
	// Triple-Shutdown must not panic (the Cleanup will call it a 4th time).
	app.metrics.Shutdown()
	app.metrics.Shutdown()
	app.metrics.Shutdown()
}
