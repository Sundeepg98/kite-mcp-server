package app

// leak_sentinel_test.go — guard against goroutine leaks from NewApp
// when the caller follows the documented cleanup pattern
// (t.Cleanup → metrics.Shutdown on the newTestApp helper, or
// cleanupInitializeServices when services were wired). Regression
// test for the Apr-2026 leak triad:
//   - metrics.Manager AutoCleanup (fixed via sync.Once Shutdown)
//   - papertrading.Monitor background loop (fixed via sync.Once Stop)
//   - invitation-cleanup ticker goroutine (fixed via context-cancel)
//
// Uses go.uber.org/goleak VerifyNone at test end for precise leak
// attribution; replaces the earlier runtime.NumGoroutine tolerance
// pattern.

import (
	"testing"

	"go.uber.org/goleak"
)

// TestGoroutineLeakSentinel_NewApp verifies that 10 NewApp calls with
// proper metrics.Shutdown do not leak goroutines. Without the
// Shutdown call the prior impl leaked one metrics cleanup goroutine
// per NewApp — goleak would fire immediately with that function name
// in the stack trace.
func TestGoroutineLeakSentinel_NewApp(t *testing.T) {
	defer goleak.VerifyNone(t,
		goleak.IgnoreTopFunction("testing.(*T).Parallel"),
		// mcp.NewToolCache spawns an unstoppable 5-minute cleanup
		// ticker; it's a process-lifetime singleton, not per-App, so
		// it appears once per test binary and is not a NewApp leak.
		goleak.IgnoreTopFunction("github.com/zerodha/kite-mcp-server/mcp.NewToolCache.func1"),
	)

	const cycles = 10
	for i := 0; i < cycles; i++ {
		app := NewApp(testLogger())
		// Immediately shut down the metrics routine — this is what
		// newTestApp.t.Cleanup does in production tests.
		app.metrics.Shutdown()
	}
}

// TestMetricsShutdownIdempotent verifies metrics.Manager.Shutdown is
// safe to call from both cleanupInitializeServices (test cleanup) and
// setupGracefulShutdown (server shutdown) without panic.
func TestMetricsShutdownIdempotent(t *testing.T) {
	app := newTestApp(t) // newTestApp already arranges cleanup
	// Triple-Shutdown must not panic (the Cleanup will call it a 4th time).
	app.metrics.Shutdown()
	app.metrics.Shutdown()
	app.metrics.Shutdown()
}
