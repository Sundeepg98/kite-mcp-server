package app

// leak_sentinel_test.go — shrunk to a single idempotent-shutdown regression
// test after Round 4 unblocked full goleak migration. The package-wide
// goroutine-leak guard now lives in main_test.go via goleak.VerifyTestMain,
// which catches every leaker (no ignore list for our own code) including
// the subtler ones the NumGoroutine-delta sentinel could miss.
//
// Round 4 production-code lifecycle fixes that unblocked the migration:
//   - kc.SessionRegistry.StopCleanupRoutine now joins the cleanup goroutine
//     via sync.WaitGroup (Round 3).
//   - mcp.ToolCache Close() + ShutdownLtpCache helper (Round 3).
//   - app.rateLimiters.Stop waits on cleanupDone, startRateLimitReloadLoop
//     returns a doneCh joined by stopRateLimitReload.
//   - app.startStdIOServer uses ctx.WithCancel tied to shutdownCh so
//     mcp-go's handleNotifications exits on app shutdown.
//   - kc/scheduler.Scheduler.Stop waits on loopDone.
//   - RunServer has a success-tracked defer that tears down every
//     wired component on error-before-serve paths (covers the case where
//     initializeServices half-wires and then fails, or startServer
//     returns err without invoking setupGracefulShutdown).
//   - initializeServices has a success-tracked defer that shuts down
//     the partially-wired app-level workers (scheduler, audit,
//     paperMonitor, hashPublisher, rateLimitReload) AND the Kite
//     manager when the production audit-required guard fires late.
//   - newTestApp registers a t.Cleanup that: (a) closes shutdownCh,
//     (b) waits on gracefulShutdownDone if setupGracefulShutdown ran,
//     (c) runs the equivalent teardown sequence directly if not.
//   - 14 alerts.OpenDB test sites got t.Cleanup(db.Close) — the
//     modernc.org/sqlite connectionOpener goroutine only exits on
//     DB.Close, and those sites had no matching close.

import (
	"testing"
)

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
