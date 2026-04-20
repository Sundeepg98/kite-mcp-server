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
// Uses the delta-NumGoroutine tolerance pattern (not goleak.VerifyNone)
// because the app package hosts ~100 parallel tests that each spawn
// their own DB pools, scheduler loops, ticker services, OAuth cleanup
// workers, rate-limit reload loops, metrics cleanup, papertrading
// Monitors, and fill-watchers. goleak.VerifyNone would require
// whitelisting every intra-package goroutine class — brittle and
// risks masking real NewApp-owned leaks.
//
// The NumGoroutine-delta pattern is resilient: it measures the delta
// from a per-test baseline after cycles of NewApp+Shutdown, and a
// small tolerance absorbs test-runtime noise. A real leak in NewApp
// (~20 goroutines over 20 cycles) would blow past the tolerance
// while intra-package interference stays below it.
//
// Apr-2026 cleanup pass reduced intra-package leaks by wiring:
//   - oauth.Handler.Close() via newTestOAuthHandler + t.Cleanup on all
//     direct oauth.NewHandler sites (~27 in total). AuthCodeStore
//     cleanup goroutine now dies per-test.
//   - instruments.Manager.Shutdown() via t.Cleanup on every
//     instruments.New test site (~64). startScheduler goroutine now
//     dies per-test.
//   - cleanupInitializeServices on every initializeServices test site
//     that previously only stopped scheduler+auditStore (14 sites).
//     Missing Shutdown hooks (hashPublisher, oauthHandler, rateLimiters,
//     paperMonitor, invitationCleanup, telegramBot) now fire on t.Cleanup.
//
// Apr-2026 Round 2: structural lifecycle fixes that moved code out of
// the "leaks by design" bucket:
//   - wire.go now wires app.rateLimitReloadStop into startRateLimitReloadLoop;
//     both graceful shutdown and cleanupInitializeServices join the loop.
//   - 7 RunServer tests (DevMode_FullLifecycle, WithOAuth, FullDevMode,
//     WithOAuth_FullWiring, SSEMode, HybridMode, OAuthWiring_Push100)
//     now set shutdownCh and close it after HTTP probing — the server
//     goroutine tree unwinds instead of leaking past test exit.
//   - kc/telegram.newTestBotHandler takes *testing.T and registers
//     tb.Cleanup(h.Shutdown) — plugs BotHandler.runCleanup across 150+
//     call sites.
//
// Apr-2026 Round 3: architectural debts paid, remaining leakers are test
// hygiene. Production-code lifecycle fixes:
//   - kc.SessionRegistry.StopCleanupRoutine now blocks on a WaitGroup
//     until the cleanupRoutine goroutine exits (not just signals cancel).
//   - mcp.ToolCache gained Close() + ShutdownLtpCache() package helper;
//     TestMain in mcp/ + app/ can fully shut down the ltpCache singleton.
//   - app.rateLimiters.Stop now waits on cleanupDone; startRateLimitReloadLoop
//     returns a doneCh and app.stopRateLimitReload joins it.
//   - app.startStdIOServer uses context.WithCancel tied to shutdownCh so
//     mcp-go's handleNotifications goroutine exits on app shutdown.
//   - newTestApp pre-wires app.shutdownCh + closes on Cleanup, so every
//     test that calls setupGracefulShutdown has its wait goroutine joined.
//
// Residual leakers are now test-side only. They cluster in tests that
// directly wire app.rateLimiters = newRateLimiters() + skip Stop,
// directly call app.initializeServices + skip cleanupInitializeServices,
// or create audit.Store workers without a matching s.Stop(). Each fix
// is a per-site t.Cleanup addition — not fundamental code changes.
//
// Because migrating THIS package to VerifyTestMain would require
// chasing down ~25+ tests and adding per-site cleanup hooks (most of
// which are best-covered by extending newTestApp further), the delta
// NumGoroutine sentinel stays as the package-wide guard. The 6
// leak_sentinel_test.go files in sibling kc/* packages retain their
// strict goleak.VerifyNone checks because those packages have narrower
// test surfaces.
//
// Other goroutine sentinels in the repo (kc/scheduler, kc/audit,
// kc/ticker, kc/alerts, kc/billing, kc/instruments, kc/papertrading)
// DO use goleak because their packages have narrower test surfaces
// and the strict-equality check gives better failure attribution.

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
