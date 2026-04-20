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
// Residual test-level leakers that block package-wide goleak migration:
//   - kc.SessionRegistry.cleanupRoutine — no user-facing Close/Stop hook
//     (internal cleanup goroutine that lives with the Manager).
//   - HTTP server goroutines from handful of remaining RunServer/stdio
//     tests that construct their own http.Server and don't call Shutdown
//     (mostly the older "cover the case branch" tests that spawn
//     configureAndStartServer without matching teardown).
//   - mcp.NewToolCache ltpCache — package-init global with a 5-minute
//     cleanup ticker and no Close. Lives for process lifetime by design.
//
// Because some residual leakers can only be masked via broad
// IgnoreAnyFunction rules, migrating THIS package to VerifyTestMain
// risks hiding real leaks the sentinel should catch. NumGoroutine-delta
// stays for the package-wide guard; the 6 leak_sentinel_test.go files
// in sibling kc/* packages retain their strict goleak.VerifyNone checks
// because those packages have narrower test surfaces.
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
