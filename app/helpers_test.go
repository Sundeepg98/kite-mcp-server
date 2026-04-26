package app

// helpers_test.go — shared test helpers for the app package.
// Consolidates: testLogger, newTestManager variants, mock types, cleanup helpers.

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/testutil/kcfixture"
)

// testLogger creates a discard logger for tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestApp wraps NewApp(testLogger()) with a t.Cleanup that shuts down the
// metrics manager (and, once wired, any other App-owned background goroutines
// created in NewApp itself). Tests that additionally call initializeServices
// must still invoke cleanupInitializeServices for the services started there.
//
// Also sets INSTRUMENTS_SKIP_FETCH=true so that tests which subsequently call
// initializeServices do not hit api.kite.trade/instruments.json. This keeps
// the full wiring exercised but removes the external-API dependency that
// caused CI timeouts under Kite rate-limiting. Integration tests that want
// to exercise the real fetch should NOT use this helper — see
// integration_kite_api_test.go, gated by -tags integration.
//
// Preferred over `NewApp(testLogger())` for new tests — catches leaks by
// default.
//
// Also pre-wires app.shutdownCh and a t.Cleanup that closes it. Tests that
// exercise setupGracefulShutdown / startXxxServer / RunServer would
// otherwise leak a goroutine blocked on signal.NotifyContext waiting for
// SIGTERM; closing shutdownCh unwinds that goroutine at test end. Tests
// that want to CONTROL the close (e.g., to assert the shutdown sequence
// fires) may call close(app.shutdownCh) themselves before the Cleanup
// runs — stopOnce on shutdownCh is handled by closeShutdownOnce.
func newTestApp(t *testing.T) *App {
	t.Helper()
	// Start from the ambient env so existing tests that pre-Setenv
	// KITE_API_KEY et al still see those values, then force-override
	// InstrumentsSkipFetch=true via the Config field (replaces the prior
	// t.Setenv("INSTRUMENTS_SKIP_FETCH", "true") — that env read is now
	// sourced from Config.InstrumentsSkipFetch, not from os.Getenv at
	// call time). Tests keep their t.Setenv semantics for other env vars
	// because ConfigFromEnv still reads them, and we don't call t.Setenv
	// ourselves — which means tests that go via newTestApp still can't
	// use t.Parallel (they retain their pre-existing env-mutation pattern).
	// For t.Parallel tests, use newTestAppWithConfig with an explicit Config.
	cfg := ConfigFromEnv()
	cfg.InstrumentsSkipFetch = true
	app := NewAppWithConfig(cfg, testLogger())
	registerTestAppCleanup(t, app)
	return app
}

// newTestAppWithConfig is the Phase E.2 entry point for tests that want to
// inject a Config explicitly rather than shaping it via t.Setenv. It mirrors
// newTestApp's lifecycle handling (shutdownCh, t.Cleanup) but routes through
// NewAppWithConfig so the caller can set KiteAPIKey / KiteAPISecret /
// OAuthJWTSecret / etc. as struct fields and run the test under t.Parallel().
//
// cfg may be nil — a nil Config becomes a zero-valued Config inside
// NewAppWithConfig. Tests that want sensible non-production defaults can
// pass `(&Config{...}).WithDefaults()`.
//
// NOTE on INSTRUMENTS_SKIP_FETCH: this helper deliberately does NOT call
// t.Setenv("INSTRUMENTS_SKIP_FETCH", "true") — that would preclude t.Parallel
// which is the whole point. Tests that only exercise NewAppWithConfig +
// LoadConfig + in-memory behaviour don't need the env var at all. Tests that
// ALSO call initializeServices (which reads INSTRUMENTS_SKIP_FETCH via
// app/wire.go:38) should keep using newTestApp until that env read is also
// plumbed through Config in a later Phase E.2 step.
func newTestAppWithConfig(t *testing.T, cfg *Config) *App {
	t.Helper()
	app := NewAppWithConfig(cfg, testLogger())
	registerTestAppCleanup(t, app)
	return app
}

// registerTestAppCleanup wires the shutdown channel + t.Cleanup block that
// both newTestApp and newTestAppWithConfig share. Extracted so the two
// helpers stay in lock-step — any new teardown step must land here once.
func registerTestAppCleanup(t *testing.T, app *App) {
	t.Helper()
	app.shutdownCh = make(chan struct{})
	t.Cleanup(func() {
		// Guard against tests that already closed shutdownCh (idempotent).
		select {
		case <-app.shutdownCh:
			// already closed by the test — nothing to do
		default:
			close(app.shutdownCh)
		}
		// If setupGracefulShutdown wired its teardown goroutine, wait
		// for it to finish so goleak sentinels observe a clean state.
		if app.gracefulShutdownDone != nil {
			select {
			case <-app.gracefulShutdownDone:
			case <-time.After(5 * time.Second):
				t.Errorf("newTestApp: graceful shutdown did not complete within 5s")
			}
		} else {
			// No setupGracefulShutdown was called (e.g., tests that invoke
			// setupMux directly without going through startXxxServer). Run
			// the equivalent teardown sequence here so background workers
			// spawned by setupMux / direct component wiring exit before
			// goleak inspects at process end. Every Stop is nil-safe.
			if app.scheduler != nil {
				app.scheduler.Stop()
			}
			if app.hashPublisherCancel != nil {
				app.hashPublisherCancel()
			}
			if app.outboxPump != nil {
				app.outboxPump.Stop()
			}
			if app.auditStore != nil {
				app.auditStore.Stop()
			}
			if app.telegramBot != nil {
				app.telegramBot.Shutdown()
			}
			if app.oauthHandler != nil {
				app.oauthHandler.Close()
			}
			if app.rateLimiters != nil {
				app.rateLimiters.Stop()
			}
			app.stopRateLimitReload()
			if app.invitationCleanupCancel != nil {
				app.invitationCleanupCancel()
			}
			if app.paperMonitor != nil {
				app.paperMonitor.Stop()
			}
		}
		if app.metrics != nil {
			app.metrics.Shutdown()
		}
	})
}

// newTestManager creates a kc.Manager in DevMode with empty instruments.
// For tests that don't need a SQLite DB.
func newTestManager(t *testing.T) *kc.Manager {
	t.Helper()
	return kcfixture.NewTestManager(t, kcfixture.WithDevMode())
}

// newTestManagerWithDB creates a kc.Manager in DevMode with an in-memory SQLite DB.
// For tests that need AlertDB, UserStore, BillingStore, etc.
func newTestManagerWithDB(t *testing.T) *kc.Manager {
	t.Helper()
	return kcfixture.NewTestManager(t,
		kcfixture.WithDevMode(),
		kcfixture.WithAlertDB(":memory:"),
	)
}

// newTestManagerWithInvitations creates a manager with DB and invitation store.
func newTestManagerWithInvitations(t *testing.T) (*kc.Manager, *users.InvitationStore) {
	t.Helper()
	mgr := newTestManagerWithDB(t)
	invStore := users.NewInvitationStore(mgr.AlertDB())
	require.NoError(t, invStore.InitTable())
	mgr.SetInvitationStore(invStore)
	return mgr, invStore
}

// newTestAuditStore creates an audit.Store backed by the given DB.
func newTestAuditStore(t *testing.T, db *alerts.DB) *audit.Store {
	t.Helper()
	s := audit.New(db)
	require.NoError(t, s.InitTable())
	s.StartWorker()
	return s
}

// cleanupInitializeServices stops background goroutines started by
// initializeServices.
//
// Production graceful-shutdown path delegates worker teardown to
// app.lifecycle.Shutdown() (registered via registerLifecycle at end of
// initializeServices). This helper does too — but it ALSO runs an
// inline backstop because some tests bypass initializeServices and
// directly mutate app fields (e.g. `app.rateLimiters = newRateLimiters()`
// in app_edge_test.go), in which case the lifecycle manager has zero
// stops registered and the backstop is the only thing that prevents a
// goroutine leak.
//
// Order matches app/wire.go:registerLifecycle plus Phase A. Every step
// is idempotent (sync.Once or nil-guard) so the duplication between
// inline backstop and lifecycle.Shutdown is safe — the second call is
// a no-op for any worker the lifecycle already stopped.
//
// The mgr argument is retained for back-compat with existing call
// sites (~10 _test.go files); kcManager.Shutdown is invoked here AND
// via the lifecycle's "kc_manager" stop. Both paths are nil/once safe.
func cleanupInitializeServices(app *App, mgr *kc.Manager) {
	// Phase A — block new work.
	if app.scheduler != nil {
		app.scheduler.Stop()
	}
	if app.hashPublisherCancel != nil {
		app.hashPublisherCancel()
	}
	// Phase C, inline backstop — covers tests that directly mutate app
	// fields and never invoked registerLifecycle. Each call is
	// idempotent so a successful lifecycle.Shutdown below is safe.
	if app.outboxPump != nil {
		app.outboxPump.Stop()
	}
	if app.auditStore != nil {
		app.auditStore.Stop()
	}
	if app.telegramBot != nil {
		app.telegramBot.Shutdown()
	}
	if mgr != nil {
		mgr.Shutdown()
	}
	if app.oauthHandler != nil {
		app.oauthHandler.Close()
	}
	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
	app.stopRateLimitReload()
	if app.invitationCleanupCancel != nil {
		app.invitationCleanupCancel()
	}
	if app.paperMonitor != nil {
		app.paperMonitor.Stop()
	}
	if app.metrics != nil {
		app.metrics.Shutdown()
	}
	// Phase C, canonical path — the lifecycle manager owns this for any
	// app that went through initializeServices. Idempotent vs the
	// inline backstop above.
	if app.lifecycle != nil {
		app.lifecycle.Shutdown()
	}
}

// ---------------------------------------------------------------------------
// Mock types for broker.Authenticator
// ---------------------------------------------------------------------------

// mockAuthenticator implements broker.Authenticator for testing.
type mockAuthenticator struct {
	result broker.AuthResult
	err    error
}

func (m *mockAuthenticator) GetLoginURL(apiKey string) string {
	return "https://kite.zerodha.com/connect/login?api_key=" + apiKey
}

func (m *mockAuthenticator) ExchangeToken(apiKey, apiSecret, requestToken string) (broker.AuthResult, error) {
	if m.err != nil {
		return broker.AuthResult{}, m.err
	}
	return m.result, nil
}

func (m *mockAuthenticator) InvalidateToken(apiKey, accessToken string) error {
	return nil
}

// newMockAuth creates a mockAuthenticator returning the given user session data.
func newMockAuth(email, userID, userName, accessToken string) *mockAuthenticator {
	return &mockAuthenticator{
		result: broker.AuthResult{
			AccessToken: accessToken,
			UserID:      userID,
			UserName:    userName,
			Email:       email,
		},
	}
}

// newMockAuthError creates a mockAuthenticator that returns an error.
func newMockAuthError(errMsg string) *mockAuthenticator {
	return &mockAuthenticator{
		err: fmt.Errorf("%s", errMsg),
	}
}

// ---------------------------------------------------------------------------
// Server-readiness helpers — replace wall-clock Sleep with fast dial polls.
// ---------------------------------------------------------------------------

// waitForServerReady polls net.DialTimeout against addr until a TCP connection
// succeeds or the overall budget expires. Returns nil once the server is
// accepting connections; failure is a t.Fatal so tests stay compact.
//
// Budget defaults to 2s — ample for any OS to bind a port + enter Accept loop,
// while still orders of magnitude faster than the 50-500ms fixed sleeps this
// replaces. Typical observed time-to-ready on Windows + Linux: 1-5ms.
//
// Use this INSTEAD of time.Sleep whenever a test spawns an HTTP server in a
// goroutine and then expects to dial it. Correctness guarantee: if dial
// succeeds, the listener is accepting — no race remains.
func waitForServerReady(t *testing.T, addr string) {
	t.Helper()
	waitForServerReadyWithin(t, addr, 2*time.Second)
}

// waitForServerReadyWithin is the configurable variant. Most callers should
// use waitForServerReady; override the budget only when a test deliberately
// exercises slow startup paths.
func waitForServerReadyWithin(t *testing.T, addr string, budget time.Duration) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("server at %s did not accept within %v (last err: %v)", addr, budget, err)
		}
		// 1ms is finer than the wall-clock slack we had (50ms min) but
		// still friendly to the OS scheduler. Real bind completes in
		// microseconds; this poll cadence is effectively free.
		time.Sleep(time.Millisecond)
	}
}

// waitForServerShutdown polls net.DialTimeout until connection is refused
// (server has stopped accepting) or the deadline expires. Replaces the
// "sleep and dial" loop in shutdown tests with a single named call.
func waitForServerShutdown(t *testing.T, addr string, budget time.Duration) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err != nil {
			return // connection refused / timeout → server is down
		}
		_ = conn.Close()
		if time.Now().After(deadline) {
			t.Fatalf("server at %s still accepting after %v shutdown budget", addr, budget)
		}
		time.Sleep(time.Millisecond)
	}
}
