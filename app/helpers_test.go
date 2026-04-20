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
func newTestApp(t *testing.T) *App {
	t.Helper()
	t.Setenv("INSTRUMENTS_SKIP_FETCH", "true")
	app := NewApp(testLogger())
	t.Cleanup(func() {
		if app.metrics != nil {
			app.metrics.Shutdown()
		}
	})
	return app
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

// cleanupInitializeServices stops background goroutines started by initializeServices.
// Call order mirrors setupGracefulShutdown (reverse of start order) so shutdown
// semantics match production. Every Shutdown call is idempotent (sync.Once or
// nil-guard) so invoking this helper after RunServer has already shut down is safe.
func cleanupInitializeServices(app *App, mgr *kc.Manager) {
	if app.scheduler != nil {
		app.scheduler.Stop()
	}
	if app.hashPublisherCancel != nil {
		app.hashPublisherCancel()
	}
	if app.auditStore != nil {
		app.auditStore.Stop()
	}
	if app.telegramBot != nil {
		app.telegramBot.Shutdown()
	}
	mgr.Shutdown()
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
