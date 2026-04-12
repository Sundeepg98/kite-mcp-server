package app

// helpers_test.go — shared test helpers for the app package.
// Consolidates: testLogger, newTestManager variants, mock types, cleanup helpers.

import (
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/testutil"
)

// testLogger creates a discard logger for tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestManager creates a kc.Manager in DevMode with empty instruments.
// For tests that don't need a SQLite DB.
func newTestManager(t *testing.T) *kc.Manager {
	t.Helper()
	return testutil.NewTestManager(t, testutil.WithDevMode())
}

// newTestManagerWithDB creates a kc.Manager in DevMode with an in-memory SQLite DB.
// For tests that need AlertDB, UserStore, BillingStore, etc.
func newTestManagerWithDB(t *testing.T) *kc.Manager {
	t.Helper()
	return testutil.NewTestManager(t,
		testutil.WithDevMode(),
		testutil.WithAlertDB(":memory:"),
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
func cleanupInitializeServices(app *App, mgr *kc.Manager) {
	if app.scheduler != nil {
		app.scheduler.Stop()
	}
	if app.auditStore != nil {
		app.auditStore.Stop()
	}
	mgr.Shutdown()
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
