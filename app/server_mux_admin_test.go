package app

// server_test.go -- consolidated tests for server lifecycle, setup, and coverage.
// Merged from: coverage_boost_test.go, coverage_boost2_test.go, server_lifecycle_test.go
import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
)

// ===========================================================================
// Merged from coverage_boost_test.go
// ===========================================================================


// ---------------------------------------------------------------------------
// Helper: create a minimal MCP server for tests.
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// registerTelegramWebhook tests — exercises early return branches
// ---------------------------------------------------------------------------
func TestRegisterTelegramWebhook_NoNotifier(t *testing.T) {
	mgr := newTestManager(t)
	app := newTestApp(t)
	mux := http.NewServeMux()
	// No Telegram notifier configured on the test manager → should return early.
	app.registerTelegramWebhook(mux, mgr)
	// No panic, no webhook registered. Verify by checking a would-be path returns 404.
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook/test", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}


func TestRegisterTelegramWebhook_NoJWTSecret(t *testing.T) {
	mgr := newTestManager(t)
	app := newTestApp(t)
	app.Config.OAuthJWTSecret = ""
	app.Config.ExternalURL = ""
	mux := http.NewServeMux()
	app.registerTelegramWebhook(mux, mgr)
	// No panic — early return because no JWT secret.
}



// ---------------------------------------------------------------------------
// initScheduler tests — exercises early-exit paths
// ---------------------------------------------------------------------------
func TestInitScheduler_NoTelegram_NoAudit(t *testing.T) {
	mgr := newTestManager(t)
	app := newTestApp(t)
	app.auditStore = nil
	app.initScheduler(mgr)
	// No Telegram notifier, no audit store → "No scheduled tasks configured" path
	assert.Nil(t, app.scheduler)
}



// ---------------------------------------------------------------------------
// initScheduler — with audit store (covers audit_cleanup branch)
// ---------------------------------------------------------------------------
func TestInitScheduler_WithAuditStore(t *testing.T) {
	mgr := newTestManager(t)
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	app := newTestApp(t)
	app.auditStore = audit.New(db)
	require.NoError(t, app.auditStore.InitTable())

	app.initScheduler(mgr)
	// With audit store but no Telegram, the audit_cleanup task should be registered
	assert.NotNil(t, app.scheduler)
	app.scheduler.Stop()
}



// ---------------------------------------------------------------------------
// registerTelegramWebhook — more coverage
// ---------------------------------------------------------------------------
func TestRegisterTelegramWebhook_NoNotifier_WithConfig(t *testing.T) {
	mgr := newTestManager(t)
	app := newTestApp(t)
	app.Config.OAuthJWTSecret = "test-secret"
	app.Config.ExternalURL = "https://example.com"
	mux := http.NewServeMux()
	// Notifier is nil on test manager → returns early
	app.registerTelegramWebhook(mux, mgr)
}



// ---------------------------------------------------------------------------
// initScheduler — additional branch: audit cleanup with no Telegram
// ---------------------------------------------------------------------------
func TestInitScheduler_AuditOnly(t *testing.T) {
	mgr := newTestManager(t)
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	app := newTestApp(t)
	app.auditStore = audit.New(db)
	require.NoError(t, app.auditStore.InitTable())

	app.initScheduler(mgr)
	require.NotNil(t, app.scheduler)
	app.scheduler.Stop()
}



// ===========================================================================
// initScheduler with P&L snapshot path
// ===========================================================================
func TestInitScheduler_WithPnLSnapshot(t *testing.T) {
	instrMgr, err := instruments.New(instruments.Config{
		Logger:   testLogger(),
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)
	mgr, err := kc.NewWithOptions(context.Background(),
		kc.WithLogger(testLogger()),
		kc.WithKiteCredentials("tk", "ts"),
		kc.WithDevMode(true),
		kc.WithInstrumentsManager(instrMgr),
		kc.WithAlertDBPath(":memory:"),
	)
	require.NoError(t, err)
	t.Cleanup(mgr.Shutdown)
	app := newTestApp(t)
	if alertDB := mgr.AlertDB(); alertDB != nil {
		app.auditStore = audit.New(alertDB)
		require.NoError(t, app.auditStore.InitTable())
	}
	app.initScheduler(mgr)
	assert.NotNil(t, app.scheduler)
	if app.scheduler != nil {
		app.scheduler.Stop()
	}
	if app.auditStore != nil {
		app.auditStore.Stop()
	}
}



// ---------------------------------------------------------------------------
// initScheduler — exercises all three branches
// ---------------------------------------------------------------------------
func TestInitScheduler_AuditAndPnL(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := newTestApp(t)

	if alertDB := mgr.AlertDB(); alertDB != nil {
		auditStore := audit.New(alertDB)
		require.NoError(t, auditStore.InitTable())
		app.auditStore = auditStore
	}

	app.initScheduler(mgr)

	// With alertDB, both audit_cleanup and pnl_snapshot should be registered
	assert.NotNil(t, app.scheduler)

	if app.scheduler != nil {
		app.scheduler.Stop()
	}
	if app.auditStore != nil {
		app.auditStore.Stop()
	}
}



// ---------------------------------------------------------------------------
// initScheduler — with DB and audit store (covers PnL snapshot branch)
// ---------------------------------------------------------------------------
func TestInitScheduler_WithDB_AuditAndPnL(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := newTestApp(t)

	// Setup audit store from the manager's DB
	if alertDB := mgr.AlertDB(); alertDB != nil {
		auditStore := audit.New(alertDB)
		require.NoError(t, auditStore.InitTable())
		app.auditStore = auditStore
	}

	app.initScheduler(mgr)

	// With DB, both audit_cleanup and pnl_snapshot should be registered
	assert.NotNil(t, app.scheduler)

	if app.scheduler != nil {
		app.scheduler.Stop()
	}
	if app.auditStore != nil {
		app.auditStore.Stop()
	}
}



// ---------------------------------------------------------------------------
// initScheduler — no tasks (no Telegram, no audit, no DB)
// ---------------------------------------------------------------------------
func TestInitScheduler_NoTasks(t *testing.T) {
	mgr := newTestManager(t) // no DB
	app := newTestApp(t)
	app.auditStore = nil

	app.initScheduler(mgr)

	// No tasks → scheduler should be nil
	assert.Nil(t, app.scheduler)
}



// ===========================================================================
// registerTelegramWebhook — early return paths
// ===========================================================================
func TestRegisterTelegramWebhook_NilNotifier(t *testing.T) {
	app := newTestApp(t)
	app.Config.OAuthJWTSecret = "test-secret"
	app.Config.ExternalURL = "https://test.example.com"

	mgr := newTestManagerWithDB(t)
	mux := http.NewServeMux()

	// TelegramNotifier() returns nil for a manager without TELEGRAM_BOT_TOKEN.
	// Should return early without panic.
	app.registerTelegramWebhook(mux, mgr)
}


func TestRegisterTelegramWebhook_MissingSecret(t *testing.T) {
	app := newTestApp(t)
	app.Config.OAuthJWTSecret = ""
	app.Config.ExternalURL = ""

	mgr := newTestManagerWithDB(t)
	mux := http.NewServeMux()

	app.registerTelegramWebhook(mux, mgr)
}



// ===========================================================================
// initScheduler — no-tasks path
// ===========================================================================
func TestInitScheduler_NoTasks_Minimal(t *testing.T) {
	// Use a manager WITHOUT AlertDB so no PnL snapshot task is added.
	mgr, err := kc.NewWithOptions(context.Background(),
		kc.WithLogger(testLogger()),
		kc.WithKiteCredentials("test_key", "test_secret"),
		kc.WithDevMode(true),
	)
	require.NoError(t, err)
	t.Cleanup(mgr.Shutdown)

	app := newTestApp(t)
	app.initScheduler(mgr)
	assert.Nil(t, app.scheduler)
}


func TestInitScheduler_WithAuditStore_Minimal(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	mgr := newTestManagerWithDB(t)
	app := newTestApp(t)
	app.auditStore = audit.New(db)
	require.NoError(t, app.auditStore.InitTable())

	app.initScheduler(mgr)

	// Scheduler should be started (audit_cleanup task was added).
	assert.NotNil(t, app.scheduler)
	app.scheduler.Stop()
}
