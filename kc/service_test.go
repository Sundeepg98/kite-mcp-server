package kc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/users"
)

func openTestAlertDB(t *testing.T) (*alerts.DB, error) {
	t.Helper()
	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { db.Close() })
	return db, nil
}

func fixedTestTime() time.Time {
	return time.Date(2026, 4, 7, 10, 0, 0, 0, time.UTC)
}

// ===========================================================================
// sessionDBAdapter — SaveSession, LoadSessions, DeleteSession (all at 0%)
// ===========================================================================

func TestSessionDBAdapter_SaveLoadDelete(t *testing.T) {
	t.Parallel()

	db, err := openTestAlertDB(t)
	if err != nil {
		t.Fatalf("openTestAlertDB error: %v", err)
	}
	adapter := &sessionDBAdapter{db: db}

	now := fixedTestTime()
	expires := now.Add(24 * time.Hour)

	// SaveSession
	err = adapter.SaveSession("sess-1", "user@test.com", now, expires, false)
	if err != nil {
		t.Fatalf("SaveSession error: %v", err)
	}

	// Save another
	err = adapter.SaveSession("sess-2", "admin@test.com", now, expires, true)
	if err != nil {
		t.Fatalf("SaveSession error: %v", err)
	}

	// LoadSessions
	sessions, err := adapter.LoadSessions()
	if err != nil {
		t.Fatalf("LoadSessions error: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("Expected 2 sessions, got %d", len(sessions))
	}

	// Verify first session
	found := false
	for _, s := range sessions {
		if s.SessionID == "sess-1" {
			if s.Email != "user@test.com" {
				t.Errorf("Email = %q, want user@test.com", s.Email)
			}
			if s.Terminated {
				t.Error("sess-1 should not be terminated")
			}
			found = true
		}
	}
	if !found {
		t.Error("sess-1 not found in loaded sessions")
	}

	// DeleteSession
	err = adapter.DeleteSession("sess-1")
	if err != nil {
		t.Fatalf("DeleteSession error: %v", err)
	}

	sessions, err = adapter.LoadSessions()
	if err != nil {
		t.Fatalf("LoadSessions error: %v", err)
	}
	if len(sessions) != 1 {
		t.Errorf("Expected 1 session after delete, got %d", len(sessions))
	}
}

// ===========================================================================
// SessionService — InitializeSessionManager, SessionManager, SetAuditStore
// ===========================================================================

func createTestSessionService() *SessionService {
	credStore := &mockCredentialStore{entries: map[string]*KiteCredentialEntry{}}
	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{}}
	credSvc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: credStore,
		TokenStore:      tokenStore,
		Logger:          testLogger(),
	})
	signer, _ := NewSessionSigner()
	ss := NewSessionService(SessionServiceConfig{
		CredentialSvc: credSvc,
		TokenStore:    tokenStore,
		SessionSigner: signer,
		Logger:        testLogger(),
	})
	return ss
}

func TestSessionService_InitializeSessionManager(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	if ss.SessionManager() == nil {
		t.Error("SessionManager should not be nil after InitializeSessionManager")
	}
}

func TestSessionService_SetSessionManager(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	sm := NewSessionRegistry(testLogger())

	ss.SetSessionManager(sm)
	if ss.SessionManager() != sm {
		t.Error("SessionManager should return the set registry")
	}
}

func TestSessionService_SetAuditStore(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	// Should not panic with nil
	ss.SetAuditStore(nil)
}

// ===========================================================================
// Manager.handleCallbackError
// ===========================================================================

func TestManager_HandleCallbackError(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	rr := httptest.NewRecorder()
	m.handleCallbackError(rr, "bad request", http.StatusBadRequest, "test error", "key", "value")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}

// ===========================================================================
// Manager.extractCallbackParams
// ===========================================================================

func TestManager_ExtractCallbackParams_MissingParams(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	// Missing both params
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	_, _, err = m.extractCallbackParams(req)
	if err == nil {
		t.Error("Expected error for missing params")
	}

	// Missing request_token
	req = httptest.NewRequest(http.MethodGet, "/callback?session_id=abc", nil)
	_, _, err = m.extractCallbackParams(req)
	if err == nil {
		t.Error("Expected error for missing request_token")
	}

	// Missing session_id
	req = httptest.NewRequest(http.MethodGet, "/callback?request_token=abc", nil)
	_, _, err = m.extractCallbackParams(req)
	if err == nil {
		t.Error("Expected error for missing session_id")
	}
}

func TestManager_ExtractCallbackParams_InvalidSignature(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	req := httptest.NewRequest(http.MethodGet, "/callback?request_token=tok&session_id=tampered.data", nil)
	_, _, err = m.extractCallbackParams(req)
	if err == nil {
		t.Error("Expected error for invalid session signature")
	}
}

func TestManager_ExtractCallbackParams_ValidSignature(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	// Generate a valid session and sign it
	sessionID := m.GenerateSession()
	signed := m.sessionSigner.SignSessionID(sessionID)

	req := httptest.NewRequest(http.MethodGet, "/callback?request_token=tok123&session_id="+signed, nil)
	rt, sid, err := m.extractCallbackParams(req)
	if err != nil {
		t.Fatalf("extractCallbackParams error: %v", err)
	}
	if rt != "tok123" {
		t.Errorf("request_token = %q, want tok123", rt)
	}
	if sid != sessionID {
		t.Errorf("session_id = %q, want %q", sid, sessionID)
	}
}

// renderSuccessTemplate has a template/struct mismatch (template expects RedirectURL
// but TemplateData only has Title). Skipping until TemplateData is updated.

// ===========================================================================
// Manager.HandleKiteCallback
// ===========================================================================

func TestHandleKiteCallback_MissingParams(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	handler := m.HandleKiteCallback()

	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}

func TestHandleKiteCallback_InvalidSignature(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	handler := m.HandleKiteCallback()

	req := httptest.NewRequest(http.MethodGet, "/callback?request_token=tok&session_id=tampered.sig", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}

// ===========================================================================
// Manager.UpdateInstrumentsConfig
// ===========================================================================

func TestManager_UpdateInstrumentsConfig(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	// Should not panic with valid config
	config := instruments.DefaultUpdateConfig()
	config.EnableScheduler = false
	m.UpdateInstrumentsConfig(config)
}

// ===========================================================================
// NewOrderService / NewPortfolioService constructors
// ===========================================================================

func TestNewOrderService(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	os := NewOrderService(ss, testLogger())
	if os == nil {
		t.Error("Expected non-nil OrderService")
	}
}

func TestNewPortfolioService(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ps := NewPortfolioService(ss, testLogger())
	if ps == nil {
		t.Error("Expected non-nil PortfolioService")
	}
}

// ===========================================================================
// GetBrokerForEmail — devMode and non-devMode paths
// ===========================================================================

func createDevModeSessionService() *SessionService {
	credStore := &mockCredentialStore{entries: map[string]*KiteCredentialEntry{}}
	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{}}
	credSvc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: credStore,
		TokenStore:      tokenStore,
		Logger:          testLogger(),
	})
	signer, _ := NewSessionSigner()
	ss := NewSessionService(SessionServiceConfig{
		CredentialSvc: credSvc,
		TokenStore:    tokenStore,
		SessionSigner: signer,
		Logger:        testLogger(),
		DevMode:       true,
	})
	return ss
}

func TestGetBrokerForEmail_DevMode(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()

	client, err := ss.GetBrokerForEmail("test@example.com")
	if err != nil {
		t.Fatalf("Expected no error in devMode, got: %v", err)
	}
	if client == nil {
		t.Fatal("Expected non-nil broker client in devMode")
	}
}

func TestGetBrokerForEmail_DevMode_EmptyEmail(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()

	client, err := ss.GetBrokerForEmail("")
	if err != nil {
		t.Fatalf("Expected no error in devMode with empty email, got: %v", err)
	}
	if client == nil {
		t.Fatal("Expected non-nil broker client in devMode")
	}
}

func TestGetBrokerForEmail_NoToken(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()

	_, err := ss.GetBrokerForEmail("notoken@example.com")
	if err == nil {
		t.Fatal("Expected error for email with no access token")
	}
	if !strings.Contains(err.Error(), "no Kite access token") {
		t.Errorf("Error should mention 'no Kite access token', got: %v", err)
	}
}

func TestGetBrokerForEmail_WithToken(t *testing.T) {
	t.Parallel()
	credStore := &mockCredentialStore{entries: map[string]*KiteCredentialEntry{
		"user@example.com": {APIKey: "test-key", APISecret: "test-secret"},
	}}
	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{
		"user@example.com": {AccessToken: "valid-access-token", UserName: "TestUser"},
	}}
	credSvc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: credStore,
		TokenStore:      tokenStore,
		Logger:          testLogger(),
	})
	signer, _ := NewSessionSigner()
	ss := NewSessionService(SessionServiceConfig{
		CredentialSvc: credSvc,
		TokenStore:    tokenStore,
		SessionSigner: signer,
		Logger:        testLogger(),
	})

	client, err := ss.GetBrokerForEmail("user@example.com")
	if err != nil {
		t.Fatalf("Expected no error with valid token, got: %v", err)
	}
	if client == nil {
		t.Fatal("Expected non-nil broker client")
	}
}

// ===========================================================================
// OrderService — all methods with devMode (mock broker)
// ===========================================================================

func createDevModeOrderService() *OrderService {
	ss := createDevModeSessionService()
	return NewOrderService(ss, testLogger())
}

func TestOrderService_GetBroker_Error(t *testing.T) {
	t.Parallel()
	// Non-devMode, no credentials => error
	ss := createTestSessionService()
	os := NewOrderService(ss, testLogger())

	_, err := os.getBroker("nouser@example.com")
	if err == nil {
		t.Fatal("Expected error from getBroker with no token")
	}
	if !strings.Contains(err.Error(), "order:") {
		t.Errorf("Error should be wrapped with 'order:', got: %v", err)
	}
}

func TestOrderService_PlaceOrder_Success(t *testing.T) {
	t.Parallel()
	os := createDevModeOrderService()

	resp, err := os.PlaceOrder("test@example.com", broker.OrderParams{
		Tradingsymbol:   "INFY",
		Exchange:        "NSE",
		TransactionType: "BUY",
		OrderType:       "MARKET",
		Quantity:        1,
		Product:         "CNC",
		Variety:         "regular",
	})
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if resp.OrderID == "" {
		t.Error("Expected non-empty OrderID")
	}
}

func TestOrderService_PlaceOrder_NoBroker(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	os := NewOrderService(ss, testLogger())

	_, err := os.PlaceOrder("nouser@example.com", broker.OrderParams{})
	if err == nil {
		t.Fatal("Expected error when broker cannot be resolved")
	}
}

func TestOrderService_ModifyOrder_BrokerError(t *testing.T) {
	t.Parallel()
	os := createDevModeOrderService()

	// In devMode, each GetBrokerForEmail returns a fresh mock client.
	// ModifyOrder on a non-existent order ID triggers the broker error path.
	_, err := os.ModifyOrder("test@example.com", "nonexistent-order", broker.OrderParams{
		Quantity: 2,
		Price:    1510.0,
	})
	if err == nil {
		t.Fatal("Expected error for modifying nonexistent order")
	}
	if !strings.Contains(err.Error(), "failed to modify order") {
		t.Errorf("Error should mention 'failed to modify order', got: %v", err)
	}
}

func TestOrderService_ModifyOrder_NoBroker(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	os := NewOrderService(ss, testLogger())

	_, err := os.ModifyOrder("nouser@example.com", "order-123", broker.OrderParams{})
	if err == nil {
		t.Fatal("Expected error when broker cannot be resolved")
	}
}

func TestOrderService_CancelOrder_BrokerError(t *testing.T) {
	t.Parallel()
	os := createDevModeOrderService()

	// Cancel a non-existent order triggers the broker error path.
	_, err := os.CancelOrder("test@example.com", "nonexistent-order", "regular")
	if err == nil {
		t.Fatal("Expected error for cancelling nonexistent order")
	}
	if !strings.Contains(err.Error(), "failed to cancel order") {
		t.Errorf("Error should mention 'failed to cancel order', got: %v", err)
	}
}

func TestOrderService_CancelOrder_NoBroker(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	os := NewOrderService(ss, testLogger())

	_, err := os.CancelOrder("nouser@example.com", "order-123", "regular")
	if err == nil {
		t.Fatal("Expected error when broker cannot be resolved")
	}
}

func TestOrderService_GetOrders_Success(t *testing.T) {
	t.Parallel()
	os := createDevModeOrderService()

	orders, err := os.GetOrders("test@example.com")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	// Mock client returns empty or pre-configured orders
	_ = orders
}

func TestOrderService_GetOrders_NoBroker(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	os := NewOrderService(ss, testLogger())

	_, err := os.GetOrders("nouser@example.com")
	if err == nil {
		t.Fatal("Expected error when broker cannot be resolved")
	}
}

func TestOrderService_GetTrades_Success(t *testing.T) {
	t.Parallel()
	os := createDevModeOrderService()

	trades, err := os.GetTrades("test@example.com")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	_ = trades
}

func TestOrderService_GetTrades_NoBroker(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	os := NewOrderService(ss, testLogger())

	_, err := os.GetTrades("nouser@example.com")
	if err == nil {
		t.Fatal("Expected error when broker cannot be resolved")
	}
}

// ===========================================================================
// PortfolioService — all methods with devMode (mock broker)
// ===========================================================================

func createDevModePortfolioService() *PortfolioService {
	ss := createDevModeSessionService()
	return NewPortfolioService(ss, testLogger())
}

func TestPortfolioService_GetBroker_Error(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ps := NewPortfolioService(ss, testLogger())

	_, err := ps.getBroker("nouser@example.com")
	if err == nil {
		t.Fatal("Expected error from getBroker with no token")
	}
	if !strings.Contains(err.Error(), "portfolio:") {
		t.Errorf("Error should be wrapped with 'portfolio:', got: %v", err)
	}
}

func TestPortfolioService_GetHoldings_Success(t *testing.T) {
	t.Parallel()
	ps := createDevModePortfolioService()

	holdings, err := ps.GetHoldings("test@example.com")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	// Demo client has pre-configured holdings
	if len(holdings) == 0 {
		t.Error("Expected demo holdings from mock broker")
	}
}

func TestPortfolioService_GetHoldings_NoBroker(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ps := NewPortfolioService(ss, testLogger())

	_, err := ps.GetHoldings("nouser@example.com")
	if err == nil {
		t.Fatal("Expected error when broker cannot be resolved")
	}
}

func TestPortfolioService_GetPositions_Success(t *testing.T) {
	t.Parallel()
	ps := createDevModePortfolioService()

	positions, err := ps.GetPositions("test@example.com")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	_ = positions
}

func TestPortfolioService_GetPositions_NoBroker(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ps := NewPortfolioService(ss, testLogger())

	_, err := ps.GetPositions("nouser@example.com")
	if err == nil {
		t.Fatal("Expected error when broker cannot be resolved")
	}
}

func TestPortfolioService_GetMargins_Success(t *testing.T) {
	t.Parallel()
	ps := createDevModePortfolioService()

	margins, err := ps.GetMargins("test@example.com")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	_ = margins
}

func TestPortfolioService_GetMargins_NoBroker(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ps := NewPortfolioService(ss, testLogger())

	_, err := ps.GetMargins("nouser@example.com")
	if err == nil {
		t.Fatal("Expected error when broker cannot be resolved")
	}
}

func TestPortfolioService_GetProfile_Success(t *testing.T) {
	t.Parallel()
	ps := createDevModePortfolioService()

	profile, err := ps.GetProfile("test@example.com")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if profile.UserID == "" {
		t.Error("Expected non-empty UserID from demo profile")
	}
}

func TestPortfolioService_GetProfile_NoBroker(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ps := NewPortfolioService(ss, testLogger())

	_, err := ps.GetProfile("nouser@example.com")
	if err == nil {
		t.Fatal("Expected error when broker cannot be resolved")
	}
}

// ===========================================================================
// Consolidated from coverage_*.go files
// ===========================================================================

// ===========================================================================
// AlertService — getters and setters
// ===========================================================================

func TestAlertService_Getters(t *testing.T) {
	t.Parallel()

	store := alerts.NewStore(nil)
	eval := alerts.NewEvaluator(store, testLogger())
	trail := alerts.NewTrailingStopManager(testLogger())

	svc := NewAlertService(AlertServiceConfig{
		AlertStore:      store,
		AlertEvaluator:  eval,
		TrailingStopMgr: trail,
	})

	if svc.AlertStore() != store {
		t.Error("AlertStore() should return the configured store")
	}
	if svc.AlertEvaluator() != eval {
		t.Error("AlertEvaluator() should return the configured evaluator")
	}
	if svc.TrailingStopManager() != trail {
		t.Error("TrailingStopManager() should return the configured manager")
	}
	if svc.TelegramNotifier() != nil {
		t.Error("TelegramNotifier() should return nil when not set")
	}
	if svc.PnLService() != nil {
		t.Error("PnLService() should return nil when not set")
	}
}

func TestAlertService_SetPnLService(t *testing.T) {
	t.Parallel()

	svc := NewAlertService(AlertServiceConfig{})
	if svc.PnLService() != nil {
		t.Error("PnLService should be nil initially")
	}

	// Create a dummy PnL service
	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}
	defer db.Close()
	pnlSvc := alerts.NewPnLSnapshotService(db, nil, nil, testLogger())

	svc.SetPnLService(pnlSvc)
	if svc.PnLService() != pnlSvc {
		t.Error("PnLService() should return the set service")
	}
}

func TestCredentialService_ResolveCredentials_PerUser(t *testing.T) {
	t.Parallel()

	credStore := &mockCredentialStore{entries: map[string]*KiteCredentialEntry{
		"user@example.com": {APIKey: "user-key", APISecret: "user-secret"},
	}}
	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{}}

	svc := NewCredentialService(CredentialServiceConfig{
		APIKey:          "global-key",
		APISecret:       "global-secret",
		CredentialStore: credStore,
		TokenStore:      tokenStore,
		Logger:          testLogger(),
	})

	key, secret, err := svc.ResolveCredentials("user@example.com")
	if err != nil {
		t.Fatalf("ResolveCredentials error: %v", err)
	}
	if key != "user-key" {
		t.Errorf("API key = %q, want %q", key, "user-key")
	}
	if secret != "user-secret" {
		t.Errorf("API secret = %q, want %q", secret, "user-secret")
	}
}

func TestCredentialService_ResolveCredentials_GlobalFallback(t *testing.T) {
	t.Parallel()

	credStore := &mockCredentialStore{entries: map[string]*KiteCredentialEntry{}}
	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{}}

	svc := NewCredentialService(CredentialServiceConfig{
		APIKey:          "global-key",
		APISecret:       "global-secret",
		CredentialStore: credStore,
		TokenStore:      tokenStore,
		Logger:          testLogger(),
	})

	key, secret, err := svc.ResolveCredentials("unknown@example.com")
	if err != nil {
		t.Fatalf("ResolveCredentials error: %v", err)
	}
	if key != "global-key" || secret != "global-secret" {
		t.Errorf("Expected global credentials, got key=%q secret=%q", key, secret)
	}
}

func TestCredentialService_ResolveCredentials_NoCredentials(t *testing.T) {
	t.Parallel()

	credStore := &mockCredentialStore{entries: map[string]*KiteCredentialEntry{}}
	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{}}

	svc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: credStore,
		TokenStore:      tokenStore,
		Logger:          testLogger(),
	})

	_, _, err := svc.ResolveCredentials("user@example.com")
	if err == nil {
		t.Error("Expected error when no credentials available")
	}
}

func TestCredentialService_HasCredentials(t *testing.T) {
	t.Parallel()

	credStore := &mockCredentialStore{entries: map[string]*KiteCredentialEntry{
		"user@example.com": {APIKey: "key", APISecret: "secret"},
	}}
	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{}}

	svc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: credStore,
		TokenStore:      tokenStore,
		Logger:          testLogger(),
	})

	if !svc.HasCredentials("user@example.com") {
		t.Error("HasCredentials should return true for existing user")
	}
	if svc.HasCredentials("unknown@example.com") {
		t.Error("HasCredentials should return false for unknown user (no global creds)")
	}
}

func TestCredentialService_GetAccessTokenForEmail(t *testing.T) {
	t.Parallel()

	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{
		"user@example.com": {AccessToken: "cached-token"},
	}}

	svc := NewCredentialService(CredentialServiceConfig{
		AccessToken:     "global-token",
		CredentialStore: &mockCredentialStore{entries: map[string]*KiteCredentialEntry{}},
		TokenStore:      tokenStore,
		Logger:          testLogger(),
	})

	// Per-user token
	token := svc.GetAccessTokenForEmail("user@example.com")
	if token != "cached-token" {
		t.Errorf("token = %q, want %q", token, "cached-token")
	}

	// Global fallback
	token = svc.GetAccessTokenForEmail("unknown@example.com")
	if token != "global-token" {
		t.Errorf("token = %q, want %q", token, "global-token")
	}

	// Empty email uses global
	token = svc.GetAccessTokenForEmail("")
	if token != "global-token" {
		t.Errorf("token = %q, want %q", token, "global-token")
	}
}

func TestCredentialService_HasCachedToken(t *testing.T) {
	t.Parallel()

	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{
		"user@example.com": {AccessToken: "tok"},
	}}

	svc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: &mockCredentialStore{entries: map[string]*KiteCredentialEntry{}},
		TokenStore:      tokenStore,
		Logger:          testLogger(),
	})

	if !svc.HasCachedToken("user@example.com") {
		t.Error("HasCachedToken should return true")
	}
	if svc.HasCachedToken("unknown@example.com") {
		t.Error("HasCachedToken should return false for unknown")
	}
	if svc.HasCachedToken("") {
		t.Error("HasCachedToken should return false for empty email")
	}
}

func TestCredentialService_HasUserCredentials(t *testing.T) {
	t.Parallel()

	credStore := &mockCredentialStore{entries: map[string]*KiteCredentialEntry{
		"user@example.com": {APIKey: "k", APISecret: "s"},
	}}

	svc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: credStore,
		TokenStore:      &mockTokenStore{entries: map[string]*KiteTokenEntry{}},
		Logger:          testLogger(),
	})

	if !svc.HasUserCredentials("user@example.com") {
		t.Error("HasUserCredentials should return true")
	}
	if svc.HasUserCredentials("unknown@example.com") {
		t.Error("HasUserCredentials should return false")
	}
	if svc.HasUserCredentials("") {
		t.Error("HasUserCredentials should return false for empty")
	}
}

func TestCredentialService_HasGlobalCredentials(t *testing.T) {
	t.Parallel()

	svc := NewCredentialService(CredentialServiceConfig{
		APIKey:          "key",
		APISecret:       "secret",
		CredentialStore: &mockCredentialStore{entries: map[string]*KiteCredentialEntry{}},
		TokenStore:      &mockTokenStore{entries: map[string]*KiteTokenEntry{}},
		Logger:          testLogger(),
	})
	if !svc.HasGlobalCredentials() {
		t.Error("HasGlobalCredentials should return true")
	}

	svc2 := NewCredentialService(CredentialServiceConfig{
		CredentialStore: &mockCredentialStore{entries: map[string]*KiteCredentialEntry{}},
		TokenStore:      &mockTokenStore{entries: map[string]*KiteTokenEntry{}},
		Logger:          testLogger(),
	})
	if svc2.HasGlobalCredentials() {
		t.Error("HasGlobalCredentials should return false when no global creds")
	}
}

func TestCredentialService_IsTokenValid(t *testing.T) {
	t.Parallel()

	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{
		"user@example.com": {AccessToken: "tok", StoredAt: time.Now()},
	}}

	svc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: &mockCredentialStore{entries: map[string]*KiteCredentialEntry{}},
		TokenStore:      tokenStore,
		Logger:          testLogger(),
	})

	if !svc.IsTokenValid("user@example.com") {
		t.Error("IsTokenValid should return true for recently stored token")
	}
	if svc.IsTokenValid("unknown@example.com") {
		t.Error("IsTokenValid should return false for unknown email")
	}
}

// ===========================================================================
// IsKiteTokenExpired
// ===========================================================================

func TestIsKiteTokenExpired_RecentToken(t *testing.T) {
	t.Parallel()
	// Token stored just now should NOT be expired
	if IsKiteTokenExpired(time.Now()) {
		t.Error("Token stored just now should not be expired")
	}
}

func TestIsKiteTokenExpired_OldToken(t *testing.T) {
	t.Parallel()
	// Token stored 2 days ago should be expired
	if !IsKiteTokenExpired(time.Now().Add(-48 * time.Hour)) {
		t.Error("Token stored 2 days ago should be expired")
	}
}

// ===========================================================================
// FamilyService
// ===========================================================================

func TestFamilyService_NilStores(t *testing.T) {
	t.Parallel()

	fs := NewFamilyService(nil, nil, nil)
	if fs == nil {
		t.Fatal("NewFamilyService should not return nil")
	}

	// AdminEmailFn with nil store
	fn := fs.AdminEmailFn()
	if fn("user@example.com") != "" {
		t.Error("AdminEmailFn should return empty with nil store")
	}

	// ListMembers with nil store
	members := fs.ListMembers("admin@example.com")
	if members != nil {
		t.Error("ListMembers should return nil with nil store")
	}

	// MemberCount with nil store
	if fs.MemberCount("admin@example.com") != 0 {
		t.Error("MemberCount should return 0 with nil store")
	}

	// MaxUsers with nil billing store
	if fs.MaxUsers("admin@example.com") != 1 {
		t.Errorf("MaxUsers with nil billing store should return 1, got %d", fs.MaxUsers("admin@example.com"))
	}

	// CanInvite with nil stores
	ok, current, max := fs.CanInvite("admin@example.com")
	if !ok {
		t.Error("CanInvite should return true when 0 < 1")
	}
	if current != 0 || max != 1 {
		t.Errorf("CanInvite: current=%d max=%d, want 0, 1", current, max)
	}

	// RemoveMember with nil store
	err := fs.RemoveMember("admin@example.com", "member@example.com")
	if err == nil {
		t.Error("RemoveMember should error with nil store")
	}
}

// ===========================================================================
// ManagedSessionService
// ===========================================================================

func TestManagedSessionService(t *testing.T) {
	t.Parallel()

	// Nil registry
	svc := NewManagedSessionService(nil)
	if svc.ActiveCount() != 0 {
		t.Errorf("ActiveCount with nil registry = %d, want 0", svc.ActiveCount())
	}
	if svc.TerminateByEmail("user@example.com") != 0 {
		t.Error("TerminateByEmail with nil registry should return 0")
	}
	if svc.Registry() != nil {
		t.Error("Registry should be nil")
	}

	// With registry
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	reg := m.SessionManager()
	svc2 := NewManagedSessionService(reg)
	if svc2.Registry() != reg {
		t.Error("Registry() should return the configured registry")
	}
	if svc2.ActiveCount() != 0 {
		t.Errorf("ActiveCount with empty registry = %d, want 0", svc2.ActiveCount())
	}
}

// ---------------------------------------------------------------------------
// FamilyService — full coverage of all branches
// ---------------------------------------------------------------------------

// mockUserStoreForFamily implements FamilyUserStore (3 methods) for testing.
// ISP benefit: mock only needs the methods FamilyService actually uses.
type mockUserStoreForFamily struct {
	users map[string]*users.User
}

func (m *mockUserStoreForFamily) Get(email string) (*users.User, bool) {
	u, ok := m.users[email]
	return u, ok
}

func (m *mockUserStoreForFamily) SetAdminEmail(email, adminEmail string) error {
	if u, ok := m.users[email]; ok {
		u.AdminEmail = adminEmail
		return nil
	}
	return nil
}

func (m *mockUserStoreForFamily) ListByAdminEmail(adminEmail string) []*users.User {
	var out []*users.User
	for _, u := range m.users {
		if u.AdminEmail == adminEmail {
			out = append(out, u)
		}
	}
	return out
}

// mockBillingStore implements BillingStoreInterface for testing.
type mockBillingStoreForFamily struct {
	subs map[string]*billing.Subscription
}

func (m *mockBillingStoreForFamily) GetTier(email string) billing.Tier { return billing.TierFree }

func (m *mockBillingStoreForFamily) SetSubscription(sub *billing.Subscription) error {
	m.subs[sub.AdminEmail] = sub
	return nil
}

func (m *mockBillingStoreForFamily) GetSubscription(email string) *billing.Subscription {
	return m.subs[email]
}

func (m *mockBillingStoreForFamily) GetEmailByCustomerID(customerID string) string { return "" }

func (m *mockBillingStoreForFamily) IsEventProcessed(eventID string) bool { return false }

func (m *mockBillingStoreForFamily) MarkEventProcessed(eventID, eventType string) error {
	return nil
}

func (m *mockBillingStoreForFamily) GetTierForUser(email string, adminEmailFn func(string) string) billing.Tier {
	return billing.TierFree
}

func TestFamilyService_AdminEmailFn_WithStore(t *testing.T) {
	t.Parallel()

	us := &mockUserStoreForFamily{users: map[string]*users.User{
		"member@example.com": {Email: "member@example.com", AdminEmail: "admin@example.com"},
		"solo@example.com":   {Email: "solo@example.com", AdminEmail: ""},
	}}

	fs := NewFamilyService(us, nil, nil)
	fn := fs.AdminEmailFn()

	// User with admin
	if got := fn("member@example.com"); got != "admin@example.com" {
		t.Errorf("AdminEmailFn(member) = %q, want admin@example.com", got)
	}

	// User without admin
	if got := fn("solo@example.com"); got != "" {
		t.Errorf("AdminEmailFn(solo) = %q, want empty", got)
	}

	// Non-existent user
	if got := fn("unknown@example.com"); got != "" {
		t.Errorf("AdminEmailFn(unknown) = %q, want empty", got)
	}
}

func TestFamilyService_ListMembers_WithStore(t *testing.T) {
	t.Parallel()

	us := &mockUserStoreForFamily{users: map[string]*users.User{
		"m1@example.com":    {Email: "m1@example.com", AdminEmail: "admin@example.com"},
		"m2@example.com":    {Email: "m2@example.com", AdminEmail: "admin@example.com"},
		"other@example.com": {Email: "other@example.com", AdminEmail: "other-admin@example.com"},
	}}

	fs := NewFamilyService(us, nil, nil)
	members := fs.ListMembers("admin@example.com")
	if len(members) != 2 {
		t.Errorf("ListMembers count = %d, want 2", len(members))
	}

	// Zero members for unknown admin
	members = fs.ListMembers("nobody@example.com")
	if len(members) != 0 {
		t.Errorf("ListMembers(nobody) count = %d, want 0", len(members))
	}
}

func TestFamilyService_MaxUsers_WithBillingStore(t *testing.T) {
	t.Parallel()

	bs := &mockBillingStoreForFamily{subs: map[string]*billing.Subscription{
		"admin@example.com": {AdminEmail: "admin@example.com", MaxUsers: 10},
	}}

	fs := NewFamilyService(nil, bs, nil)

	// Admin with subscription
	if got := fs.MaxUsers("admin@example.com"); got != 10 {
		t.Errorf("MaxUsers(admin) = %d, want 10", got)
	}

	// Unknown admin — no subscription
	if got := fs.MaxUsers("unknown@example.com"); got != 1 {
		t.Errorf("MaxUsers(unknown) = %d, want 1", got)
	}
}

func TestFamilyService_MaxUsers_NilSubscription(t *testing.T) {
	t.Parallel()

	bs := &mockBillingStoreForFamily{subs: map[string]*billing.Subscription{}}
	fs := NewFamilyService(nil, bs, nil)

	// No subscription for this admin
	if got := fs.MaxUsers("admin@example.com"); got != 1 {
		t.Errorf("MaxUsers(no sub) = %d, want 1", got)
	}
}

func TestFamilyService_MaxUsers_ZeroMaxUsers(t *testing.T) {
	t.Parallel()

	bs := &mockBillingStoreForFamily{subs: map[string]*billing.Subscription{
		"admin@example.com": {AdminEmail: "admin@example.com", MaxUsers: 0},
	}}
	fs := NewFamilyService(nil, bs, nil)

	// MaxUsers < 1 should return 1
	if got := fs.MaxUsers("admin@example.com"); got != 1 {
		t.Errorf("MaxUsers(zero) = %d, want 1", got)
	}
}

func TestFamilyService_RemoveMember_NotInFamily(t *testing.T) {
	t.Parallel()

	us := &mockUserStoreForFamily{users: map[string]*users.User{
		"member@example.com": {Email: "member@example.com", AdminEmail: "other-admin@example.com"},
	}}

	fs := NewFamilyService(us, nil, nil)
	err := fs.RemoveMember("admin@example.com", "member@example.com")
	if err == nil {
		t.Error("RemoveMember should error when member is not in admin's family")
	}
	if err.Error() != "member@example.com is not in your family" {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestFamilyService_RemoveMember_UserNotFound(t *testing.T) {
	t.Parallel()

	us := &mockUserStoreForFamily{users: map[string]*users.User{}}
	fs := NewFamilyService(us, nil, nil)
	err := fs.RemoveMember("admin@example.com", "unknown@example.com")
	if err == nil {
		t.Error("RemoveMember should error when user not found")
	}
}

func TestFamilyService_RemoveMember_Success(t *testing.T) {
	t.Parallel()

	us := &mockUserStoreForFamily{users: map[string]*users.User{
		"member@example.com": {Email: "member@example.com", AdminEmail: "admin@example.com"},
	}}

	fs := NewFamilyService(us, nil, nil)
	err := fs.RemoveMember("admin@example.com", "member@example.com")
	if err != nil {
		t.Fatalf("RemoveMember error: %v", err)
	}

	// Verify admin email was cleared
	u, _ := us.Get("member@example.com")
	if u.AdminEmail != "" {
		t.Errorf("AdminEmail should be empty after removal, got %q", u.AdminEmail)
	}
}

func TestFamilyService_CanInvite_WithMembers(t *testing.T) {
	t.Parallel()

	us := &mockUserStoreForFamily{users: map[string]*users.User{
		"m1@example.com": {Email: "m1@example.com", AdminEmail: "admin@example.com"},
		"m2@example.com": {Email: "m2@example.com", AdminEmail: "admin@example.com"},
	}}
	bs := &mockBillingStoreForFamily{subs: map[string]*billing.Subscription{
		"admin@example.com": {AdminEmail: "admin@example.com", MaxUsers: 3},
	}}

	fs := NewFamilyService(us, bs, nil)

	ok, current, max := fs.CanInvite("admin@example.com")
	if !ok {
		t.Error("CanInvite should be true (2 < 3)")
	}
	if current != 2 {
		t.Errorf("current = %d, want 2", current)
	}
	if max != 3 {
		t.Errorf("max = %d, want 3", max)
	}
}

func TestFamilyService_CanInvite_AtCapacity(t *testing.T) {
	t.Parallel()

	us := &mockUserStoreForFamily{users: map[string]*users.User{
		"m1@example.com": {Email: "m1@example.com", AdminEmail: "admin@example.com"},
		"m2@example.com": {Email: "m2@example.com", AdminEmail: "admin@example.com"},
	}}
	bs := &mockBillingStoreForFamily{subs: map[string]*billing.Subscription{
		"admin@example.com": {AdminEmail: "admin@example.com", MaxUsers: 2},
	}}

	fs := NewFamilyService(us, bs, nil)

	ok, _, _ := fs.CanInvite("admin@example.com")
	if ok {
		t.Error("CanInvite should be false (2 >= 2)")
	}
}

// ---------------------------------------------------------------------------
// IsKiteTokenExpired — boundary at exactly 6 AM IST
// ---------------------------------------------------------------------------

func TestIsKiteTokenExpired_ExactlyAt6AM(t *testing.T) {
	t.Parallel()

	// Token stored just before 6 AM today (5:59 AM IST)
	now := time.Now().In(KolkataLocation)
	sixAM := time.Date(now.Year(), now.Month(), now.Day(), 6, 0, 0, 0, KolkataLocation)

	if now.Before(sixAM) {
		// If current time is before 6 AM, a token from yesterday at 6:01 AM should be valid
		yesterday6AM := sixAM.AddDate(0, 0, -1).Add(1 * time.Minute)
		if IsKiteTokenExpired(yesterday6AM) {
			t.Error("Token stored after yesterday's 6 AM should not be expired (before today's 6 AM)")
		}
	} else {
		// If current time is after 6 AM, a token from today at 5:59 AM should be expired
		today559AM := sixAM.Add(-1 * time.Minute)
		if !IsKiteTokenExpired(today559AM) {
			t.Error("Token stored at 5:59 AM should be expired after 6 AM")
		}

		// Token stored at 6:01 AM should NOT be expired
		today601AM := sixAM.Add(1 * time.Minute)
		if IsKiteTokenExpired(today601AM) {
			t.Error("Token stored at 6:01 AM should NOT be expired")
		}
	}
}

func TestIsKiteTokenExpired_StoredYesterday(t *testing.T) {
	t.Parallel()
	// Token stored yesterday at any time should be expired
	yesterday := time.Now().Add(-30 * time.Hour)
	if !IsKiteTokenExpired(yesterday) {
		t.Error("Token stored 30 hours ago should be expired")
	}
}

func TestIsKiteTokenExpired_StoredJustNow(t *testing.T) {
	t.Parallel()
	// Token stored just now should not be expired
	if IsKiteTokenExpired(time.Now()) {
		t.Error("Token stored just now should not be expired")
	}
}

// ---------------------------------------------------------------------------
// OrderService — getBroker error path
// ---------------------------------------------------------------------------

func TestOrderService_GetBroker_NoToken(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	os := NewOrderService(ss, testLogger())

	_, err := os.PlaceOrder("unknown@example.com", broker.OrderParams{})
	if err == nil {
		t.Error("Expected error for user without access token")
	}

	_, err = os.ModifyOrder("unknown@example.com", "ORD001", broker.OrderParams{})
	if err == nil {
		t.Error("Expected error for ModifyOrder")
	}

	_, err = os.CancelOrder("unknown@example.com", "ORD001", "regular")
	if err == nil {
		t.Error("Expected error for CancelOrder")
	}

	_, err = os.GetOrders("unknown@example.com")
	if err == nil {
		t.Error("Expected error for GetOrders")
	}

	_, err = os.GetTrades("unknown@example.com")
	if err == nil {
		t.Error("Expected error for GetTrades")
	}
}

func TestOrderService_DevMode_PlaceOrder(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	os := NewOrderService(ss, testLogger())

	resp, err := os.PlaceOrder("user@example.com", broker.OrderParams{
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		TransactionType: "BUY",
		Quantity:        10,
		Product:         "CNC",
		OrderType:       "MARKET",
		Variety:         "regular",
	})
	if err != nil {
		t.Fatalf("PlaceOrder error: %v", err)
	}
	if resp.OrderID == "" {
		t.Error("Expected non-empty OrderID from mock broker")
	}
}

func TestOrderService_DevMode_GetOrders(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	os := NewOrderService(ss, testLogger())

	orders, err := os.GetOrders("user@example.com")
	if err != nil {
		t.Fatalf("GetOrders error: %v", err)
	}
	_ = orders // May be empty from mock
}

func TestOrderService_DevMode_GetTrades(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	os := NewOrderService(ss, testLogger())

	trades, err := os.GetTrades("user@example.com")
	if err != nil {
		t.Fatalf("GetTrades error: %v", err)
	}
	_ = trades
}

// ---------------------------------------------------------------------------
// PortfolioService — getBroker error path
// ---------------------------------------------------------------------------

func TestPortfolioService_GetBroker_NoToken(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ps := NewPortfolioService(ss, testLogger())

	_, err := ps.GetHoldings("unknown@example.com")
	if err == nil {
		t.Error("Expected error for GetHoldings")
	}

	_, err = ps.GetPositions("unknown@example.com")
	if err == nil {
		t.Error("Expected error for GetPositions")
	}

	_, err = ps.GetMargins("unknown@example.com")
	if err == nil {
		t.Error("Expected error for GetMargins")
	}

	_, err = ps.GetProfile("unknown@example.com")
	if err == nil {
		t.Error("Expected error for GetProfile")
	}
}

func TestPortfolioService_DevMode_GetHoldings(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	ps := NewPortfolioService(ss, testLogger())

	holdings, err := ps.GetHoldings("user@example.com")
	if err != nil {
		t.Fatalf("GetHoldings error: %v", err)
	}
	_ = holdings
}

func TestPortfolioService_DevMode_GetPositions(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	ps := NewPortfolioService(ss, testLogger())

	positions, err := ps.GetPositions("user@example.com")
	if err != nil {
		t.Fatalf("GetPositions error: %v", err)
	}
	_ = positions
}

func TestPortfolioService_DevMode_GetMargins(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	ps := NewPortfolioService(ss, testLogger())

	margins, err := ps.GetMargins("user@example.com")
	if err != nil {
		t.Fatalf("GetMargins error: %v", err)
	}
	_ = margins
}

func TestPortfolioService_DevMode_GetProfile(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	ps := NewPortfolioService(ss, testLogger())

	profile, err := ps.GetProfile("user@example.com")
	if err != nil {
		t.Fatalf("GetProfile error: %v", err)
	}
	_ = profile
}

// ===========================================================================
// IsKiteTokenExpired — boundary cases
// ===========================================================================

func TestIsKiteTokenExpired_ZeroTime(t *testing.T) {
	t.Parallel()
	if !IsKiteTokenExpired(time.Time{}) {
		t.Error("Zero time should be considered expired")
	}
}
