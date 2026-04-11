package kc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
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
		Tradingsymbol: "INFY",
		Exchange:      "NSE",
		TransactionType: "BUY",
		OrderType:     "MARKET",
		Quantity:      1,
		Product:       "CNC",
		Variety:       "regular",
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
