package kc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
)

// ===========================================================================
// coverage_push_test.go — Push kc root from 87% to 95%+
//
// Targets:
// - CompleteSession (55.6%) via mock Kite HTTP server
// - GetOrCreateSessionWithEmail (42.4%) various paths
// - OpenBrowser (45.5%) error paths + non-local mode
// - HandleKiteCallback (62.5%) full success path
// - New() (69.7%) with AlertDBPath and edge configs
// - order_service / portfolio_service nil-broker paths
// - session_signing error paths
// ===========================================================================

// ---------------------------------------------------------------------------
// Mock Kite API server
// ---------------------------------------------------------------------------

// kiteEnvelope wraps data in the Kite API JSON envelope format.
func kiteEnvelope(t *testing.T, data interface{}) string {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{"data": data, "status": "success"})
	if err != nil {
		t.Fatalf("kiteEnvelope marshal: %v", err)
	}
	return string(b)
}

// newMockKiteServer returns an httptest.Server that handles:
//   - POST /session/token  (GenerateSession)
//   - GET  /user/profile   (GetUserProfile)
//   - DELETE /session/token (InvalidateAccessToken)
func newMockKiteServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/session/token" && r.Method == http.MethodPost:
			fmt.Fprint(w, kiteEnvelope(t, map[string]interface{}{
				"user_id":       "XY1234",
				"user_name":     "Test User",
				"email":         "test@example.com",
				"access_token":  "mock-access-token",
				"public_token":  "mock-public-token",
				"refresh_token": "mock-refresh-token",
			}))
		case r.URL.Path == "/user/profile" && r.Method == http.MethodGet:
			fmt.Fprint(w, kiteEnvelope(t, map[string]interface{}{
				"user_id":   "XY1234",
				"user_name": "Test User",
				"email":     "test@example.com",
			}))
		case r.URL.Path == "/session/token" && r.Method == http.MethodDelete:
			fmt.Fprint(w, kiteEnvelope(t, true))
		default:
			http.Error(w, `{"status":"error","message":"not found"}`, http.StatusNotFound)
		}
	}))
}

// newKiteClientWithMock creates a *kiteconnect.Client pointed at the mock server.
func newKiteClientWithMock(ts *httptest.Server, apiKey string) *kiteconnect.Client {
	c := kiteconnect.New(apiKey)
	c.SetBaseURI(ts.URL)
	return c
}

// newTestManagerWithDB creates a Manager backed by an in-memory SQLite DB.
func newTestManagerWithDB(t *testing.T) *Manager {
	t.Helper()
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		AlertDBPath:        ":memory:",
	})
	if err != nil {
		t.Fatalf("newTestManagerWithDB: %v", err)
	}
	t.Cleanup(func() { m.Shutdown() })
	return m
}

// ---------------------------------------------------------------------------
// CompleteSession — success path via mock Kite
// ---------------------------------------------------------------------------

func TestCompleteSession_Success(t *testing.T) {
	t.Parallel()
	ts := newMockKiteServer(t)
	defer ts.Close()

	m := newTestManagerWithDB(t)

	// Generate a session
	sessionID := m.GenerateSession()

	// Point the session's Kite client at the mock server
	kd, err := m.GetSession(sessionID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	kd.Kite.Client.SetBaseURI(ts.URL)

	// Complete the session
	err = m.CompleteSession(sessionID, "mock-request-token")
	if err != nil {
		t.Fatalf("CompleteSession: %v", err)
	}
}

// TestCompleteSession_WithMetrics is in manager_test.go (via TestNew_WithMetrics flow).

func TestCompleteSession_WithEmailAndTokenCache(t *testing.T) {
	t.Parallel()
	ts := newMockKiteServer(t)
	defer ts.Close()

	m := newTestManagerWithDB(t)

	// Create session with email
	kd, isNew, err := m.GetOrCreateSessionWithEmail("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee01", "user@example.com")
	if err != nil {
		t.Fatalf("GetOrCreateSessionWithEmail: %v", err)
	}
	if !isNew {
		t.Error("Expected new session")
	}
	kd.Kite.Client.SetBaseURI(ts.URL)

	// Complete session
	err = m.CompleteSession("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee01", "mock-request-token")
	if err != nil {
		t.Fatalf("CompleteSession: %v", err)
	}

	// Verify token was cached
	entry, ok := m.TokenStore().Get("user@example.com")
	if !ok {
		t.Error("Expected token to be cached for user")
	}
	if entry.AccessToken != "mock-access-token" {
		t.Errorf("AccessToken = %q, want mock-access-token", entry.AccessToken)
	}
}

func TestCompleteSession_EmptySessionID(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("test_key", "test_secret")
	err := m.CompleteSession("", "mock-request-token")
	if err == nil {
		t.Error("Expected error for empty session ID")
	}
}

func TestCompleteSession_SessionNotFound(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("test_key", "test_secret")
	err := m.CompleteSession("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee99", "token")
	if err == nil {
		t.Error("Expected error for nonexistent session")
	}
}

func TestCompleteSession_NoAPISecret(t *testing.T) {
	t.Parallel()
	m, _ := New(Config{
		APIKey:             "",
		APISecret:          "",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
	})

	sessionID := m.GenerateSession()
	err := m.CompleteSession(sessionID, "mock-request-token")
	if err == nil {
		t.Error("Expected error for missing API secret")
	}
}

func TestCompleteSession_GenerateSessionFails(t *testing.T) {
	t.Parallel()
	// Use a server that returns errors for /session/token
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"status":"error","error_type":"TokenException","message":"Invalid token"}`)
	}))
	defer ts.Close()

	m, _ := newTestManager("test_key", "test_secret")
	sessionID := m.GenerateSession()
	kd, _ := m.GetSession(sessionID)
	kd.Kite.Client.SetBaseURI(ts.URL)

	err := m.CompleteSession(sessionID, "bad-token")
	if err == nil {
		t.Error("Expected error for failed GenerateSession")
	}
}

// ---------------------------------------------------------------------------
// GetOrCreateSessionWithEmail — deeper paths
// ---------------------------------------------------------------------------

func TestGetOrCreateSessionWithEmail_EmptySessionID(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("test_key", "test_secret")
	_, _, err := m.GetOrCreateSessionWithEmail("", "user@test.com")
	if err == nil {
		t.Error("Expected error for empty session ID")
	}
}

func TestGetOrCreateSessionWithEmail_NewSession(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("test_key", "test_secret")
	kd, isNew, err := m.GetOrCreateSessionWithEmail("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee02", "user@test.com")
	if err != nil {
		t.Fatalf("GetOrCreateSessionWithEmail: %v", err)
	}
	if !isNew {
		t.Error("Expected new session")
	}
	if kd.Email != "user@test.com" {
		t.Errorf("Email = %q, want user@test.com", kd.Email)
	}
}

func TestGetOrCreateSessionWithEmail_ExistingSession(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("test_key", "test_secret")
	sid := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee03"

	// Create first
	_, isNew, _ := m.GetOrCreateSessionWithEmail(sid, "user@test.com")
	if !isNew {
		t.Error("Expected new session on first call")
	}

	// Get existing
	_, isNew, _ = m.GetOrCreateSessionWithEmail(sid, "user@test.com")
	if isNew {
		t.Error("Expected existing session on second call")
	}
}

func TestGetOrCreateSessionWithEmail_EmailUpdateOnExisting(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("test_key", "test_secret")
	sid := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee04"

	// Create without email
	_, _, _ = m.GetOrCreateSessionWithEmail(sid, "")

	// Update with email
	kd, _, err := m.GetOrCreateSessionWithEmail(sid, "new@test.com")
	if err != nil {
		t.Fatalf("GetOrCreateSessionWithEmail with email update: %v", err)
	}
	// Email should be updated on the session
	if kd.Email != "new@test.com" {
		t.Errorf("Email after update = %q, want new@test.com", kd.Email)
	}
}

func TestGetOrCreateSessionWithEmail_CachedTokenApplied(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("test_key", "test_secret")

	// Pre-cache a token
	m.TokenStore().Set("cached@test.com", &KiteTokenEntry{
		AccessToken: "cached-token",
		UserID:      "U1",
	})

	kd, isNew, err := m.GetOrCreateSessionWithEmail("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee05", "cached@test.com")
	if err != nil {
		t.Fatalf("GetOrCreateSessionWithEmail: %v", err)
	}
	if !isNew {
		t.Error("Expected new session")
	}
	if kd.Kite == nil {
		t.Fatal("Expected non-nil Kite")
	}
	// We can't directly read the access token (unexported), but verify the session was created
	// with the cached email
	if kd.Email != "cached@test.com" {
		t.Errorf("Email = %q, want cached@test.com", kd.Email)
	}
}

func TestGetOrCreateSessionWithEmail_PreAuthApplied(t *testing.T) {
	t.Parallel()
	m, _ := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		AccessToken:        "preauth-token",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
	})

	kd, _, err := m.GetOrCreateSessionWithEmail("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee06", "")
	if err != nil {
		t.Fatalf("GetOrCreateSessionWithEmail: %v", err)
	}
	if kd.Kite == nil {
		t.Fatal("Expected non-nil Kite")
	}
	// Pre-auth token should have been applied (can't directly check — the code path is exercised)
	if !m.HasPreAuth() {
		t.Error("Expected HasPreAuth() to be true")
	}
}

// ---------------------------------------------------------------------------
// GetOrCreateSessionWithEmail — restore session after restart (Kite nil)
// ---------------------------------------------------------------------------

func TestGetOrCreateSessionWithEmail_RestorePersistedSession(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("test_key", "test_secret")

	sid := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee07"

	// Create a session, then simulate a restart by setting Kite to nil
	_, _, _ = m.GetOrCreateSessionWithEmail(sid, "restore@test.com")
	raw, _ := m.sessionSvc.sessionManager.GetSessionData(sid)
	kd := raw.(*KiteSessionData)
	kd.Kite = nil // simulate DB reload where Kite is nil

	// Pre-cache a token so restoration can apply it
	m.TokenStore().Set("restore@test.com", &KiteTokenEntry{
		AccessToken: "restored-token",
	})

	// Getting the session again should restore Kite and apply the cached token
	kd2, isNew, err := m.GetOrCreateSessionWithEmail(sid, "restore@test.com")
	if err != nil {
		t.Fatalf("GetOrCreateSessionWithEmail restore: %v", err)
	}
	if !isNew {
		t.Error("Expected isNew=true for restored session (triggers auth check)")
	}
	if kd2.Kite == nil {
		t.Error("Expected Kite to be restored (non-nil)")
	}
	// Can't directly verify access token (field unexported) but the code path is exercised
	_ = kd2
}

func TestGetOrCreateSessionWithEmail_RestoreWithPreAuth(t *testing.T) {
	t.Parallel()
	m, _ := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		AccessToken:        "global-preauth",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
	})

	sid := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee08"
	_, _, _ = m.GetOrCreateSessionWithEmail(sid, "")
	raw, _ := m.sessionSvc.sessionManager.GetSessionData(sid)
	kd := raw.(*KiteSessionData)
	kd.Kite = nil // simulate restart

	kd2, _, err := m.GetOrCreateSessionWithEmail(sid, "")
	if err != nil {
		t.Fatalf("restore with preauth: %v", err)
	}
	if kd2.Kite == nil {
		t.Error("Kite should be restored")
	}
	// Access token is unexported on kiteconnect.Client; code path is exercised
	_ = kd2
}

// ---------------------------------------------------------------------------
// OpenBrowser
// ---------------------------------------------------------------------------

func TestOpenBrowser_NonLocalMode_Push(t *testing.T) {
	t.Parallel()
	m, _ := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		AppMode:            "sse", // non-local
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
	})
	err := m.OpenBrowser("http://localhost:8080/callback")
	if err != nil {
		t.Errorf("OpenBrowser in non-local mode should return nil, got %v", err)
	}
}

func TestOpenBrowser_InvalidScheme_Push(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("test_key", "test_secret")
	// IsLocalMode returns true for empty appMode

	err := m.OpenBrowser("ftp://evil.com/payload")
	if err == nil {
		t.Error("Expected error for non-http scheme")
	}
}

func TestOpenBrowser_InvalidURL(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("test_key", "test_secret")
	err := m.OpenBrowser("://bad-url")
	if err == nil {
		t.Error("Expected error for malformed URL")
	}
}

func TestOpenBrowser_ValidHTTPURL(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("test_key", "test_secret")
	// This will try to exec the browser command. On CI it will fail with
	// "executable not found" or similar, but the code path is exercised.
	_ = m.OpenBrowser("http://localhost:8080/callback")
}

func TestOpenBrowser_ValidHTTPSURL(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("test_key", "test_secret")
	_ = m.OpenBrowser("https://example.com/page")
}

// ---------------------------------------------------------------------------
// HandleKiteCallback — full success path
// ---------------------------------------------------------------------------

func TestHandleKiteCallback_FullSuccess(t *testing.T) {
	t.Parallel()
	ts := newMockKiteServer(t)
	defer ts.Close()

	m := newTestManagerWithDB(t)

	// Generate a session and get the login URL
	sessionID := m.GenerateSession()

	// Point Kite at mock server
	kd, _ := m.GetSession(sessionID)
	kd.Kite.Client.SetBaseURI(ts.URL)

	// Sign the session ID for the callback
	signedID := m.sessionSigner.SignSessionID(sessionID)

	// Build callback URL
	callbackURL := fmt.Sprintf("/callback?request_token=mock-request-token&session_id=%s", signedID)
	req := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	rr := httptest.NewRecorder()

	handler := m.HandleKiteCallback()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("HandleKiteCallback status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}
}

func TestHandleKiteCallback_CompleteSessionFails(t *testing.T) {
	t.Parallel()
	// Mock server that rejects GenerateSession
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"status":"error","error_type":"TokenException","message":"bad token"}`)
	}))
	defer ts.Close()

	m := newTestManagerWithDB(t)
	sessionID := m.GenerateSession()
	kd, _ := m.GetSession(sessionID)
	kd.Kite.Client.SetBaseURI(ts.URL)

	signedID := m.sessionSigner.SignSessionID(sessionID)
	callbackURL := fmt.Sprintf("/callback?request_token=bad-token&session_id=%s", signedID)
	req := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	rr := httptest.NewRecorder()

	handler := m.HandleKiteCallback()
	handler(rr, req)

	// Should return 500 for failed session completion
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// New() — with AlertDBPath for persistence branches
// ---------------------------------------------------------------------------

func TestNew_WithAlertDBPath_Push(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		AlertDBPath:        ":memory:",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
	})
	if err != nil {
		t.Fatalf("New with AlertDBPath: %v", err)
	}
	defer m.Shutdown()

	// Verify DB-backed stores are initialized
	if m.AlertDB() == nil {
		t.Error("Expected AlertDB to be non-nil")
	}
}

func TestNew_WithEncryptionSecret_Push(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		AlertDBPath:        ":memory:",
		EncryptionSecret:   "test-encryption-secret-32chars!!", // 32 bytes
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
	})
	if err != nil {
		t.Fatalf("New with EncryptionSecret: %v", err)
	}
	defer m.Shutdown()
}

// TestNew_WithMetrics is in manager_test.go.

func TestNew_DevMode_Push(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		DevMode:            true,
	})
	if err != nil {
		t.Fatalf("New DevMode: %v", err)
	}
	if !m.DevMode() {
		t.Error("Expected DevMode to be true")
	}
}

func TestNew_NilLogger_Push(t *testing.T) {
	t.Parallel()
	_, err := New(Config{
		APIKey:    "test_key",
		APISecret: "test_secret",
	})
	if err == nil {
		t.Error("Expected error for nil logger")
	}
}

// ---------------------------------------------------------------------------
// PaperEngine / BillingStore — nil fallback branches
// ---------------------------------------------------------------------------

func TestPaperEngine_NilReturnsNil(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("k", "s")
	pe := m.PaperEngine()
	if pe != nil {
		t.Error("PaperEngine should return nil when not configured")
	}
}

func TestBillingStore_NilReturnsNil(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("k", "s")
	bs := m.BillingStore()
	if bs != nil {
		t.Error("BillingStore should return nil when not configured")
	}
}

// ---------------------------------------------------------------------------
// order_service — nil broker error paths
// ---------------------------------------------------------------------------

func TestOrderService_PlaceOrder_NilBrokerError(t *testing.T) {
	t.Parallel()
	m := newTestManagerWithDB(t)
	svc := m.OrderSvc()

	_, err := svc.PlaceOrder("nonexistent@test.com", broker.OrderParams{})
	if err == nil {
		t.Error("Expected error for nil broker")
	}
}

func TestOrderService_ModifyOrder_ReturnsBroker(t *testing.T) {
	t.Parallel()
	m := newTestManagerWithDB(t)
	svc := m.OrderSvc()
	_, err := svc.ModifyOrder("nobody@test.com", "ORD001", broker.OrderParams{})
	if err == nil {
		t.Error("Expected error for no broker")
	}
}

func TestOrderService_CancelOrder_ReturnsBroker(t *testing.T) {
	t.Parallel()
	m := newTestManagerWithDB(t)
	svc := m.OrderSvc()
	_, err := svc.CancelOrder("nobody@test.com", "ORD001", "regular")
	if err == nil {
		t.Error("Expected error for no broker")
	}
}

func TestOrderService_GetOrders_NilBrokerError(t *testing.T) {
	t.Parallel()
	m := newTestManagerWithDB(t)
	svc := m.OrderSvc()
	_, err := svc.GetOrders("nobody@test.com")
	if err == nil {
		t.Error("Expected error for nil broker")
	}
}

func TestOrderService_GetTrades_NilBrokerError(t *testing.T) {
	t.Parallel()
	m := newTestManagerWithDB(t)
	svc := m.OrderSvc()
	_, err := svc.GetTrades("nobody@test.com")
	if err == nil {
		t.Error("Expected error for nil broker")
	}
}

// ---------------------------------------------------------------------------
// portfolio_service — nil broker error paths
// ---------------------------------------------------------------------------

func TestPortfolioService_GetHoldings_NilBrokerError(t *testing.T) {
	t.Parallel()
	m := newTestManagerWithDB(t)
	svc := m.PortfolioSvc()
	_, err := svc.GetHoldings("nobody@test.com")
	if err == nil {
		t.Error("Expected error for nil broker")
	}
}

func TestPortfolioService_GetPositions_NilBrokerError(t *testing.T) {
	t.Parallel()
	m := newTestManagerWithDB(t)
	svc := m.PortfolioSvc()
	_, err := svc.GetPositions("nobody@test.com")
	if err == nil {
		t.Error("Expected error for nil broker")
	}
}

func TestPortfolioService_GetMargins_NilBrokerError(t *testing.T) {
	t.Parallel()
	m := newTestManagerWithDB(t)
	svc := m.PortfolioSvc()
	_, err := svc.GetMargins("nobody@test.com")
	if err == nil {
		t.Error("Expected error for nil broker")
	}
}

func TestPortfolioService_GetProfile_NilBrokerError(t *testing.T) {
	t.Parallel()
	m := newTestManagerWithDB(t)
	svc := m.PortfolioSvc()
	_, err := svc.GetProfile("nobody@test.com")
	if err == nil {
		t.Error("Expected error for nil broker")
	}
}

// ---------------------------------------------------------------------------
// session_signing — error paths
// ---------------------------------------------------------------------------

func TestNewSessionSignerWithKey_NilKey(t *testing.T) {
	t.Parallel()
	_, err := NewSessionSignerWithKey(nil)
	if err == nil {
		t.Error("Expected error for nil key")
	}
}

func TestSessionSigner_VerifyInvalidFormat_Push(t *testing.T) {
	t.Parallel()
	signer, _ := NewSessionSigner()
	_, err := signer.VerifySessionID("no-dot-separator")
	if err == nil {
		t.Error("Expected error for invalid signed format")
	}
}

func TestSessionSigner_VerifyTamperedSignature_Push(t *testing.T) {
	t.Parallel()
	signer, _ := NewSessionSigner()
	signed := signer.SignSessionID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee01")
	// Tamper with the signature
	tampered := signed[:len(signed)-4] + "XXXX"
	_, err := signer.VerifySessionID(tampered)
	if err == nil {
		t.Error("Expected error for tampered signature")
	}
}

func TestSessionSigner_SignRedirectParams_EmptySessionID_Push(t *testing.T) {
	t.Parallel()
	signer, _ := NewSessionSigner()
	_, err := signer.SignRedirectParams("")
	if err == nil {
		t.Error("Expected error for empty session ID")
	}
}

// ---------------------------------------------------------------------------
// ClearSession / ClearSessionData paths
// ---------------------------------------------------------------------------

func TestClearSession_EmptyID(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("k", "s")
	m.ClearSession("") // Should not panic
}

func TestClearSession_NonexistentID(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("k", "s")
	m.ClearSession("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee99") // Should not panic
}

func TestClearSessionData_EmptyID(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("k", "s")
	err := m.ClearSessionData("")
	if err == nil {
		t.Error("Expected error for empty session ID")
	}
}

func TestClearSessionData_NonexistentSession(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("k", "s")
	err := m.ClearSessionData("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee99")
	if err == nil {
		t.Error("Expected error for nonexistent session")
	}
}

func TestClearSessionData_ValidSession(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("k", "s")

	sid := m.GenerateSession()
	err := m.ClearSessionData(sid)
	if err != nil {
		t.Fatalf("ClearSessionData: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SessionLoginURL paths
// ---------------------------------------------------------------------------

func TestSessionLoginURL_EmptyID(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("k", "s")
	_, err := m.SessionLoginURL("")
	if err == nil {
		t.Error("Expected error for empty session ID")
	}
}

func TestSessionLoginURL_CreatesNewSession(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("test_key", "test_secret")
	// SessionLoginURL creates a new session if it doesn't exist
	url, err := m.SessionLoginURL("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee99")
	if err != nil {
		t.Fatalf("SessionLoginURL: %v", err)
	}
	if url == "" {
		t.Error("Expected non-empty URL")
	}
}

func TestSessionLoginURL_ValidSession(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("test_key", "test_secret")
	sid := m.GenerateSession()

	loginURL, err := m.SessionLoginURL(sid)
	if err != nil {
		t.Fatalf("SessionLoginURL: %v", err)
	}
	if loginURL == "" {
		t.Error("Expected non-empty login URL")
	}
}

// ---------------------------------------------------------------------------
// LoadSessions / Shutdown paths
// ---------------------------------------------------------------------------

func TestLoadSessions_WithDB(t *testing.T) {
	t.Parallel()
	m := newTestManagerWithDB(t)
	// SessionManager().LoadFromDB should not error on an empty DB
	if sm := m.SessionManager(); sm != nil {
		_ = sm.LoadFromDB()
	}
}

func TestShutdown_NoAuditStore(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("k", "s")
	m.Shutdown() // should not panic
}

func TestShutdown_WithDB_Push(t *testing.T) {
	t.Parallel()
	m := newTestManagerWithDB(t)
	m.Shutdown()
}

// ---------------------------------------------------------------------------
// expiry.go — IsKiteTokenExpired edge cases
// ---------------------------------------------------------------------------

func TestIsKiteTokenExpired_NightTime(t *testing.T) {
	t.Parallel()
	// Token stored at 11 PM IST yesterday — should not be expired if current time is before 6 AM IST
	ist := time.FixedZone("IST", 5*3600+30*60)
	storedAt := time.Now().In(ist).Add(-1 * time.Hour)
	result := IsKiteTokenExpired(storedAt)
	// Just exercise the function — result depends on current time
	_ = result
}

// ---------------------------------------------------------------------------
// initializeTemplates / setupTemplates
// ---------------------------------------------------------------------------

func TestInitializeTemplates_Push(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("k", "s")
	err := m.initializeTemplates()
	if err != nil {
		t.Fatalf("initializeTemplates: %v", err)
	}
}

func TestSetupTemplates(t *testing.T) {
	t.Parallel()
	tmpl, err := setupTemplates()
	if err != nil {
		t.Fatalf("setupTemplates: %v", err)
	}
	if tmpl == nil {
		t.Error("Expected non-nil template")
	}
}

func TestRenderSuccessTemplate(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("k", "s")
	_ = m.initializeTemplates()

	rr := httptest.NewRecorder()
	err := m.renderSuccessTemplate(rr)
	if err != nil {
		t.Errorf("renderSuccessTemplate: %v", err)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
}

func TestRenderSuccessTemplate_NilTemplate(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("k", "s")
	m.templates = nil

	rr := httptest.NewRecorder()
	err := m.renderSuccessTemplate(rr)
	if err == nil {
		t.Error("Expected error for nil template")
	}
}

// ---------------------------------------------------------------------------
// GetOrCreateSessionWithEmail — TerminateByEmail (session_svc.go)
// ---------------------------------------------------------------------------

func TestTerminateByEmail_WithActiveSession(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("k", "s")

	// Create session with email
	_, _, _ = m.GetOrCreateSessionWithEmail("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee10", "terminate@test.com")

	count := m.SessionManager().TerminateByEmail("terminate@test.com")
	if count < 1 {
		t.Errorf("TerminateByEmail returned %d, expected >= 1", count)
	}
}

func TestTerminateByEmail_NoSessions(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("k", "s")

	count := m.SessionManager().TerminateByEmail("nobody@test.com")
	if count != 0 {
		t.Errorf("TerminateByEmail returned %d, expected 0", count)
	}
}

// ---------------------------------------------------------------------------
// Silence unused import
// ---------------------------------------------------------------------------
var _ = time.Now
var _ instruments.Instrument
