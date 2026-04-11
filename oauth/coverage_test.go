package oauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ===========================================================================
// HandleEmailLookup — various paths
// ===========================================================================

func TestHandleEmailLookup_GET_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/oauth/email-lookup", nil)
	rr := httptest.NewRecorder()

	h.HandleEmailLookup(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %d, want 405", rr.Code)
	}
}

func TestHandleEmailLookup_POST_NoCSRF(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"email":       {"user@test.com"},
		"oauth_state": {"some-state"},
		"csrf_token":  {"wrong"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/email-lookup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// No CSRF cookie set — will fail CSRF verification
	rr := httptest.NewRecorder()

	h.HandleEmailLookup(rr, req)

	// Should return 400 because oauth_state recovery will fail (no valid signed state)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}

func TestHandleEmailLookup_POST_EmptyEmail(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Set matching CSRF tokens
	csrfToken := "test-csrf-token"
	form := url.Values{
		"email":       {""},
		"oauth_state": {h.signer.Sign("some-state")},
		"csrf_token":  {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/email-lookup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleEmailLookup(rr, req)

	// Should return 400 or re-render with error since the signed state
	// can't be recovered as valid base64-encoded JSON
	if rr.Code != http.StatusBadRequest && rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 400 or 200 (re-rendered form)", rr.Code)
	}
}

func TestHandleEmailLookup_POST_NoRegistry(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()
	// registry is nil by default in test handler

	csrfToken := "csrf123"
	form := url.Values{
		"email":       {"user@test.com"},
		"oauth_state": {h.signer.Sign("some-state")},
		"csrf_token":  {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/email-lookup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleEmailLookup(rr, req)

	// The signed state won't decode to valid oauthState JSON, so should fail
	// with either "key registry not configured" or bad state
	if rr.Code == http.StatusFound {
		t.Error("Should not redirect when registry is not configured")
	}
}

// ===========================================================================
// JWT edge cases
// ===========================================================================

func TestJWT_ExpiredToken(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Generate a token with 0 expiry (immediately expired)
	token, err := h.jwt.GenerateTokenWithExpiry("user@test.com", "mcp", -1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateTokenWithExpiry error: %v", err)
	}

	_, err = h.jwt.ValidateToken(token)
	if err == nil {
		t.Error("Expected error for expired token")
	}
}

func TestJWT_MalformedToken(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	_, err := h.jwt.ValidateToken("not.a.valid.jwt")
	if err == nil {
		t.Error("Expected error for malformed token")
	}
}

func TestJWT_WrongSecret(t *testing.T) {
	t.Parallel()
	jwt1 := NewJWTManager("secret-one", 4*time.Hour)
	jwt2 := NewJWTManager("secret-two", 4*time.Hour)

	token, err := jwt1.GenerateToken("user@test.com", "mcp")
	if err != nil {
		t.Fatalf("GenerateToken error: %v", err)
	}

	_, err = jwt2.ValidateToken(token)
	if err == nil {
		t.Error("Expected error when validating with different secret")
	}
}

func TestJWT_GenerateTokenWithExpiry(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Long expiry token
	token, err := h.jwt.GenerateTokenWithExpiry("user@test.com", "dashboard", 7*24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateTokenWithExpiry error: %v", err)
	}

	claims, err := h.jwt.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken error: %v", err)
	}
	if claims.Subject != "user@test.com" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "user@test.com")
	}
}

// ===========================================================================
// SetAuthCookie
// ===========================================================================

func TestRequireAuthBrowser_ExpiredCookie(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	token, err := h.jwt.GenerateTokenWithExpiry("user@test.com", "dashboard", -1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken error: %v", err)
	}

	innerCalled := false
	handler := h.RequireAuthBrowser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerCalled = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "kitemcp_auth", Value: token})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if innerCalled {
		t.Error("Inner handler should not be called with expired cookie")
	}
	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302", rr.Code)
	}
}

// ===========================================================================
// AuthCodeStore — edge cases
// ===========================================================================

func TestAuthCodeStore_Close(t *testing.T) {
	t.Parallel()
	store := NewAuthCodeStore()
	// Close should not panic
	store.Close()
}

func TestAuthCodeStore_ConsumeAfterExpiry(t *testing.T) {
	t.Parallel()
	store := NewAuthCodeStore()

	code, err := store.Generate(&AuthCodeEntry{
		ClientID:      "client1",
		CodeChallenge: "challenge",
		RedirectURI:   "https://example.com/cb",
		Email:         "user@test.com",
	})
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	// Manually expire the code
	store.mu.Lock()
	if entry, ok := store.entries[code]; ok {
		entry.ExpiresAt = time.Now().Add(-1 * time.Hour)
	}
	store.mu.Unlock()

	_, ok := store.Consume(code)
	if ok {
		t.Error("Expected false for expired code")
	}
}

func TestAuthCodeStore_DoubleConsume(t *testing.T) {
	t.Parallel()
	store := NewAuthCodeStore()

	code, err := store.Generate(&AuthCodeEntry{
		ClientID:      "client1",
		CodeChallenge: "challenge",
		RedirectURI:   "https://example.com/cb",
		Email:         "user@test.com",
	})
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	// First consume should succeed
	_, ok := store.Consume(code)
	if !ok {
		t.Fatal("First Consume should succeed")
	}

	// Second consume should fail (already consumed)
	_, ok = store.Consume(code)
	if ok {
		t.Error("Expected false for double consume")
	}
}

// ===========================================================================
// ClientStore — edge cases
// ===========================================================================

func TestClientStore_GetNonExistent(t *testing.T) {
	t.Parallel()
	store := NewClientStore()
	_, ok := store.Get("nonexistent")
	if ok {
		t.Error("Expected false for nonexistent client")
	}
}

func TestClientStore_IsKiteClient(t *testing.T) {
	t.Parallel()
	store := NewClientStore()

	// Register a normal client
	clientID, _, err := store.Register([]string{"https://example.com/cb"}, "test")
	if err != nil {
		t.Fatalf("Register error: %v", err)
	}
	if store.IsKiteClient(clientID) {
		t.Error("Normally registered client should not be a Kite client")
	}

	// Kite clients are registered via auto-registration during authorize
	// with the isKite flag set
}

// ===========================================================================
// ContextWithEmail / EmailFromContext
// ===========================================================================

func TestEmailFromContext_NoEmail(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	email := EmailFromContext(req.Context())
	if email != "" {
		t.Errorf("EmailFromContext = %q, want empty string", email)
	}
}

// ===========================================================================
// GoogleSSOEnabled / SetGoogleSSO / SetUserStore
// ===========================================================================

func TestGoogleSSO_NotEnabled(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	if h.GoogleSSOEnabled() {
		t.Error("GoogleSSO should not be enabled by default in tests")
	}
}

func TestSetUserStore_NilSafe(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Should not panic
	h.SetUserStore(nil)
}

func TestSetGoogleSSO_NilSafe(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Should not panic
	h.SetGoogleSSO(nil)
	if h.GoogleSSOEnabled() {
		t.Error("GoogleSSO should not be enabled after setting nil config")
	}
}

// ===========================================================================
// Handler setters
// ===========================================================================

func TestSetKiteTokenChecker(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Should not panic with nil
	h.SetKiteTokenChecker(nil)
}

func TestSetRegistry(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Should not panic with nil
	h.SetRegistry(nil)
}

func TestGenerateBrowserLoginURL_Coverage(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	loginURL := h.GenerateBrowserLoginURL("test-api-key", "user@test.com", "/dashboard")
	if !strings.Contains(loginURL, "kite.zerodha.com") {
		t.Errorf("Expected login URL to contain kite.zerodha.com, got %q", loginURL)
	}
	if !strings.Contains(loginURL, "api_key=") {
		t.Errorf("Expected login URL to contain api_key param, got %q", loginURL)
	}
}

// ===========================================================================
// HandleBrowserAuthCallback
// ===========================================================================

func TestHandleBrowserAuthCallback_MissingToken(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/callback?flow=browser", nil)
	rr := httptest.NewRecorder()

	h.HandleBrowserAuthCallback(rr, req, "")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}

func TestHandleBrowserAuthCallback_ValidToken_GlobalExchange(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/callback?flow=browser", nil)
	rr := httptest.NewRecorder()

	h.HandleBrowserAuthCallback(rr, req, "valid-request-token")

	// Should redirect after successful exchange
	if rr.Code != http.StatusFound {
		t.Fatalf("Status = %d, want 302. Body: %s", rr.Code, rr.Body.String())
	}
	// Should redirect to /admin/ops (default)
	location := rr.Header().Get("Location")
	if location != "/admin/ops" {
		t.Errorf("Location = %q, want /admin/ops", location)
	}
}

func TestHandleBrowserAuthCallback_WithSignedTarget(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.getCredentials = func(email string) (string, string, bool) {
			return "api-key", "api-secret", true
		}
	})
	defer h.Close()

	// Create a signed target with email::redirect
	raw := "dXNlckBleGFtcGxlLmNvbTo6L2Rhc2hib2FyZA" // base64url of "user@example.com::/dashboard"
	signedTarget := h.signer.Sign(raw)

	req := httptest.NewRequest(http.MethodGet, "/callback?flow=browser&target="+url.QueryEscape(signedTarget), nil)
	rr := httptest.NewRecorder()

	h.HandleBrowserAuthCallback(rr, req, "valid-token")

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302. Body: %s", rr.Code, rr.Body.String())
	}
	location := rr.Header().Get("Location")
	if location != "/dashboard" {
		t.Errorf("Location = %q, want /dashboard", location)
	}
}

func TestHandleBrowserAuthCallback_ExchangeFailure(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.exchangeFunc = func(requestToken string) (string, error) {
			return "", fmt.Errorf("exchange failed")
		}
	})
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/callback?flow=browser", nil)
	rr := httptest.NewRecorder()

	h.HandleBrowserAuthCallback(rr, req, "bad-token")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want 401", rr.Code)
	}
}

func TestHandleBrowserAuthCallback_InvalidTarget(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		signer.verifyFunc = func(signed string) (string, error) {
			return "", fmt.Errorf("bad signature")
		}
	})
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/callback?flow=browser&target=tampered", nil)
	rr := httptest.NewRecorder()

	h.HandleBrowserAuthCallback(rr, req, "valid-token")

	// Should still succeed with default redirect (global exchange)
	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302", rr.Code)
	}
	location := rr.Header().Get("Location")
	if location != "/admin/ops" {
		t.Errorf("Location = %q, want /admin/ops (default)", location)
	}
}

func TestHandleBrowserAuthCallback_OpenRedirectPrevention(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.getCredentials = func(email string) (string, string, bool) {
			return "key", "secret", true
		}
	})
	defer h.Close()

	// Create a signed target that tries to redirect to external URL
	// base64url of "user@example.com:://evil.com"
	raw := "dXNlckBleGFtcGxlLmNvbTo6Ly9ldmlsLmNvbQ"
	signedTarget := h.signer.Sign(raw)

	req := httptest.NewRequest(http.MethodGet, "/callback?flow=browser&target="+url.QueryEscape(signedTarget), nil)
	rr := httptest.NewRecorder()

	h.HandleBrowserAuthCallback(rr, req, "valid-token")

	if rr.Code != http.StatusFound {
		t.Fatalf("Status = %d, want 302. Body: %s", rr.Code, rr.Body.String())
	}
	// Should redirect to safe default, not the evil URL
	location := rr.Header().Get("Location")
	if location != "/admin/ops" {
		t.Errorf("Should redirect to /admin/ops (safe default), got: %q", location)
	}
}

// ===========================================================================
// HandleLoginChoice
// ===========================================================================

func TestHandleLoginChoice_NoExistingCookie(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/login?redirect=/dashboard", nil)
	rr := httptest.NewRecorder()

	h.HandleLoginChoice(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
}

// ===========================================================================
// HandleAdminLogin — GET
// ===========================================================================

func TestHandleAdminLogin_POST_NoCSRF(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"email":    {"admin@test.com"},
		"password": {"test123"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	// Should render the form again (CSRF failure)
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (re-rendered form)", rr.Code)
	}
}

func TestJWTManager_Accessor(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	jwtMgr := h.JWTManager()
	if jwtMgr == nil {
		t.Error("JWTManager() should not return nil")
	}
	if jwtMgr != h.jwt {
		t.Error("JWTManager() should return the same instance")
	}
}
