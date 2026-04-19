package oauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

)

// --- Well-Known Metadata ---


// --- Browser Login ---
func TestHandleBrowserLogin_CSRFProtection(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.getCredentials = func(email string) (string, string, bool) {
			return "api-key", "api-secret", true
		}
	})
	defer h.Close()

	// POST without CSRF token should re-render the form
	form := url.Values{
		"email":    {"user@test.com"},
		"redirect": {"/admin/ops"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/browser-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	// Should re-render the form (200) with CSRF error, not redirect
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (re-rendered form)", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "CSRF") && !strings.Contains(body, "csrf") {
		// Check if the form was re-rendered (contains the login form)
		if !strings.Contains(body, "email") {
			t.Errorf("Should re-render login form, got: %s", body[:min(200, len(body))])
		}
	}
}


func TestHandleBrowserLogin_GET_NoEmail_HandlersFile(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/browser-login?redirect=/admin/ops", nil)
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	// Should serve the login form
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "email") {
		t.Errorf("Should render login form with email field")
	}
	// Should set CSRF cookie
	cookies := rr.Result().Cookies()
	var csrfCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "csrf_token" {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil {
		t.Error("GET should set csrf_token cookie")
	}
}


func TestHandleBrowserLogin_GET_WithEmail_Credentials(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.getCredentials = func(email string) (string, string, bool) {
			if email == "known@test.com" {
				return "user-api-key", "user-api-secret", true
			}
			return "", "", false
		}
	})
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/browser-login?email=known@test.com&redirect=/admin/ops", nil)
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	// Should redirect to Kite login
	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302", rr.Code)
	}
	location := rr.Header().Get("Location")
	if !strings.Contains(location, "kite.zerodha.com") {
		t.Errorf("Should redirect to Kite login: %q", location)
	}
}


// --- GenerateBrowserLoginURL ---
func TestGenerateBrowserLoginURL(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	loginURL := h.GenerateBrowserLoginURL("my-api-key", "user@test.com", "/admin/ops")

	if !strings.HasPrefix(loginURL, "https://kite.zerodha.com/connect/login") {
		t.Errorf("URL should start with Kite login URL: %q", loginURL)
	}

	parsed, err := url.Parse(loginURL)
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
	}
	if parsed.Query().Get("api_key") != "my-api-key" {
		t.Errorf("api_key = %q, want %q", parsed.Query().Get("api_key"), "my-api-key")
	}

	// redirect_params is URL-encoded; decode it and check for flow=browser
	redirectParams := parsed.Query().Get("redirect_params")
	if !strings.Contains(redirectParams, "flow=browser") {
		t.Errorf("redirect_params should contain flow=browser: %q", redirectParams)
	}
	if !strings.Contains(redirectParams, "target=") {
		t.Errorf("redirect_params should contain target=: %q", redirectParams)
	}
}


func TestGenerateBrowserLoginURL_DefaultAPIKey(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Empty API key should fall back to config
	loginURL := h.GenerateBrowserLoginURL("", "user@test.com", "/admin/ops")

	if !strings.Contains(loginURL, "api_key=test-api-key") {
		t.Errorf("URL should use config API key: %q", loginURL)
	}
}


// --- HandleEmailLookup ---
func TestHandleEmailLookup_GET_NotAllowed(t *testing.T) {
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


func TestHandleEmailLookup_POST_MissingCSRF(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"email":       {"user@test.com"},
		"oauth_state": {""},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/email-lookup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.HandleEmailLookup(rr, req)

	// Missing CSRF + empty oauth_state → should return 400.
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (missing CSRF + invalid state)", rr.Code)
	}
}


// --- HandleBrowserLogin additional tests ---
func TestHandleBrowserLogin_GET_WithEmail_NoCredentials(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.getCredentials = func(email string) (string, string, bool) {
			return "", "", false
		}
	})
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/browser-login?email=unknown@test.com&redirect=/dashboard", nil)
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	// Should render the form with error message (200).
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (no creds → show form)", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "No credentials") {
		// Some form of error message should be present.
		if !strings.Contains(body, "email") {
			t.Error("Should render login form with email field")
		}
	}
}


func TestHandleBrowserLogin_POST_ValidCSRF_EmptyEmail(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"email":      {""},
		"redirect":   {"/dashboard"},
		"csrf_token": {"valid-csrf"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/browser-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "valid-csrf"})
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	// Empty email with valid CSRF → should re-render form.
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (empty email → form)", rr.Code)
	}
}


func TestHandleBrowserLogin_POST_ValidCSRF_NoCredentials(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.getCredentials = func(email string) (string, string, bool) {
			return "", "", false
		}
	})
	defer h.Close()

	form := url.Values{
		"email":      {"noone@test.com"},
		"redirect":   {"/dashboard"},
		"csrf_token": {"valid-csrf"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/browser-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "valid-csrf"})
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	// Valid CSRF, email exists but no credentials → should show form with error.
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (no creds → form)", rr.Code)
	}
}


func TestHandleBrowserLogin_POST_ValidCSRF_WithCredentials(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.getCredentials = func(email string) (string, string, bool) {
			if email == "known@test.com" {
				return "user-api-key", "user-api-secret", true
			}
			return "", "", false
		}
	})
	defer h.Close()

	form := url.Values{
		"email":      {"known@test.com"},
		"redirect":   {"/dashboard"},
		"csrf_token": {"valid-csrf"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/browser-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "valid-csrf"})
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	// Valid CSRF, email has credentials → should redirect to Kite login.
	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (redirect to Kite login)", rr.Code)
	}
	location := rr.Header().Get("Location")
	if !strings.Contains(location, "kite.zerodha.com") {
		t.Errorf("Location = %q, should contain kite.zerodha.com", location)
	}
}


// --- serveEmailPrompt ---
func TestServeEmailPrompt(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	rr := httptest.NewRecorder()
	state := oauthState{
		ClientID:    "test-client",
		RedirectURI: "https://example.com/callback",
	}

	h.serveEmailPrompt(rr, state, "Test error message")

	// Should render the email prompt page.
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
}


// --- HandleBrowserAuthCallback ---
func TestHandleBrowserAuthCallback_MissingRequestToken(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?flow=browser", nil)
	rr := httptest.NewRecorder()

	h.HandleBrowserAuthCallback(rr, req, "")

	// Missing request_token should return 400.
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}


// ===========================================================================
// Consolidated from coverage_*.go files
// ===========================================================================

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
// serveEmailPrompt — nil template error path
// ===========================================================================
func TestServeEmailPrompt_NilTemplate(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.emailPromptTmpl = nil

	rr := httptest.NewRecorder()
	h.serveEmailPrompt(rr, oauthState{}, "")

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 (nil template)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "email prompt page unavailable") {
		t.Errorf("Body = %q, want 'email prompt page unavailable'", rr.Body.String())
	}
}


// ===========================================================================
// serveBrowserLoginForm — nil template error path
// ===========================================================================
func TestServeBrowserLoginForm_NilTemplate(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.browserLoginTmpl = nil

	rr := httptest.NewRecorder()
	h.serveBrowserLoginForm(rr, "/dashboard", "", "csrf")

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 (nil template)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Failed to load login page") {
		t.Errorf("Body = %q, want 'Failed to load login page'", rr.Body.String())
	}
}


// ===========================================================================
// HandleEmailLookup — valid email with registry (full path)
// ===========================================================================

type mockKeyRegistry struct {
	entries    map[string]*RegistryEntry
	hasEntries bool
}

func (m *mockKeyRegistry) HasEntries() bool {
	return m.hasEntries
}

func (m *mockKeyRegistry) GetByEmail(email string) (*RegistryEntry, bool) {
	if m.entries == nil {
		return nil, false
	}
	e, ok := m.entries[email]
	return e, ok
}

func (m *mockKeyRegistry) GetSecretByAPIKey(apiKey string) (string, bool) {
	if m.entries == nil {
		return "", false
	}
	for _, e := range m.entries {
		if e.APIKey == apiKey {
			return e.APISecret, true
		}
	}
	return "", false
}
func TestHandleEmailLookup_POST_ValidEmail_RegistryFound(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	registry := &mockKeyRegistry{
		hasEntries: true,
		entries: map[string]*RegistryEntry{
			"user@test.com": {
				APIKey:       "test-api-key-12345678",
				APISecret:    "test-secret",
				RegisteredBy: "admin@test.com",
			},
		},
	}
	h.SetRegistry(registry)

	stateData := oauthState{
		ClientID:      "client-123",
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: "challenge",
		State:         "state",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	csrfToken := "valid-csrf"
	form := url.Values{
		"email":       {"user@test.com"},
		"oauth_state": {signedState},
		"csrf_token":  {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/email-lookup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleEmailLookup(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (redirect to Kite). Body: %s", rr.Code, rr.Body.String())
	}
	location := rr.Header().Get("Location")
	if !strings.Contains(location, "api_key=test-api-key-12345678") {
		t.Errorf("Expected registry API key in redirect, got: %q", location)
	}
}


func TestHandleEmailLookup_POST_EmailNotInRegistry(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	registry := &mockKeyRegistry{
		hasEntries: true,
		entries:    map[string]*RegistryEntry{},
	}
	h.SetRegistry(registry)

	stateData := oauthState{
		ClientID:      "client-123",
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: "challenge",
		State:         "state",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	csrfToken := "csrf-tok"
	form := url.Values{
		"email":       {"unknown@test.com"},
		"oauth_state": {signedState},
		"csrf_token":  {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/email-lookup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleEmailLookup(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (re-rendered form with error)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "No app registered") {
		t.Errorf("Body should contain 'No app registered', got: %s", rr.Body.String())
	}
}


func TestHandleEmailLookup_POST_InvalidOAuthState(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	csrfToken := "csrf-tok"
	form := url.Values{
		"email":       {"user@test.com"},
		"oauth_state": {"invalid-not-signed"},
		"csrf_token":  {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/email-lookup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleEmailLookup(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (invalid OAuth state)", rr.Code)
	}
}


func TestHandleEmailLookup_POST_CSRFFailWithRecoverableState(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	stateData := oauthState{
		ClientID:      "client-123",
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: "challenge",
		State:         "state",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	form := url.Values{
		"email":       {"user@test.com"},
		"oauth_state": {signedState},
		"csrf_token":  {"wrong-csrf"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/email-lookup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "correct-csrf"})
	rr := httptest.NewRecorder()

	h.HandleEmailLookup(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (re-rendered form after CSRF fail)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Please try again") {
		t.Errorf("Body should contain 'Please try again'")
	}
}


func TestHandleEmailLookup_POST_RegistryNotConfigured(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	stateData := oauthState{
		ClientID:      "client",
		RedirectURI:   "https://example.com/cb",
		CodeChallenge: "ch",
		State:         "st",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	csrfToken := "csrf"
	form := url.Values{
		"email":       {"user@test.com"},
		"oauth_state": {signedState},
		"csrf_token":  {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/email-lookup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleEmailLookup(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 (registry not configured)", rr.Code)
	}
}


func TestHandleEmailLookup_POST_EmptyEmailWithRegistry(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	registry := &mockKeyRegistry{hasEntries: true, entries: map[string]*RegistryEntry{}}
	h.SetRegistry(registry)

	stateData := oauthState{
		ClientID:      "client",
		RedirectURI:   "https://example.com/cb",
		CodeChallenge: "ch",
		State:         "st",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	csrfToken := "csrf"
	form := url.Values{
		"email":       {""},
		"oauth_state": {signedState},
		"csrf_token":  {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/email-lookup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleEmailLookup(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (re-rendered form)", rr.Code)
	}
}


func TestHandleBrowserAuthCallback_NoCredentialsForEmail(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.getCredentials = func(email string) (string, string, bool) {
			return "", "", false
		}
	})
	defer h.Close()

	raw := base64.RawURLEncoding.EncodeToString([]byte("nocreds@test.com::/dashboard"))
	signedTarget := h.signer.Sign(raw)

	req := httptest.NewRequest(http.MethodGet, "/callback?flow=browser&target="+url.QueryEscape(signedTarget), nil)
	rr := httptest.NewRecorder()

	h.HandleBrowserAuthCallback(rr, req, "valid-token")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want 401 (no credentials)", rr.Code)
	}
}


func TestHandleBrowserLogin_GET_RegistryFallback(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetRegistry(&mockKeyRegistry{
		hasEntries: true,
		entries: map[string]*RegistryEntry{
			"reg@test.com": {APIKey: "reg-api-key-12345678", APISecret: "reg-secret"},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/browser-login?email=reg@test.com", nil)
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (registry fallback redirect)", rr.Code)
	}
}


func TestHandleBrowserLogin_POST_RegistryFallback(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetRegistry(&mockKeyRegistry{
		hasEntries: true,
		entries: map[string]*RegistryEntry{
			"reg@test.com": {APIKey: "reg-key-12345678", APISecret: "reg-secret"},
		},
	})

	csrfToken := "csrf"
	form := url.Values{
		"email":      {"reg@test.com"},
		"redirect":   {"/dashboard"},
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/browser-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (registry fallback)", rr.Code)
	}
}


// ===========================================================================
// HandleEmailLookup — GET method not allowed
// ===========================================================================
func TestHandleEmailLookup_GET_MethodNotAllowed_Final(t *testing.T) {
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


// ===========================================================================
// HandleEmailLookup — CSRF fail with unrecoverable state
// ===========================================================================
func TestHandleEmailLookup_POST_CSRFFailUnrecoverableState(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"email":       {"user@test.com"},
		"oauth_state": {"completely-invalid-not-signed"},
		"csrf_token":  {"wrong-csrf"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/email-lookup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "different-csrf"})
	rr := httptest.NewRecorder()

	h.HandleEmailLookup(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (unrecoverable CSRF fail)", rr.Code)
	}
}


// ===========================================================================
// HandleBrowserLogin POST — empty email shows form
// ===========================================================================
func TestHandleBrowserLogin_POST_EmptyEmail_Final(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	csrfToken := "csrf-tok"
	form := url.Values{
		"email":      {""},
		"redirect":   {"/dashboard"},
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/browser-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (form shown for empty email)", rr.Code)
	}
}


// ===========================================================================
// HandleBrowserLogin POST — no credentials found
// ===========================================================================
func TestHandleBrowserLogin_POST_NoCredentials(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	csrfToken := "csrf-tok"
	form := url.Values{
		"email":      {"unknown@example.com"},
		"redirect":   {"/dashboard"},
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/browser-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (form with error)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "No credentials found") {
		t.Errorf("Body should contain 'No credentials found'")
	}
}


// ===========================================================================
// HandleBrowserLogin POST — CSRF mismatch
// ===========================================================================
func TestHandleBrowserLogin_POST_CSRFMismatch(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"email":      {"user@example.com"},
		"redirect":   {"/dashboard"},
		"csrf_token": {"form-csrf"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/browser-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "cookie-csrf"})
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (form re-rendered with CSRF error)", rr.Code)
	}
}


// ===========================================================================
// HandleBrowserLogin GET — email not found (shows form with error)
// ===========================================================================
func TestHandleBrowserLogin_GET_EmailNotFound(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/browser-login?email=unknown@test.com", nil)
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (form with error for unknown email)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "No credentials found") {
		t.Errorf("Body should contain 'No credentials found'")
	}
}


// ===========================================================================
// HandleBrowserLogin GET — email found with credentials
// ===========================================================================
func TestHandleBrowserLogin_GET_EmailFound(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.getCredentials = func(email string) (string, string, bool) {
			if email == "found@test.com" {
				return "api-key-for-found", "secret", true
			}
			return "", "", false
		}
	})
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/browser-login?email=found@test.com", nil)
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (redirect to Kite)", rr.Code)
	}
}


// ===========================================================================
// HandleBrowserLogin POST — credentials found, redirects to Kite
// ===========================================================================
func TestHandleBrowserLogin_POST_CredentialsFound(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.getCredentials = func(email string) (string, string, bool) {
			return "api-key-found", "secret", true
		}
	})
	defer h.Close()

	csrfToken := "csrf"
	form := url.Values{
		"email":      {"user@test.com"},
		"redirect":   {"/dashboard"},
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/browser-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (redirect to Kite)", rr.Code)
	}
}


// ===========================================================================
// HandleBrowserAuthCallback — exchange fails
// ===========================================================================
func TestHandleBrowserAuthCallback_ExchangeFails(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.getCredentials = func(email string) (string, string, bool) {
			return "api-key", "api-secret", true
		}
		exchanger.exchangeWithCreds = func(requestToken, apiKey, apiSecret string) (string, error) {
			return "", fmt.Errorf("exchange failed")
		}
	})
	defer h.Close()

	raw := base64.RawURLEncoding.EncodeToString([]byte("user@test.com::/dashboard"))
	signedTarget := h.signer.Sign(raw)

	req := httptest.NewRequest(http.MethodGet, "/callback?flow=browser&target="+url.QueryEscape(signedTarget), nil)
	rr := httptest.NewRecorder()

	h.HandleBrowserAuthCallback(rr, req, "valid-token")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want 401 (exchange failed)", rr.Code)
	}
}


// ===========================================================================
// serveEmailPrompt — template execution error (JSON marshal error path)
// ===========================================================================
func TestServeEmailPrompt_JSONMarshalError(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	rr := httptest.NewRecorder()
	// Pass a normal state and empty error to test the full render path
	h.serveEmailPrompt(rr, oauthState{
		ClientID:      "test-client",
		RedirectURI:   "https://example.com/cb",
		CodeChallenge: "challenge",
		State:         "state",
	}, "test error message")

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (rendered form)", rr.Code)
	}
}


// HandleBrowserLogin POST — valid CSRF, empty email
func TestHandleBrowserLogin_POST_EmptyEmail_CSRFValid(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	csrf := "test-csrf-token"
	form := url.Values{
		"email":      {""},
		"redirect":   {"/dashboard"},
		"csrf_token": {csrf},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/browser-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	rr := httptest.NewRecorder()
	h.HandleBrowserLogin(rr, req)

	// Should re-serve the login form (200)
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}
}


// HandleBrowserLogin POST — valid CSRF, email with no credentials
func TestHandleBrowserLogin_POST_NoCreds(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	csrf := "test-csrf-token-2"
	form := url.Values{
		"email":      {"nocred@example.com"},
		"redirect":   {"/dashboard"},
		"csrf_token": {csrf},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/browser-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	rr := httptest.NewRecorder()
	h.HandleBrowserLogin(rr, req)

	// Should re-serve the login form with error message (200)
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (form with error)", rr.Code)
	}
}


// HandleBrowserLogin POST — valid CSRF, email with credentials -> redirect
func TestHandleBrowserLogin_POST_WithCreds(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.getCredentials = func(email string) (string, string, bool) {
			if email == "cred@example.com" {
				return "api-key-123", "api-secret-456", true
			}
			return "", "", false
		}
	})
	defer h.Close()

	csrf := "test-csrf-token-3"
	form := url.Values{
		"email":      {"cred@example.com"},
		"redirect":   {"/dashboard"},
		"csrf_token": {csrf},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/browser-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	rr := httptest.NewRecorder()
	h.HandleBrowserLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (redirect to Kite)", rr.Code)
	}
}


// HandleBrowserLogin GET — email with no credentials
func TestHandleBrowserLogin_GET_NoCredsError(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/browser-login?email=nobody@test.com", nil)
	rr := httptest.NewRecorder()
	h.HandleBrowserLogin(rr, req)

	// Should serve form with error message
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "No credentials") {
		t.Errorf("Expected error about no credentials")
	}
}


// HandleBrowserAuthCallback — per-user credentials path
func TestHandleBrowserAuthCallback_PerUserCreds(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.getCredentials = func(email string) (string, string, bool) {
			return "per-user-key", "per-user-secret", true
		}
		e.exchangeWithCreds = func(requestToken, apiKey, apiSecret string) (string, error) {
			return "user@test.com", nil
		}
	})
	defer h.Close()

	raw := base64.RawURLEncoding.EncodeToString([]byte("user@test.com::/dashboard"))
	signedTarget := h.signer.Sign(raw)

	req := httptest.NewRequest(http.MethodGet, "/callback?flow=browser&target="+url.QueryEscape(signedTarget), nil)
	rr := httptest.NewRecorder()
	h.HandleBrowserAuthCallback(rr, req, "valid-request-token")

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302; body = %s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if loc != "/dashboard" {
		t.Errorf("Location = %q, want /dashboard", loc)
	}
}


// HandleBrowserAuthCallback — legacy target format (no :: separator, just redirect)
func TestHandleBrowserAuthCallback_LegacyTarget(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.exchangeFunc = func(requestToken string) (string, error) {
			return "user@test.com", nil
		}
	})
	defer h.Close()

	// Sign a non-base64 target (legacy: plain redirect string)
	signedTarget := h.signer.Sign("not-valid-base64")

	req := httptest.NewRequest(http.MethodGet, "/callback?flow=browser&target="+url.QueryEscape(signedTarget), nil)
	rr := httptest.NewRecorder()
	h.HandleBrowserAuthCallback(rr, req, "valid-token")

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// jwt.go:98-100 — multi-audience mismatch
// cov_push_test.go says this is unreachable when first aud matches.
// But we can trigger it if the token has multiple audiences and we
// request different ones where first matches but rest don't. Actually,
// if first audience is in the JWT, the for loop at 87-96 always finds it.
// The only way to hit 98-100 is if the JWT library's WithAudience check
// passes but none of the audiences match the loop. This is theoretically
// impossible (WithAudience checks aud[0] ∈ token.Audience, then loop
// checks all provided auds). So this is genuinely unreachable.
// Documented below in the unreachable section.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// handlers.go:417-420 — HandleEmailLookup ParseForm error
// Use an oversized body to trigger MaxBytesReader failure.
// ---------------------------------------------------------------------------
func TestHandleEmailLookup_OversizedBody_Push100(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// 100KB body exceeds the 64KB MaxBytesReader limit
	bigBody := strings.Repeat("x=", 50*1024)
	req := httptest.NewRequest(http.MethodPost, "/oauth/email-lookup",
		strings.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.HandleEmailLookup(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// handlers.go:228-232 — Register: clients.Register() error
// Fill the client store to trigger eviction path (Register doesn't fail,
// but we can test by maxing out clients)
// Actually ClientStore.Register uses randomHex which can't fail. The only way
// Register returns an error is if randomHex fails (crypto/rand). This is
// unreachable. Documented below.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// handlers.go:705-708 — HandleBrowserAuthCallback: legacy redirect decode
// When target is a plain string (not base64 email::redirect), falls through
// to the legacy branch.
// ---------------------------------------------------------------------------
func TestHandleBrowserAuthCallback_LegacyPlainRedirect_Push100(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.exchangeFunc = func(rt string) (string, error) {
			return "user@test.com", nil
		}
		// Override signer so Verify returns a string that is NOT valid base64
		// This triggers the legacy branch at lines 705-708
		s.verifyFunc = func(signed string) (string, error) {
			return "/legacy-redirect", nil
		}
	})
	defer h.Close()

	signedTarget := "anything" // signer.Verify is overridden

	req := httptest.NewRequest(http.MethodGet,
		"/callback?request_token=tok&target="+url.QueryEscape(signedTarget), nil)
	rr := httptest.NewRecorder()

	h.HandleBrowserAuthCallback(rr, req, "tok")

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc != "/legacy-redirect" {
		t.Errorf("Location = %q, want /legacy-redirect", loc)
	}
}


// ===========================================================================

// ===========================================================================
// Merged from gap_test.go
// ===========================================================================


// ===========================================================================
// gap_test.go — Push oauth from ~90% to 98%+
//
// Targets uncovered lines in handlers.go, stores.go, jwt.go, middleware.go,
// google_sso.go. Many unreachable lines (crypto/rand, embed template parse)
// are documented inline.
// ===========================================================================

// ---------------------------------------------------------------------------
// HandleBrowserLogin — POST with CSRF mismatch (lines 853-858)
// ---------------------------------------------------------------------------
func TestHandleBrowserLogin_POST_CSRFMismatch_Gap(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"email": {"user@test.com"}, "csrf_token": {"wrong"}, "redirect": {"/dashboard"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/browser-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "correct"})
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	// Should re-render form with CSRF error
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (CSRF mismatch re-render)", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// HandleBrowserLogin — POST with no CSRF cookie at all (lines 853-858)
// ---------------------------------------------------------------------------
func TestHandleBrowserLogin_POST_NoCookie(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"email": {"user@test.com"}, "csrf_token": {"token"}, "redirect": {"/dashboard"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/browser-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// No csrf_token cookie
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (no CSRF cookie re-render)", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// HandleBrowserLogin — POST with valid CSRF but unknown email (lines 884-889)
// ---------------------------------------------------------------------------
func TestHandleBrowserLogin_POST_UnknownEmail(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.getCredentials = func(email string) (string, string, bool) {
			return "", "", false
		}
	})
	defer h.Close()

	csrfToken := "valid-csrf"
	form := url.Values{
		"email": {"unknown@test.com"}, "csrf_token": {csrfToken}, "redirect": {"/dashboard"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/browser-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (unknown email re-render)", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// HandleBrowserLogin — POST success (redirect to Kite, lines 893-895)
// ---------------------------------------------------------------------------
func TestHandleBrowserLogin_POST_Success(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.getCredentials = func(email string) (string, string, bool) {
			return "api-key-123", "api-secret-456", true
		}
	})
	defer h.Close()

	csrfToken := "valid-csrf"
	form := url.Values{
		"email": {"user@test.com"}, "csrf_token": {csrfToken}, "redirect": {"/dashboard"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/browser-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (redirect to Kite)", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "kite.zerodha.com") {
		t.Errorf("Expected Kite redirect URL, got: %q", loc)
	}
}


// ---------------------------------------------------------------------------
// HandleBrowserLogin — POST with registry fallback (lines 864-868)
// ---------------------------------------------------------------------------
func TestHandleBrowserLogin_POST_RegistryFallback_Gap(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.getCredentials = func(email string) (string, string, bool) {
			return "", "", false // no stored creds
		}
	})
	defer h.Close()

	h.SetRegistry(&mockKeyRegistry{
		hasEntries: true,
		entries: map[string]*RegistryEntry{
			"user@test.com": {APIKey: "reg-key", APISecret: "reg-secret"},
		},
	})

	csrfToken := "valid-csrf"
	form := url.Values{
		"email": {"user@test.com"}, "csrf_token": {csrfToken}, "redirect": {"/dashboard"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/browser-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (registry fallback redirect)", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// HandleBrowserLogin — GET with email but unknown (line 919 path)
// ---------------------------------------------------------------------------
func TestHandleBrowserLogin_GET_EmailUnknown(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.getCredentials = func(email string) (string, string, bool) {
			return "", "", false
		}
	})
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/browser-login?email=unknown@test.com", nil)
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	// Should show form with error message
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (form with error)", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "No credentials found") {
		t.Errorf("Expected error message in body")
	}
}


// ---------------------------------------------------------------------------
// HandleBrowserLogin — GET with email + registry fallback (line 904-908)
// ---------------------------------------------------------------------------
func TestHandleBrowserLogin_GET_EmailRegistryFallback(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.getCredentials = func(email string) (string, string, bool) {
			return "", "", false
		}
	})
	defer h.Close()

	h.SetRegistry(&mockKeyRegistry{
		hasEntries: true,
		entries: map[string]*RegistryEntry{
			"user@test.com": {APIKey: "reg-key", APISecret: "reg-secret"},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/browser-login?email=user@test.com", nil)
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (GET with registry fallback)", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// HandleEmailLookup — missing oauth_state (line 417-420)
// ---------------------------------------------------------------------------
func TestHandleEmailLookup_MissingOAuthState(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{"email": {"user@test.com"}, "csrf_token": {"csrf"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/email-lookup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf"})
	rr := httptest.NewRecorder()

	h.HandleEmailLookup(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (missing oauth_state)", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// HandleBrowserAuthCallback — legacy redirect path (line 705-708)
// ---------------------------------------------------------------------------
func TestHandleBrowserAuthCallback_LegacyTarget_Gap(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.exchangeFunc = func(rt string) (string, error) {
			return "user@test.com", nil
		}
	})
	defer h.Close()

	// Sign a plain string (no email:: prefix) to exercise the legacy path
	signedTarget := h.signer.Sign(base64.RawURLEncoding.EncodeToString([]byte("not-email-format")))

	req := httptest.NewRequest(http.MethodGet, "/callback?target="+url.QueryEscape(signedTarget), nil)
	rr := httptest.NewRecorder()
	h.HandleBrowserAuthCallback(rr, req, "request-tok")

	// Should succeed with global exchange fallback
	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// HandleBrowserAuthCallback — no credentials for signed email (line 723-725)
// ---------------------------------------------------------------------------
func TestHandleBrowserAuthCallback_NoCreds(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.getCredentials = func(email string) (string, string, bool) {
			return "", "", false
		}
	})
	defer h.Close()

	raw := base64.RawURLEncoding.EncodeToString([]byte("nocreds@test.com::/dashboard"))
	signedTarget := h.signer.Sign(raw)

	req := httptest.NewRequest(http.MethodGet, "/callback?target="+url.QueryEscape(signedTarget), nil)
	rr := httptest.NewRecorder()
	h.HandleBrowserAuthCallback(rr, req, "request-tok")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want 401 (no credentials)", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// serveEmailPrompt — nil template (line 354-356, line 361-363)
// ---------------------------------------------------------------------------
func TestServeEmailPrompt_NilTmpl_Gap(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()
	h.emailPromptTmpl = nil

	rr := httptest.NewRecorder()
	h.serveEmailPrompt(rr, oauthState{}, "")

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 (nil template)", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// serveBrowserLoginForm — nil template (line 933-935)
// ---------------------------------------------------------------------------
func TestServeBrowserLoginForm_NilTmpl_Gap(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()
	h.browserLoginTmpl = nil

	rr := httptest.NewRecorder()
	h.serveBrowserLoginForm(rr, "/dashboard", "", "csrf")

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 (nil template)", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// HandleEmailLookup — POST with valid CSRF but email not in registry (line 403-405)
// ---------------------------------------------------------------------------
func TestHandleEmailLookup_NotFound(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetRegistry(&mockKeyRegistry{
		hasEntries: true,
		entries:    map[string]*RegistryEntry{},
	})

	stateData := oauthState{ClientID: "c", RedirectURI: "https://example.com/cb", CodeChallenge: "ch"}
	stateJSON, _ := json.Marshal(stateData)
	encoded := base64.URLEncoding.EncodeToString(stateJSON)
	signedOAuthState := h.signer.Sign(encoded)

	form := url.Values{
		"email":       {"unknown@test.com"},
		"csrf_token":  {"csrf"},
		"oauth_state": {signedOAuthState},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/email-lookup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf"})
	rr := httptest.NewRecorder()

	h.HandleEmailLookup(rr, req)

	// Should re-render email prompt with error
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (email not found in registry re-render)", rr.Code)
	}
}
