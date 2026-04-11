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
	"time"
)

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
// HandleAdminLogin — POST with CSRF mismatch (lines 1142-1146)
// ---------------------------------------------------------------------------
func TestHandleAdminLogin_POST_CSRFMismatch_Gap(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"email": {"admin@test.com"}, "password": {"pass"}, "csrf_token": {"wrong"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: "correct"})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (CSRF mismatch re-render)", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// HandleAdminLogin — POST without user store (lines 1152-1154)
// ---------------------------------------------------------------------------
func TestHandleAdminLogin_POST_NoUserStore_Gap(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()
	h.userStore = nil

	csrfToken := "valid-csrf"
	form := url.Values{
		"email": {"admin@test.com"}, "password": {"pass"}, "csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// HandleAdminLogin — POST success (admin login, redirect)
// ---------------------------------------------------------------------------
func TestHandleAdminLogin_POST_Success_Gap(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetUserStore(&mockAdminUserStoreWithPassword{
		roles:    map[string]string{"admin@test.com": "admin"},
		statuses: map[string]string{"admin@test.com": "active"},
		password: "correctpass",
	})

	csrfToken := "valid-csrf"
	form := url.Values{
		"email": {"admin@test.com"}, "password": {"correctpass"}, "csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (admin login success)", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// HandleAdminLogin — POST with open redirect prevention (line 1133-1134)
// ---------------------------------------------------------------------------
func TestHandleAdminLogin_POST_OpenRedirectPrev_Gap(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetUserStore(&mockAdminUserStoreWithPassword{
		roles:    map[string]string{"admin@test.com": "admin"},
		statuses: map[string]string{"admin@test.com": "active"},
		password: "pass",
	})

	csrfToken := "valid-csrf"
	form := url.Values{
		"email": {"admin@test.com"}, "password": {"pass"}, "csrf_token": {csrfToken},
		"redirect": {"//evil.com"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc != "/admin/ops" {
		t.Errorf("Expected redirect to /admin/ops (open redirect prevention), got: %q", loc)
	}
}

// ---------------------------------------------------------------------------
// HandleAdminLogin — POST verify password error (line 1163-1165)
// ---------------------------------------------------------------------------
func TestHandleAdminLogin_POST_VerifyPasswordError(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetUserStore(&mockAdminUserStoreWithVerifyError{
		roles:    map[string]string{"admin@test.com": "admin"},
		statuses: map[string]string{"admin@test.com": "active"},
	})

	csrfToken := "valid-csrf"
	form := url.Values{
		"email": {"admin@test.com"}, "password": {"pass"}, "csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	// Should fail (VerifyPassword returns error), re-render form
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (verify error re-render)", rr.Code)
	}
}

type mockAdminUserStoreWithVerifyError struct {
	roles    map[string]string
	statuses map[string]string
}

func (m *mockAdminUserStoreWithVerifyError) GetRole(email string) string   { return m.roles[email] }
func (m *mockAdminUserStoreWithVerifyError) GetStatus(email string) string { return m.statuses[email] }
func (m *mockAdminUserStoreWithVerifyError) VerifyPassword(email, password string) (bool, error) {
	return false, fmt.Errorf("bcrypt error")
}
func (m *mockAdminUserStoreWithVerifyError) EnsureGoogleUser(email string) {}

// ---------------------------------------------------------------------------
// HandleAdminLogin — GET renders form (line 1192-1198)
// ---------------------------------------------------------------------------
func TestHandleAdminLogin_GET_Gap(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/admin-login", nil)
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// HandleKiteOAuthCallback — registry flow exchange error (lines 602-606)
// ---------------------------------------------------------------------------
func TestHandleKiteOAuthCallback_RegistryFlow_ExchangeError(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.exchangeWithCreds = func(rt, ak, as string) (string, error) {
			return "", fmt.Errorf("exchange failed")
		}
	})
	defer h.Close()

	h.SetRegistry(&mockKeyRegistry{
		hasEntries: true,
		entries: map[string]*RegistryEntry{
			"some-api-key": {APIKey: "some-api-key", APISecret: "secret"},
		},
	})

	clientID, _, _ := h.clients.Register([]string{"https://example.com/cb"}, "test")

	stateData := oauthState{
		ClientID: clientID, RedirectURI: "https://example.com/cb",
		CodeChallenge: "challenge", State: "s",
		RegistryKey: "some-api-key",
	}
	stateJSON, _ := json.Marshal(stateData)
	encoded := base64.URLEncoding.EncodeToString(stateJSON)
	signedData := h.signer.Sign(encoded)

	req := httptest.NewRequest(http.MethodGet, "/callback?data="+url.QueryEscape(signedData), nil)
	rr := httptest.NewRecorder()
	h.HandleKiteOAuthCallback(rr, req, "tok")

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 (registry exchange error)", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// HandleKiteOAuthCallback — normal flow exchange error (lines 623-627)
// ---------------------------------------------------------------------------
func TestHandleKiteOAuthCallback_NormalFlow_ExchangeError(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.exchangeFunc = func(rt string) (string, error) {
			return "", fmt.Errorf("exchange failed")
		}
	})
	defer h.Close()

	clientID, _, _ := h.clients.Register([]string{"https://example.com/cb"}, "test")

	stateData := oauthState{
		ClientID: clientID, RedirectURI: "https://example.com/cb",
		CodeChallenge: "ch", State: "s",
	}
	stateJSON, _ := json.Marshal(stateData)
	encoded := base64.URLEncoding.EncodeToString(stateJSON)
	signedData := h.signer.Sign(encoded)

	req := httptest.NewRequest(http.MethodGet, "/callback?data="+url.QueryEscape(signedData), nil)
	rr := httptest.NewRecorder()
	h.HandleKiteOAuthCallback(rr, req, "tok")

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 (exchange error)", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// HandleKiteOAuthCallback — invalid redirect URI parse (line 643)
// ---------------------------------------------------------------------------
func TestHandleKiteOAuthCallback_InvalidRedirectURI(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.exchangeFunc = func(rt string) (string, error) {
			return "user@test.com", nil
		}
	})
	defer h.Close()

	clientID, _, _ := h.clients.Register([]string{"://bad"}, "test")

	stateData := oauthState{
		ClientID: clientID, RedirectURI: "://bad",
		CodeChallenge: "ch", State: "s",
	}
	stateJSON, _ := json.Marshal(stateData)
	encoded := base64.URLEncoding.EncodeToString(stateJSON)
	signedData := h.signer.Sign(encoded)

	req := httptest.NewRequest(http.MethodGet, "/callback?data="+url.QueryEscape(signedData), nil)
	rr := httptest.NewRecorder()
	h.HandleKiteOAuthCallback(rr, req, "tok")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (invalid redirect URI)", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// HandleKiteOAuthCallback — SetAuthCookie called for SSO (line 634-636)
// ---------------------------------------------------------------------------
func TestHandleKiteOAuthCallback_SSOCookie(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.exchangeFunc = func(rt string) (string, error) {
			return "user@test.com", nil
		}
	})
	defer h.Close()

	clientID, _, _ := h.clients.Register([]string{"https://example.com/cb"}, "test")

	stateData := oauthState{
		ClientID: clientID, RedirectURI: "https://example.com/cb",
		CodeChallenge: pkceChallenge("v"), State: "s",
	}
	stateJSON, _ := json.Marshal(stateData)
	encoded := base64.URLEncoding.EncodeToString(stateJSON)
	signedData := h.signer.Sign(encoded)

	req := httptest.NewRequest(http.MethodGet, "/callback?data="+url.QueryEscape(signedData), nil)
	rr := httptest.NewRecorder()
	h.HandleKiteOAuthCallback(rr, req, "tok")

	// Should have set the auth cookie for SSO
	cookies := rr.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == cookieName {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected SSO auth cookie to be set")
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
// Token — form parse error (line 984-987)
// ---------------------------------------------------------------------------
func TestToken_FormParseError(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Send a body that exceeds MaxBytesReader limit (64KB)
	bigBody := strings.Repeat("x=y&", 20000) // ~80KB
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.Token(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (form parse error)", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Token — no email resolved (line 1076-1080)
// ---------------------------------------------------------------------------
func TestToken_NoEmailResolved(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.exchangeFunc = func(rt string) (string, error) {
			return "", nil // empty email, no error
		}
	})
	defer h.Close()

	// Register client and generate an auth code with empty email and no request token
	clientID, clientSecret, _ := h.clients.Register([]string{"https://example.com/cb"}, "test")
	verifier := "test-verifier-string-must-be-43-chars-minimum"
	challenge := pkceChallenge(verifier)

	code, _ := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      clientID,
		CodeChallenge: challenge,
		RedirectURI:   "https://example.com/cb",
		Email:         "", // no email
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.Token(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 (no email resolved)", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Token — deferred exchange with stored secret fallback (line 1050-1053)
// ---------------------------------------------------------------------------
func TestToken_DeferredExchange_StoredSecretFallback(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.getSecretByAPIKey = func(apiKey string) (string, bool) {
			return "stored-secret", true
		}
		e.exchangeWithCreds = func(rt, ak, as string) (string, error) {
			return "user@test.com", nil
		}
	})
	defer h.Close()

	kiteClientID := "kite-api-key-12345678"
	h.clients.RegisterKiteClient(kiteClientID, []string{"https://example.com/cb"})

	verifier := "test-verifier-string-must-be-43-chars-minimum"
	challenge := pkceChallenge(verifier)

	code, _ := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      kiteClientID,
		CodeChallenge: challenge,
		RedirectURI:   "https://example.com/cb",
		RequestToken:  "kite-request-token", // deferred exchange marker
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {kiteClientID},
		// No client_secret — should use stored secret fallback
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.Token(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (deferred exchange with stored secret). Body: %s", rr.Code, rr.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Token — deferred exchange fails (line 1060-1063)
// ---------------------------------------------------------------------------
func TestToken_DeferredExchange_Fails(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.getSecretByAPIKey = func(apiKey string) (string, bool) {
			return "", false
		}
		e.exchangeWithCreds = func(rt, ak, as string) (string, error) {
			return "", fmt.Errorf("exchange failed")
		}
	})
	defer h.Close()

	kiteClientID := "kite-api-key-12345678"
	h.clients.RegisterKiteClient(kiteClientID, []string{"https://example.com/cb"})

	verifier := "test-verifier-string-must-be-43-chars-minimum"
	challenge := pkceChallenge(verifier)

	code, _ := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      kiteClientID,
		CodeChallenge: challenge,
		RedirectURI:   "https://example.com/cb",
		RequestToken:  "kite-request-token",
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {kiteClientID},
		// No client_secret and no stored secret → error
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.Token(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (no secret available)", rr.Code)
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
// serveAdminLoginForm — nil template (line 1203-1205)
// ---------------------------------------------------------------------------
func TestServeAdminLoginForm_NilTmpl_Gap(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()
	h.adminLoginTmpl = nil

	rr := httptest.NewRecorder()
	h.serveAdminLoginForm(rr, "/admin/ops", "", "csrf")

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 (nil template)", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// serveAdminLoginForm — empty CSRF token (no cookie set, line 1209)
// ---------------------------------------------------------------------------
func TestServeAdminLoginForm_EmptyCSRF(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	rr := httptest.NewRecorder()
	h.serveAdminLoginForm(rr, "/admin/ops", "", "")

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (render without CSRF cookie)", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Register — too many redirect URIs (line 228)
// ---------------------------------------------------------------------------
func TestRegister_TooManyRedirectURIs_Gap(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	body := map[string]interface{}{
		"redirect_uris": make([]string, 11), // max is 10
		"client_name":   "test",
	}
	for i := range body["redirect_uris"].([]string) {
		body["redirect_uris"].([]string)[i] = fmt.Sprintf("https://example.com/cb%d", i)
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(string(bodyJSON)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.Register(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (too many redirect URIs)", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// JWT ValidateToken — method check (line 72-74)
// ---------------------------------------------------------------------------
func TestJWT_ValidateToken_InvalidMethod(t *testing.T) {
	t.Parallel()
	j := NewJWTManager("test-secret", 1*time.Hour)

	_, err := j.ValidateToken("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyQHRlc3QuY29tIn0.", "test")
	if err == nil {
		t.Error("Expected error for 'none' algorithm")
	}
}

// ---------------------------------------------------------------------------
// JWT ValidateToken — invalid token (line 81-83)
// ---------------------------------------------------------------------------
func TestJWT_ValidateToken_MalformedToken(t *testing.T) {
	t.Parallel()
	j := NewJWTManager("test-secret", 1*time.Hour)

	_, err := j.ValidateToken("not.a.valid.jwt")
	if err == nil {
		t.Error("Expected error for malformed token")
	}
}

// ---------------------------------------------------------------------------
// JWT ValidateToken — audience mismatch with multiple audiences (line 98-100)
// ---------------------------------------------------------------------------
func TestJWT_ValidateToken_AudienceMismatch(t *testing.T) {
	t.Parallel()
	j := NewJWTManager("test-secret", 1*time.Hour)

	token, err := j.GenerateToken("user@test.com", "client1")
	if err != nil {
		t.Fatalf("GenerateToken error: %v", err)
	}

	// Validate with non-matching audiences
	_, err = j.ValidateToken(token, "different-audience", "another-audience")
	if err == nil {
		t.Error("Expected error for audience mismatch")
	}
}

// ---------------------------------------------------------------------------
// ClientStore — RegisterKiteClient overflow triggers evict (line 281-283)
// ---------------------------------------------------------------------------
func TestClientStore_RegisterKiteClient_Evict(t *testing.T) {
	t.Parallel()
	store := NewClientStore()

	// Fill to capacity with regular clients
	for i := 0; i < maxClients; i++ {
		store.Register([]string{fmt.Sprintf("https://example.com/cb%d", i)}, fmt.Sprintf("client-%d", i))
	}

	// RegisterKiteClient should trigger eviction
	store.RegisterKiteClient("kite-key-new", []string{"https://example.com/cb"})

	// Should still be at maxClients (one evicted, one added)
	store.mu.RLock()
	count := len(store.clients)
	store.mu.RUnlock()

	if count != maxClients {
		t.Errorf("Client count = %d, want %d", count, maxClients)
	}
}

// ---------------------------------------------------------------------------
// AuthCodeStore — Generate at capacity (ErrAuthCodeStoreFull)
// ---------------------------------------------------------------------------
func TestAuthCodeStore_Full_Gap(t *testing.T) {
	t.Parallel()
	store := NewAuthCodeStore()
	defer store.Close()

	// Fill to capacity
	for i := 0; i < maxAuthCodes; i++ {
		_, err := store.Generate(&AuthCodeEntry{ClientID: fmt.Sprintf("c%d", i)})
		if err != nil {
			t.Fatalf("Generate #%d error: %v", i, err)
		}
	}

	// Next one should fail
	_, err := store.Generate(&AuthCodeEntry{ClientID: "overflow"})
	if err != ErrAuthCodeStoreFull {
		t.Errorf("Expected ErrAuthCodeStoreFull, got: %v", err)
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

// ---------------------------------------------------------------------------
// Documented unreachable lines
// ---------------------------------------------------------------------------
//
// The following lines are documented as unreachable and NOT tested:
//
// - handlers.go:106-124 — template.ParseFS errors (templates are embedded at build time)
// - handlers.go:823-825 — generateCSRFToken (crypto/rand.Read never fails in Go 1.24+)
// - stores.go:58-60 — randomHex (crypto/rand.Read never fails in Go 1.24+)
// - stores.go:211-213, 215-217 — Register randomHex (same reason)
// - stores.go:349-353 — randomHex (same reason)
// - middleware.go:125-127 — SetAuthCookie (HS256 SignedString never fails)
// - google_sso.go:66-70 — rand.Read (same reason)
// - google_sso.go:217-221 — rand.Read (same reason)
// - google_sso.go:245-247, 255-257 — fetchGoogleUserInfo HTTP/JSON errors (tested via mock servers)
