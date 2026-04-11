package oauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

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
// serveAdminLoginForm — nil template error path
// ===========================================================================

func TestServeAdminLoginForm_NilTemplate(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.adminLoginTmpl = nil

	rr := httptest.NewRecorder()
	h.serveAdminLoginForm(rr, "/admin/ops", "", "csrf")

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 (nil template)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Failed to load admin login page") {
		t.Errorf("Body = %q, want 'Failed to load admin login page'", rr.Body.String())
	}
}

// ===========================================================================
// serveAdminLoginForm — empty CSRF token (no cookie set)
// ===========================================================================

func TestServeAdminLoginForm_EmptyCSRFNoCookie(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	rr := httptest.NewRecorder()
	h.serveAdminLoginForm(rr, "/admin/ops", "Some error", "")

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
	cookies := rr.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "csrf_token_admin" {
			t.Error("Should not set csrf_token_admin cookie when token is empty")
		}
	}
}

// ===========================================================================
// HandleLoginChoice — nil template error path
// ===========================================================================

func TestHandleLoginChoice_NilTemplate(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.loginChoiceTmpl = nil

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	rr := httptest.NewRecorder()

	h.HandleLoginChoice(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 (nil template)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Failed to load login page") {
		t.Errorf("Body = %q, want 'Failed to load login page'", rr.Body.String())
	}
}

// ===========================================================================
// writeJSON — unmarshalable type (error path)
// ===========================================================================

func TestWriteJSON_UnmarshalableType(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	rr := httptest.NewRecorder()
	h.writeJSON(rr, http.StatusOK, map[string]interface{}{
		"bad": math.Inf(1),
	})

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (status already written before encode fails)", rr.Code)
	}
}

// ===========================================================================
// SetHTTPClient coverage
// ===========================================================================

func TestSetHTTPClient_Coverage(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetHTTPClient(nil)
	h.SetHTTPClient(&http.Client{Timeout: 5 * time.Second})
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

// ===========================================================================
// cleanup — stop via done channel
// ===========================================================================

func TestAuthCodeStore_CleanupStopsOnDone(t *testing.T) {
	t.Parallel()
	store := &AuthCodeStore{
		entries: make(map[string]*AuthCodeEntry),
		done:    make(chan struct{}),
	}

	store.mu.Lock()
	store.entries["expired"] = &AuthCodeEntry{
		ClientID:  "client",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	store.entries["valid"] = &AuthCodeEntry{
		ClientID:  "client",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	store.mu.Unlock()

	go store.cleanup()
	time.Sleep(10 * time.Millisecond)
	store.Close()
}

// ===========================================================================
// HandleKiteOAuthCallback — registry flow: no secret found
// ===========================================================================

func TestHandleKiteOAuthCallback_RegistryFlow_NoSecret(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetRegistry(&mockKeyRegistry{
		hasEntries: true,
		entries:    map[string]*RegistryEntry{},
	})

	clientID, _, _ := h.clients.Register([]string{"https://example.com/cb"}, "test")

	stateData := oauthState{
		ClientID:      clientID,
		RedirectURI:   "https://example.com/cb",
		CodeChallenge: "challenge",
		State:         "state",
		RegistryKey:   "unknown-key",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	req := httptest.NewRequest(http.MethodGet, "/callback?flow=oauth&data="+url.QueryEscape(signedState), nil)
	rr := httptest.NewRecorder()

	h.HandleKiteOAuthCallback(rr, req, "request-token")

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 (registry credentials not found)", rr.Code)
	}
}

func TestHandleKiteOAuthCallback_RegistryFlow_ExchangeFails(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.exchangeWithCreds = func(requestToken, apiKey, apiSecret string) (string, error) {
			return "", fmt.Errorf("kite exchange failed")
		}
	})
	defer h.Close()

	h.SetRegistry(&mockKeyRegistry{
		hasEntries: true,
		entries: map[string]*RegistryEntry{
			"user@test.com": {
				APIKey:    "reg-key-12345678",
				APISecret: "reg-secret",
			},
		},
	})

	clientID, _, _ := h.clients.Register([]string{"https://example.com/cb"}, "test")

	stateData := oauthState{
		ClientID:      clientID,
		RedirectURI:   "https://example.com/cb",
		CodeChallenge: "challenge",
		State:         "state",
		RegistryKey:   "reg-key-12345678",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	req := httptest.NewRequest(http.MethodGet, "/callback?flow=oauth&data="+url.QueryEscape(signedState), nil)
	rr := httptest.NewRecorder()

	h.HandleKiteOAuthCallback(rr, req, "request-token")

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 (exchange failed)", rr.Code)
	}
}

func TestHandleKiteOAuthCallback_RegistryFlow_Success(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.exchangeWithCreds = func(requestToken, apiKey, apiSecret string) (string, error) {
			return "reguser@test.com", nil
		}
	})
	defer h.Close()

	h.SetRegistry(&mockKeyRegistry{
		hasEntries: true,
		entries: map[string]*RegistryEntry{
			"reguser@test.com": {
				APIKey:    "reg-api-key-12345678",
				APISecret: "reg-secret",
			},
		},
	})

	clientID, _, _ := h.clients.Register([]string{"https://example.com/cb"}, "test")

	stateData := oauthState{
		ClientID:      clientID,
		RedirectURI:   "https://example.com/cb",
		CodeChallenge: "challenge",
		State:         "state",
		RegistryKey:   "reg-api-key-12345678",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	req := httptest.NewRequest(http.MethodGet, "/callback?flow=oauth&data="+url.QueryEscape(signedState), nil)
	rr := httptest.NewRecorder()

	h.HandleKiteOAuthCallback(rr, req, "request-token")

	if rr.Code != http.StatusOK && rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 200 or 302 (registry flow success)", rr.Code)
	}
}

func TestHandleKiteOAuthCallback_KiteClient_ImmediateExchange(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.getSecretByAPIKey = func(apiKey string) (string, bool) {
			return "stored-secret", true
		}
		exchanger.exchangeWithCreds = func(requestToken, apiKey, apiSecret string) (string, error) {
			return "kite-user@test.com", nil
		}
	})
	defer h.Close()

	kiteAPIKey := "kite-immediate-key"
	h.clients.RegisterKiteClient(kiteAPIKey, []string{"https://example.com/cb"})

	stateData := oauthState{
		ClientID:      kiteAPIKey,
		RedirectURI:   "https://example.com/cb",
		CodeChallenge: "challenge",
		State:         "state",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	req := httptest.NewRequest(http.MethodGet, "/callback?flow=oauth&data="+url.QueryEscape(signedState), nil)
	rr := httptest.NewRecorder()

	h.HandleKiteOAuthCallback(rr, req, "request-token")

	if rr.Code != http.StatusOK && rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 200 or 302 (immediate exchange)", rr.Code)
	}
}

func TestHandleKiteOAuthCallback_KiteClient_ImmediateExchangeFails_FallsBackToDeferred(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.getSecretByAPIKey = func(apiKey string) (string, bool) {
			return "stale-secret", true
		}
		exchanger.exchangeWithCreds = func(requestToken, apiKey, apiSecret string) (string, error) {
			return "", fmt.Errorf("stale credentials")
		}
	})
	defer h.Close()

	kiteAPIKey := "kite-stale-key"
	h.clients.RegisterKiteClient(kiteAPIKey, []string{"https://example.com/cb"})

	stateData := oauthState{
		ClientID:      kiteAPIKey,
		RedirectURI:   "https://example.com/cb",
		CodeChallenge: "challenge",
		State:         "state",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	req := httptest.NewRequest(http.MethodGet, "/callback?flow=oauth&data="+url.QueryEscape(signedState), nil)
	rr := httptest.NewRecorder()

	h.HandleKiteOAuthCallback(rr, req, "request-token")

	if rr.Code != http.StatusOK && rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 200 or 302 (deferred fallback)", rr.Code)
	}
}

func TestHandleKiteOAuthCallback_NilSuccessTemplate_FallsBackToRedirect(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.loginSuccessTmpl = nil

	clientID, _, _ := h.clients.Register([]string{"https://example.com/cb"}, "test")

	stateData := oauthState{
		ClientID:      clientID,
		RedirectURI:   "https://example.com/cb",
		CodeChallenge: "challenge",
		State:         "state",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	req := httptest.NewRequest(http.MethodGet, "/callback?flow=oauth&data="+url.QueryEscape(signedState), nil)
	rr := httptest.NewRecorder()

	h.HandleKiteOAuthCallback(rr, req, "request-token")

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (nil template fallback)", rr.Code)
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

func TestAuthorize_RegistryFlow_ShowsEmailPrompt(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetRegistry(&mockKeyRegistry{
		hasEntries: true,
		entries: map[string]*RegistryEntry{
			"user@test.com": {APIKey: "key12345678", APISecret: "secret"},
		},
	})

	clientID, _, _ := h.clients.Register([]string{"https://example.com/cb"}, "test")

	challenge := pkceChallenge("verifier")
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {"https://example.com/cb"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"state"},
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()

	h.Authorize(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (email prompt)", rr.Code)
	}
}

func TestAuthorize_NoKiteAPIKey_ReturnsError(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		cfg.KiteAPIKey = ""
	})
	defer h.Close()

	clientID, _, _ := h.clients.Register([]string{"https://example.com/cb"}, "test")

	challenge := pkceChallenge("verifier")
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {"https://example.com/cb"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()

	h.Authorize(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (no Kite API key)", rr.Code)
	}
}

func TestAuthorize_ExistingKiteClient_AddsNewRedirectURI(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.clients.RegisterKiteClient("existing-kite-key", []string{"https://old.example.com/cb"})

	challenge := pkceChallenge("verifier")
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"existing-kite-key"},
		"redirect_uri":          {"https://new.example.com/cb"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"state"},
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()

	h.Authorize(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302", rr.Code)
	}

	if !h.clients.ValidateRedirectURI("existing-kite-key", "https://new.example.com/cb") {
		t.Error("New redirect URI should have been added to existing Kite client")
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

func TestHandleGoogleCallback_OpenRedirectInCookie(t *testing.T) {
	t.Parallel()

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenSrv.Close()

	userinfoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"email":          "admin@test.com",
			"verified_email": true,
		})
	}))
	defer userinfoSrv.Close()

	h := newTestHandler()
	defer h.Close()

	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
		Endpoint:     tokenSrv.URL,
		UserInfoURL:  userinfoSrv.URL,
	})
	h.SetHTTPClient(tokenSrv.Client())
	h.SetUserStore(&mockAdminUserStore{
		roles:    map[string]string{"admin@test.com": "admin"},
		statuses: map[string]string{"admin@test.com": "active"},
	})

	state := base64.URLEncoding.EncodeToString([]byte("mystate"))
	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback?code=c&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: googleStateCookieName, Value: state + "|//evil.com"})
	rr := httptest.NewRecorder()

	h.HandleGoogleCallback(rr, req)

	if rr.Code == http.StatusFound {
		location := rr.Header().Get("Location")
		if strings.Contains(location, "evil.com") {
			t.Errorf("Open redirect should be blocked, got: %q", location)
		}
	}
}

func TestGoogleSSOConfig_UserInfoURL_Default(t *testing.T) {
	t.Parallel()
	cfg := &GoogleSSOConfig{}
	u := cfg.userInfoURL()
	if u != googleUserInfoURL {
		t.Errorf("userInfoURL() = %q, want default %q", u, googleUserInfoURL)
	}
}

func TestGoogleSSOConfig_UserInfoURL_Override(t *testing.T) {
	t.Parallel()
	cfg := &GoogleSSOConfig{UserInfoURL: "https://custom.example.com/userinfo"}
	u := cfg.userInfoURL()
	if u != "https://custom.example.com/userinfo" {
		t.Errorf("userInfoURL() = %q, want override", u)
	}
}

func TestGoogleSSOConfig_OAuthConfig_WithEndpoint(t *testing.T) {
	t.Parallel()
	cfg := &GoogleSSOConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		RedirectURL:  "https://test.example.com/cb",
		Endpoint:     "https://custom-token-server.example.com",
	}
	oc := cfg.oauthConfig()
	if oc.Endpoint.TokenURL != "https://custom-token-server.example.com/token" {
		t.Errorf("TokenURL = %q, want custom endpoint /token", oc.Endpoint.TokenURL)
	}
	if oc.Endpoint.AuthURL != "https://custom-token-server.example.com/auth" {
		t.Errorf("AuthURL = %q, want custom endpoint /auth", oc.Endpoint.AuthURL)
	}
}
