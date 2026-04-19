package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

)

// --- Well-Known Metadata ---


// --- Authorization Endpoint ---
func TestAuthorize_Valid(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Register a client first
	clientID, _, err := h.clients.Register([]string{"https://example.com/callback"}, "test-app")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	challenge := pkceChallenge("test-verifier-string")
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {"https://example.com/callback"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"random-state"},
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()

	h.Authorize(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("Status = %d, want 302. Body: %s", rr.Code, rr.Body.String())
	}
	location := rr.Header().Get("Location")
	if !strings.Contains(location, "kite.zerodha.com/connect/login") {
		t.Errorf("Should redirect to Kite login, got: %q", location)
	}
	if !strings.Contains(location, "api_key=test-api-key") {
		t.Errorf("Should use global API key, got: %q", location)
	}
}


func TestAuthorize_MissingParams(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	tests := []struct {
		name   string
		params url.Values
	}{
		{
			"missing response_type",
			url.Values{
				"client_id":             {"client"},
				"redirect_uri":          {"https://example.com/cb"},
				"code_challenge":        {"challenge"},
				"code_challenge_method": {"S256"},
			},
		},
		{
			"wrong response_type",
			url.Values{
				"response_type":         {"token"},
				"client_id":             {"client"},
				"redirect_uri":          {"https://example.com/cb"},
				"code_challenge":        {"challenge"},
				"code_challenge_method": {"S256"},
			},
		},
		{
			"missing client_id",
			url.Values{
				"response_type":         {"code"},
				"redirect_uri":          {"https://example.com/cb"},
				"code_challenge":        {"challenge"},
				"code_challenge_method": {"S256"},
			},
		},
		{
			"missing redirect_uri",
			url.Values{
				"response_type":         {"code"},
				"client_id":             {"client"},
				"code_challenge":        {"challenge"},
				"code_challenge_method": {"S256"},
			},
		},
		{
			"missing code_challenge",
			url.Values{
				"response_type":         {"code"},
				"client_id":             {"client"},
				"redirect_uri":          {"https://example.com/cb"},
				"code_challenge_method": {"S256"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+tc.params.Encode(), nil)
			rr := httptest.NewRecorder()
			h.Authorize(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("Status = %d, want 400", rr.Code)
			}
		})
	}
}


func TestAuthorize_WrongChallengeMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"client"},
		"redirect_uri":          {"https://example.com/cb"},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"plain"},
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()

	h.Authorize(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
	var body map[string]string
	json.Unmarshal(rr.Body.Bytes(), &body)
	if !strings.Contains(body["error_description"], "S256") {
		t.Errorf("Error should mention S256: %v", body)
	}
}


func TestAuthorize_InvalidRedirectScheme(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"client"},
		"redirect_uri":          {"ftp://example.com/callback"},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"S256"},
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()

	h.Authorize(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}


func TestAuthorize_AutoRegistersKiteClient(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Use an unknown client_id — should auto-register as Kite API key client
	challenge := pkceChallenge("verifier")
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"unknown-kite-api-key"},
		"redirect_uri":          {"https://example.com/callback"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"state123"},
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()

	h.Authorize(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("Status = %d, want 302. Body: %s", rr.Code, rr.Body.String())
	}

	// Should have been auto-registered as a Kite client
	if !h.clients.IsKiteClient("unknown-kite-api-key") {
		t.Error("Unknown client should have been auto-registered as Kite API key client")
	}

	// Should use the client_id as the API key in the redirect
	location := rr.Header().Get("Location")
	if !strings.Contains(location, "api_key=unknown-kite-api-key") {
		t.Errorf("Should use per-user API key: %q", location)
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


// ===========================================================================
// Authorize — missing params
// ===========================================================================
func TestAuthorize_MissingRequiredParams(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?response_type=code", nil)
	rr := httptest.NewRecorder()
	h.Authorize(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (missing params)", rr.Code)
	}
}


// Authorize — redirect URI validation fails for non-Kite registered client
func TestAuthorize_RedirectURIMismatch(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Register a non-Kite client with a specific redirect URI
	clientID, _, _ := h.clients.Register([]string{"http://allowed.com/callback"}, "test-client")

	req := httptest.NewRequest(http.MethodGet,
		"/oauth/authorize?client_id="+clientID+
			"&redirect_uri=http://evil.com/callback"+
			"&code_challenge=testchallenge"+
			"&code_challenge_method=S256"+
			"&response_type=code",
		nil)
	rr := httptest.NewRecorder()
	h.Authorize(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (redirect_uri mismatch)", rr.Code)
	}
}
