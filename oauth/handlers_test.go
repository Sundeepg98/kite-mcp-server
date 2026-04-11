package oauth

import (
	"crypto/sha256"
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

// --- Well-Known Metadata ---

func TestResourceMetadata_GET(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rr := httptest.NewRecorder()

	h.ResourceMetadata(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}
	if body["resource"] != "https://test.example.com/mcp" {
		t.Errorf("resource = %v, want %q", body["resource"], "https://test.example.com/mcp")
	}
	servers, ok := body["authorization_servers"].([]interface{})
	if !ok || len(servers) != 1 || servers[0] != "https://test.example.com" {
		t.Errorf("authorization_servers = %v, want [https://test.example.com]", body["authorization_servers"])
	}
}

func TestResourceMetadata_POST(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodPost, "/.well-known/oauth-protected-resource", nil)
	rr := httptest.NewRecorder()

	h.ResourceMetadata(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %d, want 405", rr.Code)
	}
}

func TestAuthServerMetadata(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rr := httptest.NewRecorder()

	h.AuthServerMetadata(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want 200", rr.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}

	requiredFields := []struct {
		key  string
		want string
	}{
		{"issuer", "https://test.example.com"},
		{"authorization_endpoint", "https://test.example.com/oauth/authorize"},
		{"token_endpoint", "https://test.example.com/oauth/token"},
		{"registration_endpoint", "https://test.example.com/oauth/register"},
	}
	for _, f := range requiredFields {
		if body[f.key] != f.want {
			t.Errorf("%s = %v, want %q", f.key, body[f.key], f.want)
		}
	}

	// Check supported values
	checkStringSlice := func(key string, want []string) {
		t.Helper()
		arr, ok := body[key].([]interface{})
		if !ok {
			t.Errorf("%s is not an array", key)
			return
		}
		if len(arr) != len(want) {
			t.Errorf("%s length = %d, want %d", key, len(arr), len(want))
			return
		}
		for i, v := range arr {
			if v != want[i] {
				t.Errorf("%s[%d] = %v, want %q", key, i, v, want[i])
			}
		}
	}
	checkStringSlice("response_types_supported", []string{"code"})
	checkStringSlice("grant_types_supported", []string{"authorization_code"})
	checkStringSlice("code_challenge_methods_supported", []string{"S256"})
	checkStringSlice("token_endpoint_auth_methods_supported", []string{"client_secret_post"})
}

// --- Dynamic Client Registration ---

func TestRegister_Valid(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	body := `{"redirect_uris":["https://example.com/callback"],"client_name":"test-app"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.Register(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("Status = %d, want 201. Body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}
	if resp["client_id"] == nil || resp["client_id"] == "" {
		t.Error("client_id should be non-empty")
	}
	if resp["client_secret"] == nil || resp["client_secret"] == "" {
		t.Error("client_secret should be non-empty")
	}
	if resp["client_name"] != "test-app" {
		t.Errorf("client_name = %v, want %q", resp["client_name"], "test-app")
	}
	if resp["token_endpoint_auth_method"] != "client_secret_post" {
		t.Errorf("token_endpoint_auth_method = %v, want %q", resp["token_endpoint_auth_method"], "client_secret_post")
	}
}

func TestRegister_NoRedirectURIs(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	body := `{"redirect_uris":[],"client_name":"test-app"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.Register(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}

func TestRegister_TooManyURIs(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	uris := make([]string, 11)
	for i := range uris {
		uris[i] = fmt.Sprintf("https://example.com/cb%d", i)
	}
	reqBody := struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
	}{RedirectURIs: uris, ClientName: "test-app"}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(string(bodyBytes)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.Register(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}

func TestRegister_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/oauth/register", nil)
	rr := httptest.NewRecorder()

	h.Register(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %d, want 405", rr.Code)
	}
}

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

// --- Token Endpoint ---

func TestToken_ValidPKCEExchange(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Register a client
	clientID, clientSecret, err := h.clients.Register([]string{"https://example.com/callback"}, "test-app")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Simulate the authorize/callback flow by directly inserting an auth code
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)

	code, err := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      clientID,
		CodeChallenge: challenge,
		RedirectURI:   "https://example.com/callback",
		Email:         "alice@test.com",
	})
	if err != nil {
		t.Fatalf("Generate auth code failed: %v", err)
	}

	// Exchange code for token
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

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want 200. Body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}
	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Error("access_token should be non-empty")
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", resp["token_type"])
	}

	// Validate the returned JWT
	claims, err := h.jwt.ValidateToken(resp["access_token"].(string))
	if err != nil {
		t.Fatalf("Returned JWT is invalid: %v", err)
	}
	if claims.Subject != "alice@test.com" {
		t.Errorf("JWT Subject = %q, want %q", claims.Subject, "alice@test.com")
	}
}

func TestToken_PKCEFailure(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	clientID, clientSecret, err := h.clients.Register([]string{"https://example.com/callback"}, "test-app")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	verifier := "correct-verifier"
	challenge := pkceChallenge(verifier)

	code, err := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      clientID,
		CodeChallenge: challenge,
		RedirectURI:   "https://example.com/callback",
		Email:         "alice@test.com",
	})
	if err != nil {
		t.Fatalf("Generate auth code failed: %v", err)
	}

	// Use wrong verifier
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {"wrong-verifier"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.Token(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if !strings.Contains(resp["error_description"], "PKCE") {
		t.Errorf("Error should mention PKCE: %v", resp)
	}
}

func TestToken_ExpiredCode(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	clientID, clientSecret, err := h.clients.Register([]string{"https://example.com/callback"}, "test-app")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	verifier := "test-verifier"
	challenge := pkceChallenge(verifier)

	code, err := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      clientID,
		CodeChallenge: challenge,
		RedirectURI:   "https://example.com/callback",
		Email:         "alice@test.com",
	})
	if err != nil {
		t.Fatalf("Generate auth code failed: %v", err)
	}

	// Manually expire the code
	h.authCodes.mu.Lock()
	if entry, ok := h.authCodes.entries[code]; ok {
		entry.ExpiresAt = entry.ExpiresAt.Add(-20 * 60 * 1e9) // subtract 20 minutes
	}
	h.authCodes.mu.Unlock()

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

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}

func TestToken_ClientIDMismatch(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	clientID1, _, err := h.clients.Register([]string{"https://example.com/callback"}, "app1")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	clientID2, clientSecret2, err := h.clients.Register([]string{"https://example.com/callback"}, "app2")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	verifier := "test-verifier"
	challenge := pkceChallenge(verifier)

	// Code issued for client1
	code, err := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      clientID1,
		CodeChallenge: challenge,
		RedirectURI:   "https://example.com/callback",
		Email:         "alice@test.com",
	})
	if err != nil {
		t.Fatalf("Generate auth code failed: %v", err)
	}

	// Try to exchange with client2
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {clientID2},
		"client_secret": {clientSecret2},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.Token(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if !strings.Contains(resp["error_description"], "client_id mismatch") {
		t.Errorf("Error should mention client_id mismatch: %v", resp)
	}
}

func TestToken_UnsupportedGrantType(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"code":          {"some-code"},
		"code_verifier": {"some-verifier"},
		"client_id":     {"some-client"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.Token(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "unsupported_grant_type" {
		t.Errorf("error = %q, want %q", resp["error"], "unsupported_grant_type")
	}
}

func TestToken_InvalidClientSecret(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	clientID, _, err := h.clients.Register([]string{"https://example.com/callback"}, "test-app")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"some-code"},
		"code_verifier": {"some-verifier"},
		"client_id":     {clientID},
		"client_secret": {"wrong-secret"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.Token(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want 401", rr.Code)
	}
	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "invalid_client" {
		t.Errorf("error = %q, want %q", resp["error"], "invalid_client")
	}
}

func TestToken_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
	rr := httptest.NewRecorder()

	h.Token(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %d, want 405", rr.Code)
	}
}

// --- Kite OAuth Callback ---

func TestHandleKiteOAuthCallback_Valid(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Register a client
	clientID, _, err := h.clients.Register([]string{"https://example.com/callback"}, "test-app")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Build signed state (same as Authorize does)
	stateData := oauthState{
		ClientID:      clientID,
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: "test-challenge",
		State:         "client-state-123",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	req := httptest.NewRequest(http.MethodGet, "/callback?data="+url.QueryEscape(signedState), nil)
	rr := httptest.NewRecorder()

	h.HandleKiteOAuthCallback(rr, req, "valid-request-token")

	// Should render HTML with redirect URL containing the auth code
	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want 200. Body: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()
	// The HTML should contain a redirect URL with the code and state
	if !strings.Contains(body, "code=") {
		t.Errorf("Response should contain 'code=' in redirect URL. Body: %s", body)
	}
	if !strings.Contains(body, "client-state-123") {
		t.Errorf("Response should contain original client state. Body: %s", body)
	}
}

func TestHandleKiteOAuthCallback_MissingToken(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	rr := httptest.NewRecorder()

	h.HandleKiteOAuthCallback(rr, req, "")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}

func TestHandleKiteOAuthCallback_MissingData(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	rr := httptest.NewRecorder()

	h.HandleKiteOAuthCallback(rr, req, "valid-token")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}

func TestHandleKiteOAuthCallback_TamperedState(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		signer.verifyFunc = func(signed string) (string, error) {
			return "", fmt.Errorf("signature verification failed")
		}
	})
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/callback?data=tampered-data", nil)
	rr := httptest.NewRecorder()

	h.HandleKiteOAuthCallback(rr, req, "valid-token")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}

func TestHandleKiteOAuthCallback_ExchangeFailure(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.exchangeFunc = func(requestToken string) (string, error) {
			return "", fmt.Errorf("kite exchange failed")
		}
	})
	defer h.Close()

	// Register a non-Kite client (normal flow uses global exchange)
	clientID, _, err := h.clients.Register([]string{"https://example.com/callback"}, "test-app")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	stateData := oauthState{
		ClientID:      clientID,
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: "test-challenge",
		State:         "state",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	req := httptest.NewRequest(http.MethodGet, "/callback?data="+url.QueryEscape(signedState), nil)
	rr := httptest.NewRecorder()

	h.HandleKiteOAuthCallback(rr, req, "bad-request-token")

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500", rr.Code)
	}
}

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

// --- Close ---

func TestClose(t *testing.T) {
	t.Parallel()
	h := newTestHandler()

	// Close should not panic
	h.Close()

	// Double close should not panic (protected by sync.Once)
	h.Close()
}

// --- Full PKCE flow end-to-end ---

func TestFullPKCEFlow(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Step 1: Register client
	regBody := `{"redirect_uris":["https://example.com/callback"],"client_name":"e2e-app"}`
	regReq := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	regRR := httptest.NewRecorder()
	h.Register(regRR, regReq)

	if regRR.Code != http.StatusCreated {
		t.Fatalf("Register: status = %d, want 201", regRR.Code)
	}
	var regResp map[string]interface{}
	json.Unmarshal(regRR.Body.Bytes(), &regResp)
	clientID := regResp["client_id"].(string)
	clientSecret := regResp["client_secret"].(string)

	// Step 2: Generate PKCE pair
	codeVerifier := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Step 3: Simulate the callback by directly inserting an auth code
	// (In production, Authorize redirects to Kite, then Kite calls back)
	code, err := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      clientID,
		CodeChallenge: codeChallenge,
		RedirectURI:   "https://example.com/callback",
		Email:         "e2e-user@test.com",
	})
	if err != nil {
		t.Fatalf("Generate auth code failed: %v", err)
	}

	// Step 4: Exchange code for token
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {codeVerifier},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	tokenReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRR := httptest.NewRecorder()
	h.Token(tokenRR, tokenReq)

	if tokenRR.Code != http.StatusOK {
		t.Fatalf("Token: status = %d, want 200. Body: %s", tokenRR.Code, tokenRR.Body.String())
	}
	var tokenResp map[string]interface{}
	json.Unmarshal(tokenRR.Body.Bytes(), &tokenResp)
	accessToken := tokenResp["access_token"].(string)

	// Step 5: Use the token to access a protected endpoint
	protectedHandler := h.RequireAuth(echoEmailHandler())
	protectedReq := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	protectedReq.Header.Set("Authorization", "Bearer "+accessToken)
	protectedRR := httptest.NewRecorder()
	protectedHandler.ServeHTTP(protectedRR, protectedReq)

	if protectedRR.Code != http.StatusOK {
		t.Fatalf("Protected endpoint: status = %d, want 200", protectedRR.Code)
	}
	if body := protectedRR.Body.String(); body != "e2e-user@test.com" {
		t.Errorf("Protected endpoint body = %q, want %q", body, "e2e-user@test.com")
	}
}

// --- Token endpoint: deferred exchange (Kite API key client) ---

func TestToken_DeferredExchange_KiteClient(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.exchangeWithCreds = func(requestToken, apiKey, apiSecret string) (string, error) {
			if apiKey == "kite-user-api-key" && apiSecret == "kite-user-secret" {
				return "kite-user@test.com", nil
			}
			return "", fmt.Errorf("invalid credentials")
		}
	})
	defer h.Close()

	// Register as Kite client
	kiteAPIKey := "kite-user-api-key"
	h.clients.RegisterKiteClient(kiteAPIKey, []string{"https://example.com/callback"})

	verifier := "deferred-verifier-value"
	challenge := pkceChallenge(verifier)

	// Auth code with RequestToken (deferred exchange)
	code, err := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      kiteAPIKey,
		CodeChallenge: challenge,
		RedirectURI:   "https://example.com/callback",
		RequestToken:  "kite-request-token",
	})
	if err != nil {
		t.Fatalf("Generate auth code failed: %v", err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {kiteAPIKey},
		"client_secret": {"kite-user-secret"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.Token(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want 200. Body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	accessToken := resp["access_token"].(string)

	claims, err := h.jwt.ValidateToken(accessToken)
	if err != nil {
		t.Fatalf("Returned JWT is invalid: %v", err)
	}
	if claims.Subject != "kite-user@test.com" {
		t.Errorf("JWT Subject = %q, want %q", claims.Subject, "kite-user@test.com")
	}
}

// --- Kite OAuth Callback: Deferred Exchange Flow ---

func TestHandleKiteOAuthCallback_DeferredExchange(t *testing.T) {
	t.Parallel()

	kiteAPIKey := "deferred-kite-api-key"
	kiteAPISecret := "deferred-kite-api-secret"

	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.exchangeWithCreds = func(requestToken, apiKey, apiSecret string) (string, error) {
			if apiKey == kiteAPIKey && apiSecret == kiteAPISecret && requestToken == "deferred-request-token" {
				return "deferred@test.com", nil
			}
			return "", fmt.Errorf("invalid credentials: apiKey=%s apiSecret=%s", apiKey, apiSecret)
		}
	})
	defer h.Close()

	// Nil out the template so the callback falls back to a 302 redirect,
	// making it easy to extract the auth code from the Location header.
	h.loginSuccessTmpl = nil

	// Step 1: Register a Kite API key client
	h.clients.RegisterKiteClient(kiteAPIKey, []string{"https://example.com/callback"})

	// Step 2: Create signed state (as the Authorize endpoint would)
	verifier := "deferred-exchange-verifier"
	challenge := pkceChallenge(verifier)

	stateData := oauthState{
		ClientID:      kiteAPIKey,
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: challenge,
		State:         "deferred-state-abc",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	// Step 3: Call HandleKiteOAuthCallback with a request_token
	req := httptest.NewRequest(http.MethodGet, "/callback?data="+url.QueryEscape(signedState), nil)
	rr := httptest.NewRecorder()

	h.HandleKiteOAuthCallback(rr, req, "deferred-request-token")

	// Should redirect (302) since template is nil
	if rr.Code != http.StatusFound {
		t.Fatalf("Status = %d, want 302. Body: %s", rr.Code, rr.Body.String())
	}

	// Step 4: Extract the auth code from the Location header
	location := rr.Header().Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("Failed to parse Location URL: %v", err)
	}
	authCode := redirectURL.Query().Get("code")
	if authCode == "" {
		t.Fatalf("No 'code' param in redirect URL: %s", location)
	}
	// Verify original state is preserved
	if got := redirectURL.Query().Get("state"); got != "deferred-state-abc" {
		t.Errorf("state = %q, want %q", got, "deferred-state-abc")
	}

	// Step 5: Exchange at the token endpoint with code_verifier and client_secret
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"code_verifier": {verifier},
		"client_id":     {kiteAPIKey},
		"client_secret": {kiteAPISecret},
	}
	tokenReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRR := httptest.NewRecorder()

	h.Token(tokenRR, tokenReq)

	if tokenRR.Code != http.StatusOK {
		t.Fatalf("Token status = %d, want 200. Body: %s", tokenRR.Code, tokenRR.Body.String())
	}

	var tokenResp map[string]interface{}
	if err := json.Unmarshal(tokenRR.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("Failed to decode token response: %v", err)
	}

	// Step 6: Verify JWT contains the correct email
	accessToken := tokenResp["access_token"].(string)
	claims, err := h.jwt.ValidateToken(accessToken)
	if err != nil {
		t.Fatalf("Returned JWT is invalid: %v", err)
	}
	if claims.Subject != "deferred@test.com" {
		t.Errorf("JWT Subject = %q, want %q", claims.Subject, "deferred@test.com")
	}
}

// --- Token endpoint: credential store fallback ---

func TestToken_CredentialStoreFallback(t *testing.T) {
	t.Parallel()

	kiteAPIKey := "fallback-kite-api-key"
	storedSecret := "stored-kite-api-secret"

	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.getSecretByAPIKey = func(apiKey string) (string, bool) {
			if apiKey == kiteAPIKey {
				return storedSecret, true
			}
			return "", false
		}
		exchanger.exchangeWithCreds = func(requestToken, apiKey, apiSecret string) (string, error) {
			if apiKey == kiteAPIKey && apiSecret == storedSecret && requestToken == "fallback-request-token" {
				return "fallback@test.com", nil
			}
			return "", fmt.Errorf("invalid credentials: apiKey=%s apiSecret=%s", apiKey, apiSecret)
		}
	})
	defer h.Close()

	// Register as Kite client
	h.clients.RegisterKiteClient(kiteAPIKey, []string{"https://example.com/callback"})

	verifier := "fallback-verifier-value"
	challenge := pkceChallenge(verifier)

	// Generate auth code with RequestToken (deferred exchange)
	code, err := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      kiteAPIKey,
		CodeChallenge: challenge,
		RedirectURI:   "https://example.com/callback",
		RequestToken:  "fallback-request-token",
	})
	if err != nil {
		t.Fatalf("Generate auth code failed: %v", err)
	}

	// Call Token WITHOUT client_secret — should fall back to credential store
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {kiteAPIKey},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.Token(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want 200. Body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	accessToken := resp["access_token"].(string)
	claims, err := h.jwt.ValidateToken(accessToken)
	if err != nil {
		t.Fatalf("Returned JWT is invalid: %v", err)
	}
	if claims.Subject != "fallback@test.com" {
		t.Errorf("JWT Subject = %q, want %q", claims.Subject, "fallback@test.com")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// --- HandleLoginChoice ---

func TestHandleLoginChoice_GET_NoCookie(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/login?redirect=/dashboard", nil)
	rr := httptest.NewRecorder()

	h.HandleLoginChoice(rr, req)

	// Should render the login choice page (200).
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Sign In") && !strings.Contains(body, "sign") {
		// Template should render some form content.
		if len(body) == 0 {
			t.Error("Body should not be empty")
		}
	}
}

func TestHandleLoginChoice_GET_ValidCookie(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Generate a valid dashboard token
	token, err := h.jwt.GenerateToken("user@test.com", "dashboard")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/login?redirect=/admin/ops", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	rr := httptest.NewRecorder()

	h.HandleLoginChoice(rr, req)

	// Should redirect since the user already has a valid cookie.
	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (valid cookie should redirect)", rr.Code)
	}
	location := rr.Header().Get("Location")
	if location != "/admin/ops" {
		t.Errorf("Location = %q, want /admin/ops", location)
	}
}

func TestHandleLoginChoice_GET_InvalidCookie(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/login?redirect=/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: "invalid-jwt"})
	rr := httptest.NewRecorder()

	h.HandleLoginChoice(rr, req)

	// Invalid cookie should render the login page (200).
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (invalid cookie should show login)", rr.Code)
	}
}

func TestHandleLoginChoice_DefaultRedirect_HandlersFile(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Generate a valid dashboard token.
	token, _ := h.jwt.GenerateToken("user@test.com", "dashboard")

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	rr := httptest.NewRecorder()

	h.HandleLoginChoice(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302", rr.Code)
	}
	location := rr.Header().Get("Location")
	if location != "/dashboard" {
		t.Errorf("Location = %q, want /dashboard (default redirect)", location)
	}
}

// --- HandleAdminLogin ---

func TestHandleAdminLogin_GET(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/admin-login?redirect=/admin/ops", nil)
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	// Should render the admin login form.
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
}

func TestHandleAdminLogin_POST_MissingCSRF(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"email":    {"admin@test.com"},
		"password": {"secret"},
		"redirect": {"/admin/ops"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	// Should re-render the form (200) due to missing CSRF.
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (CSRF check re-renders form)", rr.Code)
	}
}

func TestHandleAdminLogin_POST_NoUserStore(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Set valid CSRF cookie + form value.
	form := url.Values{
		"email":      {"admin@test.com"},
		"password":   {"secret"},
		"redirect":   {"/admin/ops"},
		"csrf_token": {"test-csrf-value"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: "test-csrf-value"})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	// No user store configured — should re-render form with error.
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (no user store)", rr.Code)
	}
}

func TestHandleAdminLogin_DefaultRedirect(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// GET with no redirect param — should default to /admin/ops.
	req := httptest.NewRequest(http.MethodGet, "/auth/admin-login", nil)
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
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

// --- recoverOAuthState ---

func TestRecoverOAuthState_EmptyString(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	_, ok := h.recoverOAuthState("")
	if ok {
		t.Error("recoverOAuthState should return false for empty string")
	}
}

func TestRecoverOAuthState_InvalidSignature(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	_, ok := h.recoverOAuthState("invalid-signed-data")
	if ok {
		t.Error("recoverOAuthState should return false for invalid signature")
	}
}

func TestRecoverOAuthState_InvalidBase64(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		signer.verifyFunc = func(signed string) (string, error) {
			// Return invalid base64
			return "not-base64!@#$%^", nil
		}
	})
	defer h.Close()

	_, ok := h.recoverOAuthState("some-signed-value")
	if ok {
		t.Error("recoverOAuthState should return false for invalid base64")
	}
}

func TestRecoverOAuthState_InvalidJSON(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		signer.verifyFunc = func(signed string) (string, error) {
			// Return valid base64 but invalid JSON
			return base64.URLEncoding.EncodeToString([]byte("not json")), nil
		}
	})
	defer h.Close()

	_, ok := h.recoverOAuthState("some-signed-value")
	if ok {
		t.Error("recoverOAuthState should return false for invalid JSON")
	}
}

func TestRecoverOAuthState_ValidRoundTrip(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	state := oauthState{
		ClientID:      "client-123",
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: "abc123",
	}

	stateJSON, _ := json.Marshal(state)
	encoded := base64.URLEncoding.EncodeToString(stateJSON)
	signed := h.signer.Sign(encoded)

	recovered, ok := h.recoverOAuthState(signed)
	if !ok {
		t.Fatal("recoverOAuthState should return true for valid state")
	}
	if recovered.ClientID != "client-123" {
		t.Errorf("ClientID = %q, want %q", recovered.ClientID, "client-123")
	}
	if recovered.RedirectURI != "https://example.com/callback" {
		t.Errorf("RedirectURI = %q, want %q", recovered.RedirectURI, "https://example.com/callback")
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

// --- AuthCodeStore additional edge cases ---

func TestAuthCodeStore_ConsumeExpiredCode(t *testing.T) {
	t.Parallel()
	store := NewAuthCodeStore()
	defer store.Close()

	code, err := store.Generate(&AuthCodeEntry{
		ClientID: "client",
		Email:    "user@test.com",
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Manually expire the entry.
	store.mu.Lock()
	if entry, ok := store.entries[code]; ok {
		entry.ExpiresAt = time.Now().Add(-1 * time.Minute)
	}
	store.mu.Unlock()

	// Consume should fail for expired code.
	_, ok := store.Consume(code)
	if ok {
		t.Error("Consume should fail for expired code")
	}
}

func TestAuthCodeStore_Full(t *testing.T) {
	t.Parallel()
	store := &AuthCodeStore{
		entries: make(map[string]*AuthCodeEntry),
		done:    make(chan struct{}),
	}
	defer store.Close()

	// Fill the store to capacity.
	for i := 0; i < maxAuthCodes; i++ {
		store.entries[fmt.Sprintf("code-%d", i)] = &AuthCodeEntry{
			ExpiresAt: time.Now().Add(10 * time.Minute),
		}
	}

	// Next Generate should fail.
	_, err := store.Generate(&AuthCodeEntry{ClientID: "overflow"})
	if err != ErrAuthCodeStoreFull {
		t.Errorf("Expected ErrAuthCodeStoreFull, got %v", err)
	}
}

// --- ClientStore eviction ---

func TestClientStore_EvictOldest(t *testing.T) {
	t.Parallel()
	store := NewClientStore()

	// Fill the store to capacity with known clients.
	for i := 0; i < maxClients; i++ {
		store.mu.Lock()
		store.clients[fmt.Sprintf("client-%06d", i)] = &ClientEntry{
			ClientName: fmt.Sprintf("Client %d", i),
			CreatedAt:  time.Now().Add(time.Duration(i) * time.Second),
		}
		store.mu.Unlock()
	}

	// Register one more — should evict the oldest (client-000000).
	id, secret, err := store.Register([]string{"https://example.com/cb"}, "NewClient")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if id == "" || secret == "" {
		t.Error("Register should return non-empty id and secret")
	}

	// The oldest client should have been evicted.
	store.mu.RLock()
	_, exists := store.clients["client-000000"]
	store.mu.RUnlock()
	if exists {
		t.Error("Oldest client should have been evicted")
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
