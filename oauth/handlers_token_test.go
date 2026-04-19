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

)

// --- Well-Known Metadata ---


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

	var resp map[string]any
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
	var regResp map[string]any
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
	var tokenResp map[string]any
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

	var resp map[string]any
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


// ===========================================================================
// Token — various error paths
// ===========================================================================
func TestToken_MethodNotAllowed_Final(t *testing.T) {
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


func TestToken_UnsupportedGrantType_Final(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"grant_type": {"client_credentials"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}


func TestToken_MissingParams_Final(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"grant_type": {"authorization_code"},
		// missing code, code_verifier, client_id
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}


func TestToken_InvalidClient(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"some-code"},
		"code_verifier": {"some-verifier"},
		"client_id":     {"nonexistent-client"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want 401", rr.Code)
	}
}


func TestToken_WrongClientSecret(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	clientID, _, _ := h.clients.Register([]string{"https://example.com/cb"}, "test")

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
}


func TestToken_InvalidAuthCode(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	clientID, clientSecret, _ := h.clients.Register([]string{"https://example.com/cb"}, "test")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"invalid-code"},
		"code_verifier": {"some-verifier"},
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


func TestToken_PKCEVerificationFailure(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	clientID, clientSecret, _ := h.clients.Register([]string{"https://example.com/cb"}, "test")
	challenge := pkceChallenge("real-verifier")

	code, _ := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      clientID,
		CodeChallenge: challenge,
		RedirectURI:   "https://example.com/cb",
		Email:         "user@example.com",
	})

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
		t.Errorf("Status = %d, want 400 (PKCE failure)", rr.Code)
	}
}


func TestToken_ClientIDMismatch_Final(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	clientID1, clientSecret1, _ := h.clients.Register([]string{"https://example.com/cb"}, "test1")
	clientID2, _, _ := h.clients.Register([]string{"https://example.com/cb"}, "test2")

	verifier := "my-verifier-12345"
	challenge := pkceChallenge(verifier)

	// Issue code for clientID2
	code, _ := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      clientID2,
		CodeChallenge: challenge,
		RedirectURI:   "https://example.com/cb",
		Email:         "user@example.com",
	})

	// Try to exchange with clientID1
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {clientID1},
		"client_secret": {clientSecret1},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (client_id mismatch)", rr.Code)
	}
}


func TestToken_SuccessfulExchange(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	clientID, clientSecret, _ := h.clients.Register([]string{"https://example.com/cb"}, "test")
	verifier := "test-verifier-string"
	challenge := pkceChallenge(verifier)

	code, _ := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      clientID,
		CodeChallenge: challenge,
		RedirectURI:   "https://example.com/cb",
		Email:         "user@example.com",
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

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want 200", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("JSON decode error: %v", err)
	}
	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Error("Expected non-empty access_token")
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", resp["token_type"])
	}
}


// ===========================================================================
// Token — deferred exchange with Kite API key client
// ===========================================================================
func TestToken_DeferredExchange_NoSecret(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.getSecretByAPIKey = func(apiKey string) (string, bool) {
			return "", false // no stored secret
		}
	})
	defer h.Close()

	kiteAPIKey := "kite-api-key-12345"
	h.clients.RegisterKiteClient(kiteAPIKey, []string{"https://example.com/cb"})

	verifier := "test-verifier"
	challenge := pkceChallenge(verifier)

	code, _ := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      kiteAPIKey,
		CodeChallenge: challenge,
		RedirectURI:   "https://example.com/cb",
		RequestToken:  "kite-request-token",
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {kiteAPIKey},
		// no client_secret
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (no secret for deferred exchange)", rr.Code)
	}
}


func TestToken_DeferredExchange_ExchangeFails(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.getSecretByAPIKey = func(apiKey string) (string, bool) {
			return "stored-secret", true
		}
		exchanger.exchangeWithCreds = func(requestToken, apiKey, apiSecret string) (string, error) {
			return "", fmt.Errorf("kite auth failed")
		}
	})
	defer h.Close()

	kiteAPIKey := "kite-api-key-fail"
	h.clients.RegisterKiteClient(kiteAPIKey, []string{"https://example.com/cb"})

	verifier := "test-verifier"
	challenge := pkceChallenge(verifier)

	code, _ := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      kiteAPIKey,
		CodeChallenge: challenge,
		RedirectURI:   "https://example.com/cb",
		RequestToken:  "kite-request-token",
	})

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

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (exchange failed)", rr.Code)
	}
}


// ===========================================================================
// Token — deferred exchange success with stored secret
// ===========================================================================
func TestToken_DeferredExchange_Success(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.getSecretByAPIKey = func(apiKey string) (string, bool) {
			return "stored-secret", true
		}
		exchanger.exchangeWithCreds = func(requestToken, apiKey, apiSecret string) (string, error) {
			return "deferred-user@example.com", nil
		}
	})
	defer h.Close()

	kiteAPIKey := "kite-api-key-ok"
	h.clients.RegisterKiteClient(kiteAPIKey, []string{"https://example.com/cb"})

	verifier := "test-verifier"
	challenge := pkceChallenge(verifier)

	code, _ := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      kiteAPIKey,
		CodeChallenge: challenge,
		RedirectURI:   "https://example.com/cb",
		RequestToken:  "kite-request-token",
	})

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
		t.Fatalf("Status = %d, want 200", rr.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Error("Expected non-empty access_token from deferred exchange")
	}
}


// ===========================================================================
// Coverage push — deeper handler paths
// ===========================================================================

// Token with deferred exchange (ExchangeWithCredentials via stored secret)
func TestToken_DeferredExchange_ViaStoredSecret(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.exchangeWithCreds = func(requestToken, apiKey, apiSecret string) (string, error) {
			return "deferred@example.com", nil
		}
		e.getSecretByAPIKey = func(apiKey string) (string, bool) {
			return "stored-secret", true
		}
	})
	defer h.Close()

	// Register a Kite client
	h.clients.RegisterKiteClient("kite-api-key", []string{"http://localhost:3000/callback"})

	// Generate auth code with RequestToken (deferred exchange scenario)
	verifier := "test-verifier-for-deferred-exchange"
	challenge := pkceChallenge(verifier)
	code, err := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      "kite-api-key",
		CodeChallenge: challenge,
		RedirectURI:   "http://localhost:3000/callback",
		RequestToken:  "kite-request-token-123",
	})
	if err != nil {
		t.Fatalf("Generate auth code: %v", err)
	}

	// Exchange — no client_secret in request, should use stored secret
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {"kite-api-key"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}
}


// Token deferred exchange where ExchangeWithCredentials fails (via stored secret)
func TestToken_DeferredExchange_ExchangeFails_ViaStoredSecret(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.exchangeWithCreds = func(requestToken, apiKey, apiSecret string) (string, error) {
			return "", fmt.Errorf("kite rejected token")
		}
		e.getSecretByAPIKey = func(apiKey string) (string, bool) {
			return "stored-secret", true
		}
	})
	defer h.Close()

	h.clients.RegisterKiteClient("kite-fail-key", []string{"http://localhost:3000/callback"})
	verifier := "test-verifier-deferred-fail"
	challenge := pkceChallenge(verifier)
	code, _ := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      "kite-fail-key",
		CodeChallenge: challenge,
		RedirectURI:   "http://localhost:3000/callback",
		RequestToken:  "invalid-token",
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {"kite-fail-key"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400; body = %s", rr.Code, rr.Body.String())
	}
}


// Token deferred exchange — no stored secret, no client_secret in request (coverage push)
func TestToken_DeferredExchange_NoSecret_Push(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.getSecretByAPIKey = func(apiKey string) (string, bool) {
			return "", false // no stored secret
		}
	})
	defer h.Close()

	h.clients.RegisterKiteClient("kite-no-secret-key", []string{"http://localhost:3000/callback"})
	verifier := "test-verifier-no-secret"
	challenge := pkceChallenge(verifier)
	code, _ := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      "kite-no-secret-key",
		CodeChallenge: challenge,
		RedirectURI:   "http://localhost:3000/callback",
		RequestToken:  "req-token",
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {"kite-no-secret-key"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400; body = %s", rr.Code, rr.Body.String())
	}
}


// Token where resolved email is empty
func TestToken_DeferredExchange_EmptyEmail(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.exchangeWithCreds = func(requestToken, apiKey, apiSecret string) (string, error) {
			return "", nil // empty email, no error
		}
		e.getSecretByAPIKey = func(apiKey string) (string, bool) {
			return "secret", true
		}
	})
	defer h.Close()

	h.clients.RegisterKiteClient("kite-empty-email", []string{"http://localhost:3000/callback"})
	verifier := "test-verifier-empty"
	challenge := pkceChallenge(verifier)
	code, _ := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      "kite-empty-email",
		CodeChallenge: challenge,
		RedirectURI:   "http://localhost:3000/callback",
		RequestToken:  "req-tok",
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {"kite-empty-email"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500; body = %s", rr.Code, rr.Body.String())
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
