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

// --- Well-Known Metadata ---


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


// HandleKiteOAuthCallback — immediate exchange (returning user SSO)
func TestHandleKiteOAuthCallback_ImmediateExchange(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.getSecretByAPIKey = func(apiKey string) (string, bool) {
			return "stored-api-secret", true
		}
		e.exchangeWithCreds = func(requestToken, apiKey, apiSecret string) (string, error) {
			return "returning@example.com", nil
		}
	})
	defer h.Close()

	h.clients.RegisterKiteClient("kite-returning-key", []string{"http://localhost:3000/callback"})

	stateData := oauthState{
		ClientID:      "kite-returning-key",
		CodeChallenge: "test-challenge",
		RedirectURI:   "http://localhost:3000/callback",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	reqURL := "/callback?flow=oauth&data=" + url.QueryEscape(signedState)
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	rr := httptest.NewRecorder()
	h.HandleKiteOAuthCallback(rr, req, "valid-request-token")

	// Handler serves a success HTML page (200) with auto-redirect, or 302 if template is nil
	if rr.Code != http.StatusOK && rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 200 or 302; body snippet = %.200s", rr.Code, rr.Body.String())
	}
	// Verify the response contains the auth code (in HTML body or Location header)
	body := rr.Body.String()
	loc := rr.Header().Get("Location")
	if !strings.Contains(body, "code=") && !strings.Contains(loc, "code=") {
		t.Errorf("Expected auth code in response body or Location header")
	}
}


// HandleKiteOAuthCallback — immediate exchange fails, falls back to deferred
func TestHandleKiteOAuthCallback_ImmediateExchangeFails_DeferredFallback(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.getSecretByAPIKey = func(apiKey string) (string, bool) {
			return "stale-secret", true
		}
		e.exchangeWithCreds = func(requestToken, apiKey, apiSecret string) (string, error) {
			return "", fmt.Errorf("stale credentials")
		}
	})
	defer h.Close()

	h.clients.RegisterKiteClient("kite-stale-key", []string{"http://localhost:3000/callback"})

	stateData := oauthState{
		ClientID:      "kite-stale-key",
		CodeChallenge: "test-challenge",
		RedirectURI:   "http://localhost:3000/callback",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	reqURL := "/callback?flow=oauth&data=" + url.QueryEscape(signedState)
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	rr := httptest.NewRecorder()
	h.HandleKiteOAuthCallback(rr, req, "valid-request-token")

	// Deferred fallback still serves a success page or redirect
	if rr.Code != http.StatusOK && rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 200 or 302 (deferred fallback); body snippet = %.200s", rr.Code, rr.Body.String())
	}
}


// ---------------------------------------------------------------------------
// handlers.go:552-556, 569-573, 602-606, 623-627 — authCodes.Generate fails
// (auth code store full)
// ---------------------------------------------------------------------------
func TestHandleKiteOAuthCallback_StoreFullNormalFlow_Push100(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.exchangeFunc = func(rt string) (string, error) {
			return "user@test.com", nil
		}
	})
	defer h.Close()

	// Fill the auth code store to capacity
	h.authCodes.mu.Lock()
	for i := 0; i < maxAuthCodes; i++ {
		h.authCodes.entries[fmt.Sprintf("code-%d", i)] = &AuthCodeEntry{
			ClientID:  "test",
			ExpiresAt: time.Now().Add(10 * time.Minute),
		}
	}
	h.authCodes.mu.Unlock()

	// Register a standard (non-Kite) client
	clientID, _, _ := h.clients.Register([]string{"http://localhost/cb"}, "test")
	stateData := oauthState{
		ClientID:      clientID,
		RedirectURI:   "http://localhost/cb",
		CodeChallenge: "challenge",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	req := httptest.NewRequest(http.MethodGet,
		"/callback?request_token=tok&data="+url.QueryEscape(signedState), nil)
	rr := httptest.NewRecorder()

	h.HandleKiteOAuthCallback(rr, req, "tok")

	// Lines 623-627: auth code store full
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// handlers.go:552-556 — immediate exchange path, store full
// ---------------------------------------------------------------------------
func TestHandleKiteOAuthCallback_StoreFullImmediateExchange_Push100(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.getSecretByAPIKey = func(apiKey string) (string, bool) {
			return "secret", true
		}
		e.exchangeWithCreds = func(rt, ak, as string) (string, error) {
			return "user@test.com", nil // immediate exchange succeeds
		}
	})
	defer h.Close()

	// Fill auth code store
	h.authCodes.mu.Lock()
	for i := 0; i < maxAuthCodes; i++ {
		h.authCodes.entries[fmt.Sprintf("code-%d", i)] = &AuthCodeEntry{
			ClientID:  "test",
			ExpiresAt: time.Now().Add(10 * time.Minute),
		}
	}
	h.authCodes.mu.Unlock()

	// Register as Kite key client
	kiteKey := "kite-api-key-test"
	h.clients.RegisterKiteClient(kiteKey, []string{"http://localhost/cb"})

	stateData := oauthState{
		ClientID:      kiteKey,
		RedirectURI:   "http://localhost/cb",
		CodeChallenge: "challenge",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	req := httptest.NewRequest(http.MethodGet,
		"/callback?request_token=tok&data="+url.QueryEscape(signedState), nil)
	rr := httptest.NewRecorder()

	h.HandleKiteOAuthCallback(rr, req, "tok")

	// Lines 552-556: generate error on immediate path
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// handlers.go:569-573 — deferred exchange path, store full
// ---------------------------------------------------------------------------
func TestHandleKiteOAuthCallback_StoreFullDeferredExchange_Push100(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.getSecretByAPIKey = func(apiKey string) (string, bool) {
			return "old-secret", true
		}
		e.exchangeWithCreds = func(rt, ak, as string) (string, error) {
			return "", fmt.Errorf("stale") // immediate fails
		}
	})
	defer h.Close()

	// Fill auth code store
	h.authCodes.mu.Lock()
	for i := 0; i < maxAuthCodes; i++ {
		h.authCodes.entries[fmt.Sprintf("code-%d", i)] = &AuthCodeEntry{
			ClientID:  "test",
			ExpiresAt: time.Now().Add(10 * time.Minute),
		}
	}
	h.authCodes.mu.Unlock()

	kiteKey := "kite-api-key-deferred"
	h.clients.RegisterKiteClient(kiteKey, []string{"http://localhost/cb"})

	stateData := oauthState{
		ClientID:      kiteKey,
		RedirectURI:   "http://localhost/cb",
		CodeChallenge: "challenge",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	req := httptest.NewRequest(http.MethodGet,
		"/callback?request_token=tok&data="+url.QueryEscape(signedState), nil)
	rr := httptest.NewRecorder()

	h.HandleKiteOAuthCallback(rr, req, "tok")

	// Lines 569-573: generate error on deferred path
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// handlers.go:602-606 — registry flow, store full
// ---------------------------------------------------------------------------
func TestHandleKiteOAuthCallback_StoreFullRegistryFlow_Push100(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.exchangeWithCreds = func(rt, ak, as string) (string, error) {
			return "user@test.com", nil
		}
	})
	defer h.Close()

	h.registry = &mockRegistry{
		entries: map[string]*RegistryEntry{
			"user@test.com": {APIKey: "registry-key-1234567890", APISecret: "registry-secret"},
		},
	}

	// Fill auth code store
	h.authCodes.mu.Lock()
	for i := 0; i < maxAuthCodes; i++ {
		h.authCodes.entries[fmt.Sprintf("code-%d", i)] = &AuthCodeEntry{
			ClientID:  "test",
			ExpiresAt: time.Now().Add(10 * time.Minute),
		}
	}
	h.authCodes.mu.Unlock()

	clientID, _, _ := h.clients.Register([]string{"http://localhost/cb"}, "test")
	stateData := oauthState{
		ClientID:      clientID,
		RedirectURI:   "http://localhost/cb",
		CodeChallenge: "challenge",
		RegistryKey:   "registry-key-1234567890",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	req := httptest.NewRequest(http.MethodGet,
		"/callback?request_token=tok&data="+url.QueryEscape(signedState), nil)
	rr := httptest.NewRecorder()

	h.HandleKiteOAuthCallback(rr, req, "tok")

	// Lines 602-606: generate error on registry path
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// handlers.go — HandleKiteOAuthCallback: registry flow, exchange fails (lines 591-594)
// ---------------------------------------------------------------------------
func TestHandleKiteOAuthCallback_RegistryFlowExchangeFails_Push100(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.exchangeWithCreds = func(rt, ak, as string) (string, error) {
			return "", fmt.Errorf("kite exchange failed")
		}
	})
	defer h.Close()

	h.registry = &mockRegistry{
		entries: map[string]*RegistryEntry{
			"user@test.com": {APIKey: "reg-key-1234567890", APISecret: "reg-secret"},
		},
	}

	clientID, _, _ := h.clients.Register([]string{"http://localhost/cb"}, "test")
	stateData := oauthState{
		ClientID:      clientID,
		RedirectURI:   "http://localhost/cb",
		CodeChallenge: "challenge",
		RegistryKey:   "reg-key-1234567890",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	req := httptest.NewRequest(http.MethodGet,
		"/callback?request_token=tok&data="+url.QueryEscape(signedState), nil)
	rr := httptest.NewRecorder()

	h.HandleKiteOAuthCallback(rr, req, "tok")

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 (registry exchange failed)", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// handlers.go — HandleKiteOAuthCallback: registry flow, no registry secret (lines 585-588)
// ---------------------------------------------------------------------------
func TestHandleKiteOAuthCallback_RegistryFlowNoRegistrySecret_Push100(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Registry with no matching API key
	h.registry = &mockRegistry{
		entries: map[string]*RegistryEntry{
			"other@test.com": {APIKey: "other-key-12345678", APISecret: "other-secret"},
		},
	}

	clientID, _, _ := h.clients.Register([]string{"http://localhost/cb"}, "test")
	stateData := oauthState{
		ClientID:      clientID,
		RedirectURI:   "http://localhost/cb",
		CodeChallenge: "challenge",
		RegistryKey:   "nonexistent-key-123",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	req := httptest.NewRequest(http.MethodGet,
		"/callback?request_token=tok&data="+url.QueryEscape(signedState), nil)
	rr := httptest.NewRecorder()

	h.HandleKiteOAuthCallback(rr, req, "tok")

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 (no registry secret)", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// handlers.go — HandleKiteOAuthCallback: Kite key immediate success + SSO cookie (lines 530-558)
// ---------------------------------------------------------------------------
func TestHandleKiteOAuthCallback_KiteKeyImmediateSuccess_Push100(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.getSecretByAPIKey = func(apiKey string) (string, bool) {
			return "api-secret", true
		}
		e.exchangeWithCreds = func(rt, ak, as string) (string, error) {
			return "user@test.com", nil
		}
	})
	defer h.Close()

	kiteKey := "kite-api-key-imm"
	h.clients.RegisterKiteClient(kiteKey, []string{"http://localhost/cb"})

	stateData := oauthState{
		ClientID:      kiteKey,
		RedirectURI:   "http://localhost/cb",
		CodeChallenge: "challenge",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	req := httptest.NewRequest(http.MethodGet,
		"/callback?request_token=tok&data="+url.QueryEscape(signedState), nil)
	rr := httptest.NewRecorder()

	h.HandleKiteOAuthCallback(rr, req, "tok")

	// Success: renders login success page (200) or redirects (302)
	if rr.Code != http.StatusOK && rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 200 or 302 (immediate exchange success)", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// handlers.go — HandleKiteOAuthCallback: Kite key immediate fails → deferred succeeds (lines 539-574)
// ---------------------------------------------------------------------------
func TestHandleKiteOAuthCallback_KiteKeyFallbackDeferred_Push100(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, s *mockSigner, e *mockExchanger) {
		e.getSecretByAPIKey = func(apiKey string) (string, bool) {
			return "stale-secret", true
		}
		e.exchangeWithCreds = func(rt, ak, as string) (string, error) {
			return "", fmt.Errorf("stale credentials")
		}
	})
	defer h.Close()

	kiteKey := "kite-api-key-deferred2"
	h.clients.RegisterKiteClient(kiteKey, []string{"http://localhost/cb"})

	stateData := oauthState{
		ClientID:      kiteKey,
		RedirectURI:   "http://localhost/cb",
		CodeChallenge: "challenge",
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	req := httptest.NewRequest(http.MethodGet,
		"/callback?request_token=tok&data="+url.QueryEscape(signedState), nil)
	rr := httptest.NewRecorder()

	h.HandleKiteOAuthCallback(rr, req, "tok")

	// Deferred path: auth code stored with RequestToken, renders success page (200)
	// or redirects (302) depending on template availability
	if rr.Code != http.StatusOK && rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 200 or 302 (deferred exchange)", rr.Code)
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
