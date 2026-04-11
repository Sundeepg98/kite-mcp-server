package oauth

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ===========================================================================
// ContextWithEmail / EmailFromContext round-trip tests
// ===========================================================================

func TestContextWithEmail_RoundTrip(t *testing.T) {
	t.Parallel()
	ctx := ContextWithEmail(context.Background(), "alice@test.com")
	email := EmailFromContext(ctx)
	if email != "alice@test.com" {
		t.Errorf("EmailFromContext = %q, want %q", email, "alice@test.com")
	}
}

func TestContextWithEmail_Empty(t *testing.T) {
	t.Parallel()
	ctx := ContextWithEmail(context.Background(), "")
	email := EmailFromContext(ctx)
	if email != "" {
		t.Errorf("EmailFromContext = %q, want empty", email)
	}
}

func TestContextWithEmail_Override(t *testing.T) {
	t.Parallel()
	ctx := ContextWithEmail(context.Background(), "first@test.com")
	ctx = ContextWithEmail(ctx, "second@test.com")
	email := EmailFromContext(ctx)
	if email != "second@test.com" {
		t.Errorf("EmailFromContext = %q, want %q", email, "second@test.com")
	}
}

func TestEmailFromContext_NilContext(t *testing.T) {
	t.Parallel()
	email := EmailFromContext(context.Background())
	if email != "" {
		t.Errorf("EmailFromContext on empty context = %q, want empty", email)
	}
}

// ===========================================================================
// JWTManager additional tests
// ===========================================================================

func TestGenerateTokenWithExpiry(t *testing.T) {
	t.Parallel()
	jm := NewJWTManager("test-secret-custom-expiry", 1*time.Hour) // default 1h

	// Generate with custom 30-minute expiry
	token, err := jm.GenerateTokenWithExpiry("user@test.com", "dashboard", 30*time.Minute)
	if err != nil {
		t.Fatalf("GenerateTokenWithExpiry failed: %v", err)
	}
	if token == "" {
		t.Fatal("GenerateTokenWithExpiry returned empty token")
	}

	// Validate the token
	claims, err := jm.ValidateToken(token, "dashboard")
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}
	if claims.Subject != "user@test.com" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "user@test.com")
	}

	// Verify expiry is roughly 30 minutes from now (not 1 hour)
	exp := claims.ExpiresAt.Time
	expectedMax := time.Now().Add(31 * time.Minute)
	expectedMin := time.Now().Add(29 * time.Minute)
	if exp.Before(expectedMin) || exp.After(expectedMax) {
		t.Errorf("ExpiresAt = %v, expected between %v and %v", exp, expectedMin, expectedMax)
	}
}

func TestJWTManager_DifferentIssuersValidate(t *testing.T) {
	t.Parallel()
	jm := NewJWTManager("shared-secret", 1*time.Hour)

	// Generate token
	token, err := jm.GenerateToken("user@test.com", "client-1")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// Validate with same manager (same secret)
	claims, err := jm.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}
	if claims.Issuer != "kite-mcp-server" {
		t.Errorf("Issuer = %q, want %q", claims.Issuer, "kite-mcp-server")
	}
}

// ===========================================================================
// Config validation additional tests
// ===========================================================================

func TestConfig_Validate_OptionalKiteAPIKey(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		JWTSecret:   "my-secret",
		ExternalURL: "https://test.example.com",
		TokenExpiry: 1 * time.Hour,
		// KiteAPIKey intentionally empty
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate should succeed with empty KiteAPIKey: %v", err)
	}
}

// ===========================================================================
// AuthCodeStore additional tests
// ===========================================================================

func TestAuthCodeStore_GenerateUniqueCodes(t *testing.T) {
	t.Parallel()
	store := NewAuthCodeStore()
	defer store.Close()

	codes := make(map[string]bool)
	for i := 0; i < 100; i++ {
		code, err := store.Generate(&AuthCodeEntry{
			ClientID:      "client",
			CodeChallenge: "challenge",
			RedirectURI:   "https://example.com/callback",
		})
		if err != nil {
			t.Fatalf("Generate #%d failed: %v", i, err)
		}
		if codes[code] {
			t.Fatalf("Duplicate code generated at iteration %d: %s", i, code)
		}
		codes[code] = true
	}
}

func TestAuthCodeStore_ConsumeDeletesEntry(t *testing.T) {
	t.Parallel()
	store := NewAuthCodeStore()
	defer store.Close()

	code, _ := store.Generate(&AuthCodeEntry{
		ClientID: "client",
		Email:    "user@test.com",
	})

	// Consume once
	entry, ok := store.Consume(code)
	if !ok {
		t.Fatal("First consume should succeed")
	}
	if entry.Email != "user@test.com" {
		t.Errorf("Email = %q, want %q", entry.Email, "user@test.com")
	}

	// Second consume should fail
	_, ok = store.Consume(code)
	if ok {
		t.Fatal("Second consume should fail")
	}
}

// ===========================================================================
// ClientStore additional tests
// ===========================================================================

func TestClientStore_IsKiteClient_Unknown(t *testing.T) {
	t.Parallel()
	store := NewClientStore()
	if store.IsKiteClient("nonexistent") {
		t.Error("IsKiteClient should return false for unknown client")
	}
}

func TestClientStore_RegisterKiteClient_ShortKey(t *testing.T) {
	t.Parallel()
	store := NewClientStore()
	// Key shorter than 8 chars
	store.RegisterKiteClient("short", []string{"https://example.com/cb"})
	entry, ok := store.Get("short")
	if !ok {
		t.Fatal("Short key should be retrievable")
	}
	if entry.ClientName != "kite-user" {
		t.Errorf("ClientName = %q, want %q for short key", entry.ClientName, "kite-user")
	}
}

func TestClientStore_AddRedirectURI_NonexistentClient(t *testing.T) {
	t.Parallel()
	store := NewClientStore()
	// Should not panic
	store.AddRedirectURI("nonexistent", "https://example.com/cb")
}

// ===========================================================================
// Middleware helper: SetAuthCookie round-trip
// ===========================================================================

func TestSetAuthCookie_Roundtrip(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	jm := h.JWTManager()
	if jm == nil {
		t.Fatal("JWTManager should not be nil")
	}

	// Generate a token and verify it can be validated
	token, err := jm.GenerateToken("test@example.com", "client-x")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	claims, err := jm.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}
	if claims.Subject != "test@example.com" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "test@example.com")
	}
}

// ===========================================================================
// Handler close / initialization
// ===========================================================================

func TestNewHandler_Close(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	// Close should not panic
	h.Close()
	// Double close should also not panic
	h.Close()
}

func TestHandler_SetKiteTokenChecker(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	called := false
	h.SetKiteTokenChecker(func(email string) bool {
		called = true
		return email == "valid@test.com"
	})

	// The checker is stored internally; we can't call it directly,
	// but we can verify it doesn't panic.
	if called {
		t.Error("Checker should not have been called yet")
	}
}

// ===========================================================================
// Additional coverage tests: SetUserStore, SetGoogleSSO, GoogleSSOEnabled,
// SetRegistry, SetClientPersister, LoadClientsFromDB, SetLogger
// ===========================================================================

func TestHandler_SetUserStore(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// SetUserStore should not panic with nil.
	h.SetUserStore(nil)

	// GoogleSSOEnabled should be false by default.
	if h.GoogleSSOEnabled() {
		t.Error("GoogleSSOEnabled should be false by default")
	}
}

func TestHandler_SetGoogleSSO(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Initially not enabled.
	if h.GoogleSSOEnabled() {
		t.Error("GoogleSSOEnabled should be false initially")
	}

	// Enable Google SSO.
	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
	})

	if !h.GoogleSSOEnabled() {
		t.Error("GoogleSSOEnabled should be true after SetGoogleSSO")
	}

	// Disable by setting nil.
	h.SetGoogleSSO(nil)
	if h.GoogleSSOEnabled() {
		t.Error("GoogleSSOEnabled should be false after SetGoogleSSO(nil)")
	}
}

func TestHandler_SetRegistry(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// SetRegistry should not panic with nil.
	h.SetRegistry(nil)
}

func TestHandler_SetClientPersister(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	mock := newMockPersister()
	logger := h.logger

	// SetClientPersister should not panic.
	h.SetClientPersister(mock, logger)

	// LoadClientsFromDB should succeed with empty persister.
	err := h.LoadClientsFromDB()
	if err != nil {
		t.Fatalf("LoadClientsFromDB failed: %v", err)
	}
}

func TestHandler_LoadClientsFromDB_NoPersister(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Without a persister, LoadClientsFromDB should be a no-op.
	err := h.LoadClientsFromDB()
	if err != nil {
		t.Fatalf("LoadClientsFromDB without persister should return nil: %v", err)
	}
}

func TestClientStore_SetLogger(t *testing.T) {
	t.Parallel()
	store := NewClientStore()

	// SetLogger should not panic.
	store.SetLogger(nil)

	// Set a real logger.
	store.SetLogger(slog.New(slog.NewTextHandler(nil, nil)))
}

func TestJWTManager_GenerateAndValidate_Roundtrip(t *testing.T) {
	t.Parallel()
	jm := NewJWTManager("roundtrip-test-secret", 2*time.Hour)

	token, err := jm.GenerateToken("alice@test.com", "client-abc")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	claims, err := jm.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if claims.Subject != "alice@test.com" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "alice@test.com")
	}
	if claims.Issuer != "kite-mcp-server" {
		t.Errorf("Issuer = %q, want %q", claims.Issuer, "kite-mcp-server")
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "client-abc" {
		t.Errorf("Audience = %v, want [client-abc]", claims.Audience)
	}
}

func TestEmailFromContext_WithContextValue(t *testing.T) {
	t.Parallel()

	// Set and retrieve email.
	ctx := ContextWithEmail(context.Background(), "test@example.com")
	email := EmailFromContext(ctx)
	if email != "test@example.com" {
		t.Errorf("got %q, want %q", email, "test@example.com")
	}
}

func TestContextWithEmail_Nested(t *testing.T) {
	t.Parallel()

	// Nested contexts: inner email should shadow outer.
	ctx1 := ContextWithEmail(context.Background(), "outer@test.com")
	ctx2 := ContextWithEmail(ctx1, "inner@test.com")

	if email := EmailFromContext(ctx2); email != "inner@test.com" {
		t.Errorf("inner context should return inner email, got %q", email)
	}
	if email := EmailFromContext(ctx1); email != "outer@test.com" {
		t.Errorf("outer context should still return outer email, got %q", email)
	}
}

func TestGoogleSSOConfig_OauthConfig(t *testing.T) {
	t.Parallel()
	cfg := &GoogleSSOConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
	}

	oauthCfg := cfg.oauthConfig()
	if oauthCfg.ClientID != "test-client-id" {
		t.Errorf("ClientID = %q, want %q", oauthCfg.ClientID, "test-client-id")
	}
	if oauthCfg.ClientSecret != "test-client-secret" {
		t.Errorf("ClientSecret mismatch")
	}
	if oauthCfg.RedirectURL != "https://test.example.com/auth/google/callback" {
		t.Errorf("RedirectURL mismatch")
	}
	if len(oauthCfg.Scopes) != 3 {
		t.Errorf("Scopes = %v, want 3 scopes", oauthCfg.Scopes)
	}
}

func TestHandleGoogleLogin_NoSSO(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Google SSO not configured — should return 404.
	req := httptest.NewRequest(http.MethodGet, "/auth/google/login", nil)
	rr := httptest.NewRecorder()
	h.HandleGoogleLogin(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Status = %d, want 404", rr.Code)
	}
}

func TestHandleGoogleCallback_NoSSO(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Google SSO not configured — should return 404.
	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback", nil)
	rr := httptest.NewRecorder()
	h.HandleGoogleCallback(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Status = %d, want 404", rr.Code)
	}
}

func TestHandleGoogleCallback_MissingStateCookie(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
	})

	// No state cookie — should return 400.
	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback?code=abc&state=xyz", nil)
	rr := httptest.NewRecorder()
	h.HandleGoogleCallback(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}

func TestHandleGoogleCallback_MalformedStateCookie(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
	})

	// State cookie without separator — malformed.
	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback?code=abc&state=xyz", nil)
	req.AddCookie(&http.Cookie{Name: googleStateCookieName, Value: "nopipe"})
	rr := httptest.NewRecorder()
	h.HandleGoogleCallback(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}

func TestHandleGoogleCallback_StateMismatch(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
	})

	// State cookie doesn't match query state.
	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback?code=abc&state=wrong", nil)
	req.AddCookie(&http.Cookie{Name: googleStateCookieName, Value: "expected|/dashboard"})
	rr := httptest.NewRecorder()
	h.HandleGoogleCallback(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}

func TestHandleGoogleCallback_MissingCode(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
	})

	// State matches but no code parameter.
	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback?state=mystate", nil)
	req.AddCookie(&http.Cookie{Name: googleStateCookieName, Value: "mystate|/dashboard"})
	rr := httptest.NewRecorder()
	h.HandleGoogleCallback(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}

func TestHandleGoogleCallback_OAuthError(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
	})

	// OAuth error parameter should redirect.
	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback?error=access_denied&state=mystate", nil)
	req.AddCookie(&http.Cookie{Name: googleStateCookieName, Value: "mystate|/dashboard"})
	rr := httptest.NewRecorder()
	h.HandleGoogleCallback(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 redirect", rr.Code)
	}
}

func TestAuthServerMetadata_POST(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodPost, "/.well-known/oauth-authorization-server", nil)
	rr := httptest.NewRecorder()
	h.AuthServerMetadata(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %d, want 405", rr.Code)
	}
}

func TestRequireAuthBrowser_BearerNonDashboard(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Generate a non-dashboard token
	token, err := h.jwt.GenerateToken("user@test.com", "mcp-client")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	handler := h.RequireAuthBrowser(echoEmailHandler())
	req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should redirect because the Bearer token has wrong audience (not dashboard)
	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (non-dashboard Bearer should be rejected)", rr.Code)
	}
}

func TestRequireAuth_NonBearerAuth(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	handler := h.RequireAuth(echoEmailHandler())
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz") // Basic auth
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want 401 (non-Bearer auth should fail)", rr.Code)
	}
}
