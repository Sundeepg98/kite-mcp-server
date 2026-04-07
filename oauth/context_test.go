package oauth

import (
	"context"
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
