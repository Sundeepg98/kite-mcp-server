package oauth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateToken_Valid(t *testing.T) {
	t.Parallel()
	jm := NewJWTManager("test-secret", 1*time.Hour)
	token, err := jm.GenerateToken("user@example.com", "client-123")
	if err != nil {
		t.Fatalf("GenerateToken returned error: %v", err)
	}
	if token == "" {
		t.Fatal("GenerateToken returned empty token")
	}
}

func TestGenerateToken_ClaimsContent(t *testing.T) {
	t.Parallel()
	jm := NewJWTManager("test-secret", 2*time.Hour)

	before := time.Now()
	token, err := jm.GenerateToken("alice@test.com", "my-client")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
	after := time.Now()

	// Parse without validation to inspect claims
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(token, &Claims{})
	if err != nil {
		t.Fatalf("ParseUnverified failed: %v", err)
	}
	claims := parsed.Claims.(*Claims)

	if claims.Subject != "alice@test.com" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "alice@test.com")
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "my-client" {
		t.Errorf("Audience = %v, want [my-client]", claims.Audience)
	}
	if claims.Issuer != "kite-mcp-server" {
		t.Errorf("Issuer = %q, want %q", claims.Issuer, "kite-mcp-server")
	}
	// JWT timestamps are truncated to seconds, so truncate our bounds too
	exp := claims.ExpiresAt.Time
	beforeExp := before.Add(2 * time.Hour).Truncate(time.Second)
	afterExp := after.Add(2 * time.Hour).Truncate(time.Second).Add(time.Second)
	if exp.Before(beforeExp) || exp.After(afterExp) {
		t.Errorf("ExpiresAt = %v, expected between %v and %v", exp, beforeExp, afterExp)
	}
	iat := claims.IssuedAt.Time
	beforeIat := before.Truncate(time.Second)
	afterIat := after.Truncate(time.Second).Add(time.Second)
	if iat.Before(beforeIat) || iat.After(afterIat) {
		t.Errorf("IssuedAt = %v, expected between %v and %v", iat, beforeIat, afterIat)
	}
}

func TestValidateToken_Valid(t *testing.T) {
	t.Parallel()
	jm := NewJWTManager("roundtrip-secret", 1*time.Hour)

	token, err := jm.GenerateToken("bob@test.com", "client-abc")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	claims, err := jm.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}
	if claims.Subject != "bob@test.com" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "bob@test.com")
	}
}

func TestValidateToken_Expired(t *testing.T) {
	t.Parallel()
	jm := NewJWTManager("expired-secret", 1*time.Millisecond)

	token, err := jm.GenerateToken("user@test.com", "client")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// Wait for token to expire
	time.Sleep(10 * time.Millisecond)

	_, err = jm.ValidateToken(token)
	if err == nil {
		t.Fatal("ValidateToken should have failed for expired token")
	}
}

func TestValidateToken_WrongSecret(t *testing.T) {
	t.Parallel()
	jm1 := NewJWTManager("secret-one", 1*time.Hour)
	jm2 := NewJWTManager("secret-two", 1*time.Hour)

	token, err := jm1.GenerateToken("user@test.com", "client")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	_, err = jm2.ValidateToken(token)
	if err == nil {
		t.Fatal("ValidateToken should have failed with wrong secret")
	}
}

func TestValidateToken_InvalidFormat(t *testing.T) {
	t.Parallel()
	jm := NewJWTManager("test-secret", 1*time.Hour)

	cases := []struct {
		name  string
		token string
	}{
		{"empty string", ""},
		{"garbage", "not-a-jwt-token"},
		{"random dots", "a.b.c"},
		{"partial jwt", "eyJhbGciOiJIUzI1NiJ9.garbage.garbage"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := jm.ValidateToken(tc.token)
			if err == nil {
				t.Errorf("ValidateToken(%q) should have returned error", tc.token)
			}
		})
	}
}

func TestValidateToken_WrongAlgorithm(t *testing.T) {
	t.Parallel()
	jm := NewJWTManager("test-secret", 1*time.Hour)

	// Craft a token signed with HS384 (not HS256)
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user@test.com",
			Audience:  jwt.ClaimStrings{"client"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "kite-mcp-server",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS384, claims)
	tokenStr, err := token.SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatalf("Failed to create HS384 token: %v", err)
	}

	_, err = jm.ValidateToken(tokenStr)
	if err == nil {
		t.Fatal("ValidateToken should reject non-HS256 algorithm")
	}
}

func TestValidateToken_AudienceMatch(t *testing.T) {
	t.Parallel()
	jm := NewJWTManager("aud-secret", 1*time.Hour)

	token, err := jm.GenerateToken("user@test.com", "dashboard")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// Validate with matching audience
	claims, err := jm.ValidateToken(token, "dashboard")
	if err != nil {
		t.Fatalf("ValidateToken with matching audience failed: %v", err)
	}
	if claims.Subject != "user@test.com" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "user@test.com")
	}
}

func TestValidateToken_AudienceMismatch(t *testing.T) {
	t.Parallel()
	jm := NewJWTManager("aud-secret", 1*time.Hour)

	token, err := jm.GenerateToken("user@test.com", "dashboard")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// Validate with wrong audience
	_, err = jm.ValidateToken(token, "mcp-client")
	if err == nil {
		t.Fatal("ValidateToken should fail with audience mismatch")
	}
}

func TestValidateToken_MultipleAudiences(t *testing.T) {
	t.Parallel()
	jm := NewJWTManager("multi-aud-secret", 1*time.Hour)

	// Token has audience "dashboard"
	token, err := jm.GenerateToken("user@test.com", "dashboard")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// Should match when "dashboard" is in the list
	claims, err := jm.ValidateToken(token, "dashboard", "mcp-client")
	if err != nil {
		t.Fatalf("ValidateToken with multiple audiences (first match) failed: %v", err)
	}
	if claims.Subject != "user@test.com" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "user@test.com")
	}

	// The jwt library only checks audiences[0] via WithAudience.
	// When audiences[0] doesn't match the token's audience, validation fails.
	// This is expected behavior — document with an explicit assertion.
	_, err = jm.ValidateToken(token, "mcp-client", "dashboard")
	if err == nil {
		t.Error("expected error when first audience doesn't match token audience")
	}

	// No match at all
	_, err = jm.ValidateToken(token, "other-client", "another-client")
	if err == nil {
		t.Fatal("ValidateToken should fail when no audience matches")
	}
}

func TestValidateToken_NoAudienceCheck(t *testing.T) {
	t.Parallel()
	jm := NewJWTManager("no-aud-secret", 1*time.Hour)

	token, err := jm.GenerateToken("user@test.com", "any-client")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// When no audiences passed, any token audience is accepted
	claims, err := jm.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken without audience check failed: %v", err)
	}
	if claims.Subject != "user@test.com" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "user@test.com")
	}
}

// ===========================================================================
// Consolidated from coverage_*.go files
// ===========================================================================

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

// ===========================================================================
// Merged from stores_coverage_test.go (jwt-related test)
// ===========================================================================

func TestValidateToken_MultiAud_Match(t *testing.T) {
	t.Parallel()
	jm := NewJWTManager("test-secret", 1*time.Hour)

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "test@test.com",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Audience:  jwt.ClaimStrings{"aud-a", "aud-b"},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	// First audience matches, multi-aud loop confirms
	result, err := jm.ValidateToken(tokenStr, "aud-a", "aud-c")
	assert.NoError(t, err)
	assert.Equal(t, "test@test.com", result.Subject)
}
