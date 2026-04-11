package oauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"time"
)

// --- Mock implementations ---

// mockSigner implements Signer for testing.
type mockSigner struct {
	signFunc   func(data string) string
	verifyFunc func(signed string) (string, error)
}

func (m *mockSigner) Sign(data string) string {
	if m.signFunc != nil {
		return m.signFunc(data)
	}
	// Default: HMAC-SHA256 with a fixed test key, format: data|signature
	mac := hmac.New(sha256.New, []byte("test-signer-key"))
	mac.Write([]byte(data))
	sig := hex.EncodeToString(mac.Sum(nil))
	return data + "|" + sig
}

func (m *mockSigner) Verify(signed string) (string, error) {
	if m.verifyFunc != nil {
		return m.verifyFunc(signed)
	}
	// Default: split on "|", verify HMAC
	for i := len(signed) - 1; i >= 0; i-- {
		if signed[i] == '|' {
			data := signed[:i]
			sig := signed[i+1:]
			mac := hmac.New(sha256.New, []byte("test-signer-key"))
			mac.Write([]byte(data))
			expected := hex.EncodeToString(mac.Sum(nil))
			if sig != expected {
				return "", fmt.Errorf("invalid signature")
			}
			return data, nil
		}
	}
	return "", fmt.Errorf("no separator found in signed data")
}

// mockExchanger implements KiteExchanger for testing.
type mockExchanger struct {
	exchangeFunc      func(requestToken string) (string, error)
	exchangeWithCreds func(requestToken, apiKey, apiSecret string) (string, error)
	getCredentials    func(email string) (string, string, bool)
	getSecretByAPIKey func(apiKey string) (string, bool)
}

func (m *mockExchanger) ExchangeRequestToken(requestToken string) (string, error) {
	if m.exchangeFunc != nil {
		return m.exchangeFunc(requestToken)
	}
	return "user@example.com", nil
}

func (m *mockExchanger) ExchangeWithCredentials(requestToken, apiKey, apiSecret string) (string, error) {
	if m.exchangeWithCreds != nil {
		return m.exchangeWithCreds(requestToken, apiKey, apiSecret)
	}
	return "user@example.com", nil
}

func (m *mockExchanger) GetCredentials(email string) (string, string, bool) {
	if m.getCredentials != nil {
		return m.getCredentials(email)
	}
	return "", "", false
}

func (m *mockExchanger) GetSecretByAPIKey(apiKey string) (string, bool) {
	if m.getSecretByAPIKey != nil {
		return m.getSecretByAPIKey(apiKey)
	}
	return "", false
}

// --- Test helper ---

// newTestHandler creates a fully configured *Handler suitable for tests.
// Templates are parsed from the embedded FS so callback/login endpoints work.
func newTestHandler(opts ...func(*Config, *mockSigner, *mockExchanger)) *Handler {
	cfg := &Config{
		KiteAPIKey:  "test-api-key",
		JWTSecret:   "super-secret-jwt-key-for-testing",
		ExternalURL: "https://test.example.com",
		TokenExpiry: 4 * time.Hour,
		Logger:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	signer := &mockSigner{}
	exchanger := &mockExchanger{}

	for _, opt := range opts {
		opt(cfg, signer, exchanger)
	}

	return NewHandler(cfg, signer, exchanger)
}

// pkceChallenge computes the S256 code_challenge for a given code_verifier,
// matching the production PKCE algorithm.
func pkceChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// ===========================================================================
// Consolidated from coverage_*.go files
// ===========================================================================

type devNull struct{}

func (devNull) Write(p []byte) (int, error) { return len(p), nil }

// testLogger returns a discard logger for tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(devNull{}, nil))
}
