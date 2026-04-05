package oauth

import (
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestConfig_Validate_Valid(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		KiteAPIKey:  "test-api-key",
		JWTSecret:   "my-secret",
		ExternalURL: "https://test.example.com",
		TokenExpiry: 2 * time.Hour,
		Logger:      slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate should succeed for valid config: %v", err)
	}
}

func TestConfig_Validate_MissingJWTSecret(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		ExternalURL: "https://test.example.com",
		TokenExpiry: 1 * time.Hour,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate should fail when JWTSecret is empty")
	}
	if err.Error() != "JWTSecret is required" {
		t.Errorf("Unexpected error message: %q", err.Error())
	}
}

func TestConfig_Validate_MissingExternalURL(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		JWTSecret:   "my-secret",
		TokenExpiry: 1 * time.Hour,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate should fail when ExternalURL is empty")
	}
	if err.Error() != "ExternalURL is required" {
		t.Errorf("Unexpected error message: %q", err.Error())
	}
}

func TestConfig_Validate_TrailingSlash(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		JWTSecret:   "my-secret",
		ExternalURL: "https://test.example.com/",
		TokenExpiry: 1 * time.Hour,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if cfg.ExternalURL != "https://test.example.com" {
		t.Errorf("ExternalURL = %q, want trailing slash stripped", cfg.ExternalURL)
	}

	// Multiple trailing slashes
	cfg2 := &Config{
		JWTSecret:   "my-secret",
		ExternalURL: "https://test.example.com///",
		TokenExpiry: 1 * time.Hour,
	}
	if err := cfg2.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if cfg2.ExternalURL != "https://test.example.com" {
		t.Errorf("ExternalURL = %q, want all trailing slashes stripped", cfg2.ExternalURL)
	}
}

func TestConfig_Validate_DefaultExpiry(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		JWTSecret:   "my-secret",
		ExternalURL: "https://test.example.com",
		// TokenExpiry is zero
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if cfg.TokenExpiry != 24*time.Hour {
		t.Errorf("TokenExpiry = %v, want 24h default", cfg.TokenExpiry)
	}
}
