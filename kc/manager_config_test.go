package kc

import (
	"testing"

)

// newTestInstrumentsManager creates a fast test instruments manager without HTTP calls



// KiteConnect API Tests (consolidated from api_test.go)
func TestNewKiteConnect(t *testing.T) {
	apiKey := "test_api_key"

	kc := NewKiteConnect(apiKey)

	if kc == nil {
		t.Fatal("Expected non-nil KiteConnect")
	}

	if kc.Client == nil {
		t.Error("Expected non-nil Client")
	}
}



// TestNewConfigConstructor tests the new Config-based constructor
func TestNewConfigConstructor(t *testing.T) {
	// Test minimal config
	t.Run("minimal_config", func(t *testing.T) {
		manager, err := New(Config{
			APIKey:             "test_key",
			APISecret:          "test_secret",
			InstrumentsManager: newTestInstrumentsManager(),
			Logger:             testLogger(),
		})
		if err != nil {
			t.Fatalf("Expected no error with minimal config, got: %v", err)
		}

		if manager.apiKey != "test_key" {
			t.Errorf("Expected API key 'test_key', got %s", manager.apiKey)
		}
		if manager.apiSecret != "test_secret" {
			t.Errorf("Expected API secret 'test_secret', got %s", manager.apiSecret)
		}
		if manager.Instruments == nil {
			t.Error("Expected instruments manager to be set")
		}
		if manager.sessionSigner == nil {
			t.Error("Expected session signer to be initialized")
		}
	})

	// Test validation
	t.Run("validation", func(t *testing.T) {
		// Missing API key/secret is allowed (warns, doesn't error)
		m, err := New(Config{
			Logger: testLogger(),
		})
		if err != nil {
			t.Errorf("Expected no error with empty API key/secret (per-user creds), got: %v", err)
		}
		if m != nil {
			m.Shutdown()
		}

		// Missing logger is still an error
		_, err = New(Config{
			APIKey:    "test_key",
			APISecret: "test_secret",
		})
		if err == nil || err.Error() != "logger is required" {
			t.Errorf("Expected 'logger is required' error, got: %v", err)
		}
	})

	// Test with custom session signer
	t.Run("custom_session_signer", func(t *testing.T) {
		customSigner, err := NewSessionSignerWithKey([]byte("test-key-32-bytes-long-for-hmac"))
		if err != nil {
			t.Fatalf("Failed to create custom signer: %v", err)
		}

		manager, err := New(Config{
			APIKey:             "test_key",
			APISecret:          "test_secret",
			InstrumentsManager: newTestInstrumentsManager(),
			SessionSigner:      customSigner,
			Logger:             testLogger(),
		})
		if err != nil {
			t.Fatalf("Expected no error with custom session signer, got: %v", err)
		}

		if manager.sessionSigner != customSigner {
			t.Error("Expected custom session signer to be used")
		}
	})
}



// ===========================================================================
// Manager — truncKey
// ===========================================================================
func TestTruncKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		n     int
		want  string
	}{
		{"abcdefgh", 4, "abcd"},
		{"abc", 4, "abc"},
		{"abcd", 4, "abcd"},
		{"", 4, ""},
	}
	for _, tc := range tests {
		got := truncKey(tc.input, tc.n)
		if got != tc.want {
			t.Errorf("truncKey(%q, %d) = %q, want %q", tc.input, tc.n, got, tc.want)
		}
	}
}
