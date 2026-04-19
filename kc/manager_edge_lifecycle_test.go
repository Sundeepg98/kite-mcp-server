package kc

import (
	"strings"
	"testing"

	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
)

// ===========================================================================
// Manager.New — nil logger error
// ===========================================================================

func TestNew_NilLogger(t *testing.T) {
	t.Parallel()
	_, err := New(Config{
		APIKey:    "key",
		APISecret: "secret",
	})
	if err == nil {
		t.Fatal("Expected error with nil logger")
	}
}



// ===========================================================================
// Manager.New — no API key/secret warning path (doesn't error, just warns)
// ===========================================================================
func TestNew_NoAPICredentials(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		Logger:             testLogger(),
		InstrumentsManager: newTestInstrumentsManager(),
	})
	if err != nil {
		t.Fatalf("Expected no error (just warning), got: %v", err)
	}
	defer m.Shutdown()
	if m.apiKey != "" {
		t.Errorf("apiKey = %q, want empty", m.apiKey)
	}
}



// ===========================================================================
// Manager.OpenBrowser — coverage for URL validation and non-local mode
// ===========================================================================
func TestOpenBrowser_NonLocalMode_HTTP(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey: "key", APISecret: "secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		AppMode:            "http", // not local mode
	})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer m.Shutdown()

	// Non-local mode should return nil immediately
	err = m.OpenBrowser("https://example.com")
	if err != nil {
		t.Errorf("Expected nil for non-local mode, got: %v", err)
	}
}


func TestOpenBrowser_InvalidScheme_FTP(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	err = m.OpenBrowser("ftp://example.com")
	if err == nil {
		t.Fatal("Expected error for ftp scheme")
	}
	if !strings.Contains(err.Error(), "invalid URL scheme") {
		t.Errorf("Error should mention 'invalid URL scheme', got: %v", err)
	}
}


func TestOpenBrowser_EmptyURL_Boost(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	err = m.OpenBrowser("")
	if err == nil {
		t.Fatal("Expected error for empty URL")
	}
}



// ===========================================================================
// Manager.PaperEngine — nil returns nil interface
// ===========================================================================
func TestPaperEngine_Nil(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	if m.PaperEngine() != nil {
		t.Error("PaperEngine should return nil when not configured")
	}
}


func TestPaperEngine_Configured(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	engine := &papertrading.PaperEngine{}
	m.SetPaperEngine(engine)

	result := m.PaperEngine()
	if result == nil {
		t.Error("PaperEngine should not be nil when configured")
	}
}



// ===========================================================================
// Manager.BillingStore — nil returns nil interface
// ===========================================================================
func TestBillingStore_Nil(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	if m.BillingStore() != nil {
		t.Error("BillingStore should return nil when not configured")
	}
}


func TestBillingStore_Configured(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	store := &billing.Store{}
	m.SetBillingStore(store)

	result := m.BillingStore()
	if result == nil {
		t.Error("BillingStore should not be nil when configured")
	}
}



// ===========================================================================
// Manager.Shutdown — comprehensive shutdown
// ===========================================================================
func TestManager_Shutdown_WithComponents(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey: "key", APISecret: "secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		AlertDBPath:        ":memory:",
	})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	// Should not panic
	m.Shutdown()
}



// ===========================================================================
// Manager — various getters
// ===========================================================================
func TestManager_Getters(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	if m.ExternalURL() != "" {
		t.Errorf("ExternalURL = %q, want empty", m.ExternalURL())
	}
	if m.AdminSecretPath() != "" {
		t.Errorf("AdminSecretPath = %q, want empty", m.AdminSecretPath())
	}
	if !m.IsLocalMode() {
		t.Error("Expected local mode for default")
	}
	if m.SessionSigner() == nil {
		t.Error("SessionSigner should not be nil")
	}
	if m.PaperEngineConcrete() != nil {
		t.Error("PaperEngineConcrete should be nil")
	}
	if m.BillingStoreConcrete() != nil {
		t.Error("BillingStoreConcrete should be nil")
	}
	if m.RiskGuard() != nil {
		t.Error("RiskGuard should be nil")
	}
	if m.InvitationStore() != nil {
		t.Error("InvitationStore should be nil")
	}
	if m.ManagedSessionSvc() == nil {
		t.Error("ManagedSessionSvc should not be nil")
	}
}



// ===========================================================================
// Tests merged from gap_test.go
// ===========================================================================
func TestNew_WithAlertDBPath_Gap(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "key",
		APISecret:          "secret",
		Logger:             testLogger(),
		InstrumentsManager: newTestInstrumentsManager(),
		AlertDBPath:        ":memory:",
		EncryptionSecret:   "test-encryption-secret-32bytes!!",
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer m.Shutdown()

	if m.alertDB == nil {
		t.Error("Expected alertDB to be initialized")
	}
	if m.tokenStore == nil {
		t.Error("Expected tokenStore to be initialized")
	}
}



// ---------------------------------------------------------------------------
// Manager New() — with Telegram bot token (covers Telegram path)
// ---------------------------------------------------------------------------
func TestNew_WithTelegramToken(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "key",
		APISecret:          "secret",
		Logger:             testLogger(),
		InstrumentsManager: newTestInstrumentsManager(),
		TelegramBotToken:   "123:fake-token-for-test",
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer m.Shutdown()

	// telegramNotifier may or may not be nil depending on token validity
	// We just ensure no panic
}



// ---------------------------------------------------------------------------
// Manager New() — with custom session signer (line 572-573)
// ---------------------------------------------------------------------------
func TestNew_WithCustomSessionSigner_Gap(t *testing.T) {
	t.Parallel()
	signer, err := NewSessionSignerWithKey([]byte("test-secret-key-1234567890123456"))
	if err != nil {
		t.Fatalf("NewSessionSignerWithKey error: %v", err)
	}

	m, err := New(Config{
		APIKey:             "key",
		APISecret:          "secret",
		Logger:             testLogger(),
		InstrumentsManager: newTestInstrumentsManager(),
		SessionSigner:      signer,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer m.Shutdown()

	if m.sessionSigner != signer {
		t.Error("Expected custom session signer to be used")
	}
}



// ---------------------------------------------------------------------------
// Manager New() — nil logger (should return error)
// ---------------------------------------------------------------------------
func TestNew_NilLogger_Gap(t *testing.T) {
	t.Parallel()
	_, err := New(Config{
		APIKey:    "key",
		APISecret: "secret",
	})
	if err == nil {
		t.Error("Expected error for nil logger")
	}
}



// ---------------------------------------------------------------------------
// Manager New() — no credentials (line 59-61 warn path)
// ---------------------------------------------------------------------------
func TestNew_NoCredentials(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		Logger:             testLogger(),
		InstrumentsManager: newTestInstrumentsManager(),
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer m.Shutdown()
	// Just verifies no panic, warn is logged
}



// ---------------------------------------------------------------------------
// Manager New() — instruments manager creation (line 68-76)
// ---------------------------------------------------------------------------
func TestNew_DefaultInstrumentsManager(t *testing.T) {
	t.Parallel()
	// Create with no InstrumentsManager, it should auto-create one
	config := instruments.DefaultUpdateConfig()
	config.EnableScheduler = false

	m, err := New(Config{
		APIKey:            "key",
		APISecret:         "secret",
		Logger:            testLogger(),
		InstrumentsConfig: config,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer m.Shutdown()

	if m.Instruments == nil {
		t.Error("Expected instruments manager to be created automatically")
	}
}



// ---------------------------------------------------------------------------
// Manager Shutdown — with alertDB open (covers DB close error path)
// ---------------------------------------------------------------------------
func TestManager_ShutdownWithDB(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "key",
		APISecret:          "secret",
		Logger:             testLogger(),
		InstrumentsManager: newTestInstrumentsManager(),
		AlertDBPath:        ":memory:",
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Close the DB manually first to trigger error on Shutdown
	m.alertDB.Close()
	m.Shutdown() // should log error but not panic
}



// ---------------------------------------------------------------------------
// Documented unreachable lines
// ---------------------------------------------------------------------------
//
// The following lines are documented as unreachable and NOT tested:
//
// - session_signing.go:39-41 — NewSessionSigner crypto/rand.Read error
//   (crypto/rand.Read never fails in Go 1.24+, panics instead)
//
// - manager.go:73-75 — instruments.New() error path
//   (only fails with bad config, tested via instruments package itself)
//
// - manager.go:551-554 — initializeTemplates/setupTemplates template parse
//   errors (templates are embedded via embed.FS, always valid at build time)

// ===========================================================================
// Tests merged from manager_coverage_test.go
// ===========================================================================

// ---------------------------------------------------------------------------
// New() — with EncryptionSecret to cover the HKDF salt branch
// ---------------------------------------------------------------------------
func TestNew_WithEncryptionSecret_C98(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		AlertDBPath:        ":memory:",
		EncryptionSecret:   "test-encryption-secret-long-enough",
	})
	if err != nil {
		t.Fatalf("New with encryption: %v", err)
	}
	defer m.Shutdown()
}



// ---------------------------------------------------------------------------
// New() — with DevMode to cover the mock broker path
// ---------------------------------------------------------------------------
func TestNew_DevMode_C98(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		DevMode:            true,
	})
	if err != nil {
		t.Fatalf("New DevMode: %v", err)
	}
	defer m.Shutdown()
	if !m.devMode {
		t.Error("Expected devMode to be true")
	}
}



// ---------------------------------------------------------------------------
// OpenBrowser — exercising the exec.Command path for valid URL in local mode
// ---------------------------------------------------------------------------
func TestOpenBrowser_EmptyScheme(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("key", "secret")
	defer m.Shutdown()

	err := m.OpenBrowser("://no-scheme")
	if err == nil {
		t.Error("Expected error for empty/invalid scheme")
	}
}



// ---------------------------------------------------------------------------
// New() — with instruments manager creation error (nil config with nil manager)
// ---------------------------------------------------------------------------
func TestNew_InstrumentsManagerAutoCreation(t *testing.T) {
	t.Parallel()
	// When InstrumentsManager is nil, New() creates one internally.
	// This tests the internal creation path (which uses HTTP for real instruments).
	// We don't want actual HTTP calls, but the creation path is exercised.
	cfg := instruments.DefaultUpdateConfig()
	cfg.EnableScheduler = false
	m, err := New(Config{
		APIKey:            "key",
		APISecret:         "secret",
		Logger:            testLogger(),
		InstrumentsConfig: cfg,
	})
	if err != nil {
		t.Fatalf("New with auto instruments: %v", err)
	}
	defer m.Shutdown()
}
