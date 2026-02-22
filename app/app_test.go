package app

import (
	"io"
	"log/slog"
	"os"
	"testing"
)

// testLogger creates a discard logger for tests
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestLoadConfig_MissingAPIKey_NoOAuth(t *testing.T) {
	// Without OAuth, missing Kite credentials should error
	_ = os.Unsetenv("KITE_API_KEY")
	_ = os.Unsetenv("KITE_API_SECRET")
	_ = os.Unsetenv("GOOGLE_CLIENT_ID")

	app := NewApp(testLogger())
	err := app.LoadConfig()

	if err == nil {
		t.Error("Expected error when API key/secret are missing without OAuth")
	}
}

func TestLoadConfig_MissingAPISecret_NoOAuth(t *testing.T) {
	// Without OAuth, missing API secret should error
	_ = os.Setenv("KITE_API_KEY", "test_key")
	_ = os.Unsetenv("KITE_API_SECRET")
	_ = os.Unsetenv("GOOGLE_CLIENT_ID")
	defer func() { _ = os.Unsetenv("KITE_API_KEY") }()

	app := NewApp(testLogger())
	err := app.LoadConfig()

	if err == nil {
		t.Error("Expected error when API secret is missing without OAuth")
	}
}

func TestLoadConfig_MissingCredentials_WithOAuth(t *testing.T) {
	// With OAuth enabled, missing Kite credentials should NOT error (per-user creds via setup_kite)
	_ = os.Unsetenv("KITE_API_KEY")
	_ = os.Unsetenv("KITE_API_SECRET")
	_ = os.Setenv("GOOGLE_CLIENT_ID", "test_client_id")
	defer func() { _ = os.Unsetenv("GOOGLE_CLIENT_ID") }()

	app := NewApp(testLogger())
	err := app.LoadConfig()

	if err != nil {
		t.Errorf("Expected no error with OAuth enabled (per-user credentials), got: %v", err)
	}
}

func TestLoadConfig_ValidCredentials(t *testing.T) {
	// Set both API key and secret
	_ = os.Setenv("KITE_API_KEY", "test_key")
	_ = os.Setenv("KITE_API_SECRET", "test_secret")
	defer func() {
		_ = os.Unsetenv("KITE_API_KEY")
		_ = os.Unsetenv("KITE_API_SECRET")
	}()

	app := NewApp(testLogger())
	err := app.LoadConfig()

	if err != nil {
		t.Errorf("Expected no error with valid credentials, got: %v", err)
	}

	// Verify config values
	if app.Config.KiteAPIKey != "test_key" {
		t.Errorf("Expected API key 'test_key', got '%s'", app.Config.KiteAPIKey)
	}

	if app.Config.KiteAPISecret != "test_secret" {
		t.Errorf("Expected API secret 'test_secret', got '%s'", app.Config.KiteAPISecret)
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	// Clear all environment variables
	_ = os.Unsetenv("APP_MODE")
	_ = os.Unsetenv("APP_PORT")
	_ = os.Unsetenv("APP_HOST")
	_ = os.Setenv("KITE_API_KEY", "test_key")
	_ = os.Setenv("KITE_API_SECRET", "test_secret")
	defer func() {
		_ = os.Unsetenv("KITE_API_KEY")
		_ = os.Unsetenv("KITE_API_SECRET")
	}()

	app := NewApp(testLogger())
	err := app.LoadConfig()

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Verify defaults
	if app.Config.AppMode != DefaultAppMode {
		t.Errorf("Expected default app mode '%s', got '%s'", DefaultAppMode, app.Config.AppMode)
	}

	if app.Config.AppPort != DefaultPort {
		t.Errorf("Expected default port '%s', got '%s'", DefaultPort, app.Config.AppPort)
	}

	if app.Config.AppHost != DefaultHost {
		t.Errorf("Expected default host '%s', got '%s'", DefaultHost, app.Config.AppHost)
	}
}

func TestStartServer_InvalidMode(t *testing.T) {
	app := &App{
		Config: &Config{
			AppMode: "invalid_mode",
		},
	}

	err := app.startServer(nil, nil, nil, "")

	if err == nil {
		t.Error("Expected error for invalid APP_MODE")
	}

	expectedMsg := "invalid APP_MODE: invalid_mode"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', got '%s'", expectedMsg, err.Error())
	}
}

func TestNewApp(t *testing.T) {
	app := NewApp(testLogger())

	if app == nil {
		t.Error("Expected non-nil app")
		return
	}

	if app.Config == nil {
		t.Error("Expected non-nil config")
	}

	if app.Version != "v0.0.0" {
		t.Errorf("Expected default version 'v0.0.0', got '%s'", app.Version)
	}
}

func TestSetVersion(t *testing.T) {
	app := NewApp(testLogger())
	testVersion := "v1.2.3"

	app.SetVersion(testVersion)

	if app.Version != testVersion {
		t.Errorf("Expected version '%s', got '%s'", testVersion, app.Version)
	}
}
