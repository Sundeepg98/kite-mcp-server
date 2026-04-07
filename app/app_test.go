package app

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// testLogger creates a discard logger for tests
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestLoadConfig_MissingAPIKey(t *testing.T) {
	t.Setenv("KITE_API_KEY", "")
	t.Setenv("KITE_API_SECRET", "")
	t.Setenv("OAUTH_JWT_SECRET", "")

	app := NewApp(testLogger())
	err := app.LoadConfig()

	if err == nil {
		t.Error("Expected error when API key/secret are missing")
	}
}

func TestLoadConfig_MissingAPISecret(t *testing.T) {
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "")
	t.Setenv("OAUTH_JWT_SECRET", "")

	app := NewApp(testLogger())
	err := app.LoadConfig()

	if err == nil {
		t.Error("Expected error when API secret is missing")
	}
}

func TestLoadConfig_ValidCredentials(t *testing.T) {
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")

	app := NewApp(testLogger())
	err := app.LoadConfig()

	if err != nil {
		t.Errorf("Expected no error with valid credentials, got: %v", err)
	}

	if app.Config.KiteAPIKey != "test_key" {
		t.Errorf("Expected API key 'test_key', got '%s'", app.Config.KiteAPIKey)
	}
	if app.Config.KiteAPISecret != "test_secret" {
		t.Errorf("Expected API secret 'test_secret', got '%s'", app.Config.KiteAPISecret)
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	t.Setenv("APP_MODE", "")
	t.Setenv("APP_PORT", "")
	t.Setenv("APP_HOST", "")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")

	app := NewApp(testLogger())
	err := app.LoadConfig()

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

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

func TestDeriveAggregateID(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		event    domain.Event
		expected string
	}{
		{
			name:     "OrderPlacedEvent uses OrderID",
			event:    domain.OrderPlacedEvent{OrderID: "ORD-123", Timestamp: now},
			expected: "ORD-123",
		},
		{
			name:     "OrderModifiedEvent uses OrderID",
			event:    domain.OrderModifiedEvent{OrderID: "ORD-456", Timestamp: now},
			expected: "ORD-456",
		},
		{
			name:     "OrderCancelledEvent uses OrderID",
			event:    domain.OrderCancelledEvent{OrderID: "ORD-789", Timestamp: now},
			expected: "ORD-789",
		},
		{
			name:     "PositionClosedEvent uses OrderID",
			event:    domain.PositionClosedEvent{OrderID: "ORD-POS-1", Timestamp: now},
			expected: "ORD-POS-1",
		},
		{
			name:     "AlertTriggeredEvent uses AlertID",
			event:    domain.AlertTriggeredEvent{AlertID: "ALERT-42", Timestamp: now},
			expected: "ALERT-42",
		},
		{
			name:     "UserFrozenEvent uses Email",
			event:    domain.UserFrozenEvent{Email: "user@example.com", Timestamp: now},
			expected: "user@example.com",
		},
		{
			name:     "UserSuspendedEvent uses Email",
			event:    domain.UserSuspendedEvent{Email: "suspended@example.com", Timestamp: now},
			expected: "suspended@example.com",
		},
		{
			name:     "GlobalFreezeEvent uses By (admin email)",
			event:    domain.GlobalFreezeEvent{By: "admin@example.com", Timestamp: now},
			expected: "admin@example.com",
		},
		{
			name:     "FamilyInvitedEvent uses AdminEmail",
			event:    domain.FamilyInvitedEvent{AdminEmail: "family-admin@example.com", Timestamp: now},
			expected: "family-admin@example.com",
		},
		{
			name:     "RiskLimitBreachedEvent uses Email",
			event:    domain.RiskLimitBreachedEvent{Email: "risky@example.com", Timestamp: now},
			expected: "risky@example.com",
		},
		{
			name:     "SessionCreatedEvent uses SessionID",
			event:    domain.SessionCreatedEvent{SessionID: "sess-abc", Timestamp: now},
			expected: "sess-abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveAggregateID(tt.event)
			if got != tt.expected {
				t.Errorf("deriveAggregateID() = %q, want %q", got, tt.expected)
			}
		})
	}
}
