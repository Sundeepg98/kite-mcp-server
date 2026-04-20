package app

import (
	"errors"
	"os"
	"strings"
)

// ConfigFromEnv constructs a *Config populated from the environment. It reads
// every env var that app/app.go:NewApp currently reads inline, consolidating
// the env surface in one place so Task #21 (Phase E.2) can thread Config
// through without touching os.Getenv at runtime.
//
// The struct type itself is defined in app.go (predates this file). This
// helper is additive: existing NewApp still works, and tests can construct
// a hand-built Config without t.Setenv to run with t.Parallel.
//
// Fields and their env vars (mirrors app/app.go:339-366):
//
//	KiteAPIKey         <- KITE_API_KEY
//	KiteAPISecret      <- KITE_API_SECRET
//	KiteAccessToken    <- KITE_ACCESS_TOKEN
//	AppMode            <- APP_MODE
//	AppPort            <- APP_PORT
//	AppHost            <- APP_HOST
//	ExcludedTools      <- EXCLUDED_TOOLS
//	AdminSecretPath    <- ADMIN_ENDPOINT_SECRET_PATH
//	OAuthJWTSecret     <- OAUTH_JWT_SECRET
//	ExternalURL        <- EXTERNAL_URL
//	TelegramBotToken   <- TELEGRAM_BOT_TOKEN
//	AlertDBPath        <- ALERT_DB_PATH
//	AdminEmails        <- ADMIN_EMAILS
//	GoogleClientID     <- GOOGLE_CLIENT_ID
//	GoogleClientSecret <- GOOGLE_CLIENT_SECRET
//	EnableTrading      <- ENABLE_TRADING == "true" (case-insensitive)
//
// Defaults are applied via WithDefaults when the caller opts in.
func ConfigFromEnv() *Config {
	return &Config{
		KiteAPIKey:         os.Getenv("KITE_API_KEY"),
		KiteAPISecret:      os.Getenv("KITE_API_SECRET"),
		KiteAccessToken:    os.Getenv("KITE_ACCESS_TOKEN"),
		AppMode:            os.Getenv("APP_MODE"),
		AppPort:            os.Getenv("APP_PORT"),
		AppHost:            os.Getenv("APP_HOST"),
		ExcludedTools:      os.Getenv("EXCLUDED_TOOLS"),
		AdminSecretPath:    os.Getenv("ADMIN_ENDPOINT_SECRET_PATH"),
		OAuthJWTSecret:     os.Getenv("OAUTH_JWT_SECRET"),
		ExternalURL:        os.Getenv("EXTERNAL_URL"),
		TelegramBotToken:   os.Getenv("TELEGRAM_BOT_TOKEN"),
		AlertDBPath:        os.Getenv("ALERT_DB_PATH"),
		AdminEmails:        os.Getenv("ADMIN_EMAILS"),
		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		EnableTrading:      strings.EqualFold(os.Getenv("ENABLE_TRADING"), "true"),
	}
}

// WithDefaults returns a copy of c with empty fields filled from defaults:
//
//	AppMode -> DefaultAppMode ("http")
//	AppPort -> DefaultPort    ("8080")
//	AppHost -> DefaultHost    ("localhost")
//
// All other fields are left as-is (empty string / false). Caller owns the
// returned pointer; the receiver is not mutated.
func (c *Config) WithDefaults() *Config {
	if c == nil {
		return nil
	}
	out := *c
	if out.AppMode == "" {
		out.AppMode = DefaultAppMode
	}
	if out.AppPort == "" {
		out.AppPort = DefaultPort
	}
	if out.AppHost == "" {
		out.AppHost = DefaultHost
	}
	return &out
}

// ErrMissingKiteCredentials is returned by Validate when KITE_API_KEY or
// KITE_API_SECRET is empty in a non-dev-mode deployment.
//
// This sentinel lets callers distinguish the "missing required fields"
// failure from other validation errors without parsing the message.
var ErrMissingKiteCredentials = errors.New("config: KITE_API_KEY and KITE_API_SECRET are required")

// Validate returns a non-nil error when the Config lacks fields required
// for a production start. devMode=true relaxes the Kite-credential
// requirement (mock broker path).
//
// Currently enforces:
//   - KiteAPIKey and KiteAPISecret non-empty (unless devMode)
//
// Additional checks (OAuthJWTSecret required for hosted mode, valid
// AppMode values, etc.) can layer on here as Task #21 plumbs Config
// through the rest of the startup path.
func (c *Config) Validate(devMode bool) error {
	if c == nil {
		return errors.New("config: nil")
	}
	if !devMode && (c.KiteAPIKey == "" || c.KiteAPISecret == "") {
		return ErrMissingKiteCredentials
	}
	return nil
}
