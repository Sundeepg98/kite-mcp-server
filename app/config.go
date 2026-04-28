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
//	EnableTrading        <- ENABLE_TRADING == "true" (case-insensitive)
//	InstrumentsSkipFetch <- INSTRUMENTS_SKIP_FETCH == "true" (case-insensitive)
//	AdminPassword        <- ADMIN_PASSWORD
//	StripeWebhookSecret  <- STRIPE_WEBHOOK_SECRET
//	RiskguardPluginDir   <- RISKGUARD_PLUGIN_DIR
//
// Defaults are applied via WithDefaults when the caller opts in.
//
// ConfigFromEnv is the production wrapper: reads each env var via os.Getenv
// then delegates to ConfigFromMap. Tests should use ConfigFromMap with a
// fixture map literal — no t.Setenv, parallel-safe.
func ConfigFromEnv() *Config {
	return ConfigFromMap(map[string]string{
		"KITE_API_KEY":               os.Getenv("KITE_API_KEY"),
		"KITE_API_SECRET":            os.Getenv("KITE_API_SECRET"),
		"KITE_ACCESS_TOKEN":          os.Getenv("KITE_ACCESS_TOKEN"),
		"APP_MODE":                   os.Getenv("APP_MODE"),
		"APP_PORT":                   os.Getenv("APP_PORT"),
		"APP_HOST":                   os.Getenv("APP_HOST"),
		"EXCLUDED_TOOLS":             os.Getenv("EXCLUDED_TOOLS"),
		"ADMIN_ENDPOINT_SECRET_PATH": os.Getenv("ADMIN_ENDPOINT_SECRET_PATH"),
		"OAUTH_JWT_SECRET":           os.Getenv("OAUTH_JWT_SECRET"),
		"OAUTH_JWT_SECRET_PREVIOUS":  os.Getenv("OAUTH_JWT_SECRET_PREVIOUS"),
		"EXTERNAL_URL":               os.Getenv("EXTERNAL_URL"),
		"TELEGRAM_BOT_TOKEN":         os.Getenv("TELEGRAM_BOT_TOKEN"),
		"ALERT_DB_PATH":              os.Getenv("ALERT_DB_PATH"),
		"ADMIN_EMAILS":               os.Getenv("ADMIN_EMAILS"),
		"GOOGLE_CLIENT_ID":           os.Getenv("GOOGLE_CLIENT_ID"),
		"GOOGLE_CLIENT_SECRET":       os.Getenv("GOOGLE_CLIENT_SECRET"),
		"ENABLE_TRADING":             os.Getenv("ENABLE_TRADING"),
		"INSTRUMENTS_SKIP_FETCH":     os.Getenv("INSTRUMENTS_SKIP_FETCH"),
		"RISKGUARD_PLUGIN_DIR":       os.Getenv("RISKGUARD_PLUGIN_DIR"),
		"ADMIN_PASSWORD":             os.Getenv("ADMIN_PASSWORD"),
		"STRIPE_WEBHOOK_SECRET":      os.Getenv("STRIPE_WEBHOOK_SECRET"),
		"STRIPE_SECRET_KEY":          os.Getenv("STRIPE_SECRET_KEY"),
		"STRIPE_PRICE_PRO":           os.Getenv("STRIPE_PRICE_PRO"),
		"STRIPE_PRICE_PREMIUM":       os.Getenv("STRIPE_PRICE_PREMIUM"),
		"DEV_MODE":                   os.Getenv("DEV_MODE"),
		"TLS_AUTOCERT_DOMAIN":        os.Getenv("TLS_AUTOCERT_DOMAIN"),
		"TLS_AUTOCERT_CACHE_DIR":     os.Getenv("TLS_AUTOCERT_CACHE_DIR"),
	})
}

// ConfigFromMap is the pure parser: builds a *Config from an arbitrary
// env-name → value map. Fields are populated identically to ConfigFromEnv,
// just sourced from the map instead of os.Getenv. Tests pass a literal
// map and verify Config fields without t.Setenv.
//
// Bool flags (ENABLE_TRADING, INSTRUMENTS_SKIP_FETCH) parse via
// strings.EqualFold("true") so values like "TRUE" and "True" also enable.
func ConfigFromMap(env map[string]string) *Config {
	return &Config{
		KiteAPIKey:           env["KITE_API_KEY"],
		KiteAPISecret:        env["KITE_API_SECRET"],
		KiteAccessToken:      env["KITE_ACCESS_TOKEN"],
		AppMode:              env["APP_MODE"],
		AppPort:              env["APP_PORT"],
		AppHost:              env["APP_HOST"],
		ExcludedTools:        env["EXCLUDED_TOOLS"],
		AdminSecretPath:      env["ADMIN_ENDPOINT_SECRET_PATH"],
		OAuthJWTSecret:         env["OAUTH_JWT_SECRET"],
		OAuthJWTSecretPrevious: env["OAUTH_JWT_SECRET_PREVIOUS"],
		ExternalURL:            env["EXTERNAL_URL"],
		TelegramBotToken:     env["TELEGRAM_BOT_TOKEN"],
		AlertDBPath:          env["ALERT_DB_PATH"],
		AdminEmails:          env["ADMIN_EMAILS"],
		GoogleClientID:       env["GOOGLE_CLIENT_ID"],
		GoogleClientSecret:   env["GOOGLE_CLIENT_SECRET"],
		EnableTrading:        strings.EqualFold(env["ENABLE_TRADING"], "true"),
		InstrumentsSkipFetch: strings.EqualFold(env["INSTRUMENTS_SKIP_FETCH"], "true"),
		RiskguardPluginDir:   env["RISKGUARD_PLUGIN_DIR"],
		AdminPassword:        env["ADMIN_PASSWORD"],
		StripeWebhookSecret:  env["STRIPE_WEBHOOK_SECRET"],
		StripeSecretKey:      env["STRIPE_SECRET_KEY"],
		StripePricePro:       env["STRIPE_PRICE_PRO"],
		StripePricePremium:   env["STRIPE_PRICE_PREMIUM"],
		DevMode:              env["DEV_MODE"] == "true",
		TLSAutocertDomain:    env["TLS_AUTOCERT_DOMAIN"],
		TLSAutocertCacheDir:  env["TLS_AUTOCERT_CACHE_DIR"],
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
