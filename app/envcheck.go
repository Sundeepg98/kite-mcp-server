package app

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// envCheck runs targeted validation of environment variables at startup.
//
// It only validates vars where a wrong value causes subtle breakage
// (silent downgrade, runtime panic, OAuth callback mismatch, etc.). For
// most opt-in flags we rely on the feature itself to fail loudly when
// misconfigured — no need to duplicate that here.
//
// Logging contract:
//   - INFO: var is set, value looks valid (secrets are masked)
//   - WARN: var is unset but has a safe default we fall back to
//   - ERROR: var is required or malformed — returned as an error so the
//     caller can choose whether to abort startup
//
// Full inventory of every env var consumed by the server lives in
// docs/env-vars.md. This function is intentionally a subset.
func (app *App) envCheck() error {
	logger := app.logger
	var firstErr error
	recordErr := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}

	// --- OAUTH_JWT_SECRET ---
	//
	// Doubles as: JWT HMAC key, AES-GCM-via-HKDF root secret, audit-chain
	// HMAC, and fallback HMAC for external hash publishing. A short or
	// guessable value compromises every one of those at once. 32 bytes
	// gives HMAC-SHA256 its full security margin.
	//
	// In single-user/dev mode OAuth is off; a missing value is fine.
	if jwt := app.Config.OAuthJWTSecret; jwt != "" {
		switch {
		case len(jwt) < 32:
			recordErr(fmt.Errorf("OAUTH_JWT_SECRET is %d bytes; need at least 32 for HMAC-SHA256 security", len(jwt)))
			logger.Error("env var OAUTH_JWT_SECRET too short", "length", len(jwt), "min", 32)
		case strings.Contains(strings.ToLower(jwt), "your-secret") ||
			strings.Contains(strings.ToLower(jwt), "changeme") ||
			strings.Contains(strings.ToLower(jwt), "placeholder"):
			recordErr(fmt.Errorf("OAUTH_JWT_SECRET looks like a placeholder value — replace with a high-entropy secret"))
			logger.Error("env var OAUTH_JWT_SECRET looks like placeholder")
		default:
			logger.Info("env var OAUTH_JWT_SECRET set", "value", maskSecret(jwt))
		}
	} else if !app.DevMode {
		// Only a soft note — app.LoadConfig() is the authoritative gate.
		logger.Warn("env var OAUTH_JWT_SECRET not set; multi-user OAuth disabled")
	}

	// --- EXTERNAL_URL ---
	//
	// Baked into every OAuth redirect URL. A trailing slash produces
	// `https://example.com//auth/callback` (double slash) which some
	// clients reject. Wrong scheme (e.g. a bare `example.com`) makes the
	// browser open the raw string as a relative URL.
	if ext := app.Config.ExternalURL; ext != "" {
		u, err := url.Parse(ext)
		switch {
		case err != nil:
			recordErr(fmt.Errorf("EXTERNAL_URL is not a valid URL: %w", err))
			logger.Error("env var EXTERNAL_URL unparseable", "value", ext, "error", err)
		case u.Scheme != "http" && u.Scheme != "https":
			recordErr(fmt.Errorf("EXTERNAL_URL must use http:// or https:// scheme, got %q", u.Scheme))
			logger.Error("env var EXTERNAL_URL bad scheme", "value", ext, "scheme", u.Scheme)
		case u.Host == "":
			recordErr(fmt.Errorf("EXTERNAL_URL has no host: %q", ext))
			logger.Error("env var EXTERNAL_URL no host", "value", ext)
		case strings.HasSuffix(ext, "/"):
			// Trailing slash is a footgun — warn but don't fail.
			logger.Warn("env var EXTERNAL_URL has a trailing slash; OAuth callbacks will contain double slashes", "value", ext)
		default:
			logger.Info("env var EXTERNAL_URL set", "value", ext)
		}
	}

	// --- ALERT_DB_PATH ---
	//
	// If the parent directory doesn't exist, SQLite silently errors at
	// open time and audit/riskguard wiring fails downstream with a less
	// obvious error. Checking here produces a clearer message.
	if dbPath := app.Config.AlertDBPath; dbPath != "" {
		dir := filepath.Dir(dbPath)
		if dir == "." || dir == "" {
			logger.Info("env var ALERT_DB_PATH set", "value", dbPath, "dir", "(cwd)")
		} else if info, err := os.Stat(dir); err != nil {
			recordErr(fmt.Errorf("ALERT_DB_PATH parent directory %q does not exist: %w", dir, err))
			logger.Error("env var ALERT_DB_PATH parent missing", "path", dbPath, "dir", dir, "error", err)
		} else if !info.IsDir() {
			recordErr(fmt.Errorf("ALERT_DB_PATH parent %q is not a directory", dir))
			logger.Error("env var ALERT_DB_PATH parent not a dir", "path", dbPath, "dir", dir)
		} else {
			logger.Info("env var ALERT_DB_PATH set", "value", dbPath)
		}
	} else if !app.DevMode {
		logger.Warn("env var ALERT_DB_PATH not set; audit, riskguard, and user store will fail to initialize in production")
	}

	// --- LOG_LEVEL ---
	//
	// main.go silently falls back to INFO when unrecognized — which
	// hides debug-mode typos like `LOG_LEVEL=debugg` until an operator
	// notices the missing logs. Call it out here.
	if lvl := os.Getenv("LOG_LEVEL"); lvl != "" {
		switch strings.ToLower(lvl) {
		case "debug", "info", "warn", "error":
			logger.Info("env var LOG_LEVEL set", "value", lvl)
		default:
			logger.Warn("env var LOG_LEVEL unrecognized; falling back to info", "value", lvl, "valid", "debug|info|warn|error")
		}
	}

	// --- APP_MODE ---
	//
	// Unknown mode means the server starts but never registers any
	// transport — requests hang with no error. Validate up front.
	if mode := app.Config.AppMode; mode != "" {
		switch mode {
		case ModeHTTP, ModeSSE, ModeStdIO, ModeHybrid:
			logger.Info("env var APP_MODE set", "value", mode)
		default:
			recordErr(fmt.Errorf("APP_MODE %q unknown; valid: %s, %s, %s, %s", mode, ModeHTTP, ModeSSE, ModeStdIO, ModeHybrid))
			logger.Error("env var APP_MODE unknown", "value", mode)
		}
	}

	// --- ENABLE_TRADING ---
	//
	// Gates every order-placement tool (place_order, modify_order,
	// GTT, MF, trailing stops, native alerts). Default is FALSE so a
	// hosted multi-user deployment that forgets to configure this
	// cannot silently accept orders — and thus does not fall under the
	// NSE/INVG/69255 Annexure I Para 2.8 "Algo Provider" classification.
	// We accept only the strings "true" or "false" (case-insensitive);
	// anything else warns because the app will silently treat it as
	// false, which is usually not what the operator intended.
	if raw := os.Getenv("ENABLE_TRADING"); raw != "" {
		switch strings.ToLower(raw) {
		case "true":
			logger.Warn("env var ENABLE_TRADING=true — order-placement tools ENABLED (intended for local single-user only)")
		case "false":
			logger.Info("env var ENABLE_TRADING=false — order-placement tools gated (hosted safe mode)")
		default:
			logger.Warn("env var ENABLE_TRADING value unrecognized; treating as false",
				"value", raw, "valid", "true|false")
		}
	} else {
		logger.Info("env var ENABLE_TRADING not set — defaulting to false (order-placement gated)")
	}

	// --- AUDIT_HASH_PUBLISH_INTERVAL ---
	//
	// LoadHashPublishConfig silently ignores an unparseable value and
	// keeps the 1h default — operator thinks they set 5m, but nothing
	// changes. Validate syntax here so the mistake is visible.
	if raw := os.Getenv("AUDIT_HASH_PUBLISH_INTERVAL"); raw != "" {
		if d, err := time.ParseDuration(raw); err != nil {
			logger.Warn("env var AUDIT_HASH_PUBLISH_INTERVAL not a valid duration; keeping default 1h", "value", raw, "error", err)
		} else if d <= 0 {
			logger.Warn("env var AUDIT_HASH_PUBLISH_INTERVAL must be positive; keeping default 1h", "value", raw)
		} else {
			logger.Info("env var AUDIT_HASH_PUBLISH_INTERVAL set", "value", d.String())
		}
	}

	return firstErr
}

// maskSecret returns a fixed-width redacted form of a secret for logging.
// Keeps the first two and last two bytes so operators can sanity-check
// they're looking at the right secret without leaking the body.
func maskSecret(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}
